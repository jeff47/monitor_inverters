# orchestrator.py
"""
Orchestrator for the SolarEdge inverter monitoring stack.

This class coordinates:
- Modbus reading
- Daylight evaluation
- Simulation layer
- Cloud API checking
- Anomaly detection
- Alert state management
- Recovery notifications
- Daily summary generation
- Healthchecks pings

The goal is to reduce the complexity of monitor_inverters.py
and give a single, testable execution entrypoint.
"""

import sys
from astral import LocationInfo

from inverter_reader import InverterReader, ReaderSettings
from anomaly_detector import AnomalyDetector, DetectionSettings
from solaredge_api_checker import SolarEdgeAPIChecker
from daily_summary import DailySummaryManager, DailySummaryConfig
from notifiers import Notifier, Healthchecks
from alert_state import AlertStateManager, AlertStateConfig
from simulation import SimulationEngine
from utils import (
    extract_serial_from_text,
    status_human,
    DaylightPolicy,
    key_for_alert_message
)

from output_formats import json_output


def key_for_alert_message(msg: str) -> str:
    """Stable key for dedupe/repeat suppression."""
    ser = extract_serial_from_text(msg)
    if ser:
        return ser
    return (msg.split(":", 1)[0].strip().upper()) if ":" in msg else msg.strip().upper()


class Orchestrator:
    def __init__(self, args, cfg, solaredge_modbus):
        """
        args - CLI args from argparse
        cfg  - ConfigManager instance
        solaredge_modbus - dynamically loaded module (for debug logging)
        """
        self.args = args
        self.cfg = cfg
        self.solaredge_modbus = solaredge_modbus

        # ---------- Simulation ----------
        self.sim = SimulationEngine(
            args.simulate,
            args.simulate_target,
        )

        # ---------- Astral ----------
        self.astral_loc = LocationInfo(
            cfg.site.city_name,
            "USA",
            cfg.site.tzname,
            cfg.site.lat,
            cfg.site.lon,
        )

        # ---------- Alert State Manager ----------
        self.alert_mgr = AlertStateManager(
            AlertStateConfig(
                path=cfg.alerts.state_file,
                repeat_count=cfg.alerts.repeat_count,
                repeat_window_min=cfg.alerts.repeat_window_min,
            ),
            debug=args.debug,
        )

        # ---------- Detector ----------
        self.detector = AnomalyDetector(
            DetectionSettings(
                abs_min_watts=cfg.thresholds.abs_min_watts,
                safe_dc_volt_max=cfg.thresholds.safe_dc_volt_max,
                zero_current_eps=cfg.thresholds.zero_current_eps,
                peer_compare=cfg.thresholds.peer_compare,
                peer_min_watts=cfg.thresholds.peer_min_watts,
                peer_low_ratio=cfg.thresholds.peer_low_ratio,
            ),
            status_formatter=status_human,
        )

        # ---------- Modbus Reader ----------
        self.reader = InverterReader(
            ReaderSettings(
                timeout=cfg.thresholds.modbus_timeout,
                retries=cfg.thresholds.modbus_retries,
            )
        )

        # ---------- Notifiers ----------
        self.notifier = Notifier(
            user_key=cfg.pushover.user_key,
            api_token=cfg.pushover.api_token,
        )
        self.health = Healthchecks(cfg.alerts.healthchecks_url)

        # ---------- Daily Summary ----------
        self.daily_mgr = DailySummaryManager(
            cfg=DailySummaryConfig(
                enabled=cfg.alerts.daily_enabled,
                method=cfg.alerts.daily_method,
                offset_min=cfg.alerts.daily_offset_min,
                api_key=cfg.api.api_key,
                site_id=cfg.api.site_id,
            ),
            astral_loc=self.astral_loc,
            status_func=status_human,
            state=self.alert_mgr,
            debug=args.debug,
        )

        # ---------- Cloud API ----------
        self.api_checker = SolarEdgeAPIChecker(
            api_key=cfg.api.api_key,
            site_id=cfg.api.site_id,
            optimizer_expected_per_inv=cfg.optimizer_expected_by_serial,
            debug=args.debug,
        )

        # ---------- Daylight Policy ----------
        self.daylight = DaylightPolicy(
            astral_loc=self.astral_loc,
            thresholds=cfg.thresholds,
            tzname=cfg.site.tzname,
            log=self._log,
            simulation_engine=self.sim,
        )

    # ---------------------------------------------------------
    # Logging wrapper
    # ---------------------------------------------------------
    def _log(self, msg, err=False):
        if err:
            print(msg, file=sys.stderr)
        elif not self.args.quiet:
            print(msg)

    # ---------------------------------------------------------
    # Run one full monitor cycle
    # ---------------------------------------------------------
    def run_once(self):
        # Verbose modbus module info
        if self.args.verbose and not self.args.quiet:
            print(f"solaredge_modbus version: {getattr(self.solaredge_modbus, '__version__', '(unknown)')}")
            print(f"Loaded from: {getattr(self.solaredge_modbus, '__file__', '(unknown path)')}")

        dt_local = self.daylight.now_local()

        # ---------- Modbus ----------
        results, any_success = self.reader.read_all(
            self.cfg.inverters,
            verbose=self.args.verbose,
            quiet=self.args.quiet,
            debug=self.args.debug,
        )

        # ---------- Daylight evaluation ----------
        dayinfo = self.daylight.evaluate(
            dt_local,
            results=results,
            verbose=self.args.verbose,
            quiet=self.args.quiet,
        )

        is_day = dayinfo["is_day"]
        skip_modbus = dayinfo["skip_modbus"]

        if self.args.verbose and not self.args.quiet:
            self._log(
                f"[time] now={dayinfo['dt_local'].strftime('%Y-%m-%d %H:%M:%S %Z')} "
                f"day={dayinfo['is_day']} "
                f"sunrise+grace={dayinfo['sunrise'].strftime('%H:%M')} "
                f"sunset-grace={dayinfo['sunset'].strftime('%H:%M')}"
            )

        # ---------- Simulation ----------
        simulation_info = self.sim.apply_to_results(
            results, self._log, verbose=self.args.verbose
        )

        # JSON mode bypasses everything else
        if self.args.json:
            print(json_output(results, dt_local, simulation_info))
            return 0

        # ---------- Communication failure ----------
        if not any_success:
            confirmed, suppressed = self.alert_mgr.process_alerts(
                ["All inverters: Modbus communication failed"],
                key_for_alert_message,
            )
            if confirmed:
                self.notifier.send("SolarEdge Monitor Alert", confirmed[0], priority=1)
            return 1

        # ---------- Detection ----------
        read_ok = [r for r in results if not r.get("error")]
        alerts = []

        if not skip_modbus:
            alerts.extend(
                self.detector.detect(
                    read_ok,
                    is_day=is_day,
                    near_edges=dayinfo.get("near_edges", False),
                )
            )


        # API alerts
        alerts.extend(self.api_checker.generate_alerts(read_ok))

        # Recovery detection
        recoveries = self.alert_mgr.update_inverter_states(read_ok, self.notifier)
        for msg in recoveries:
            self._log(f"ℹ️ {msg}")

        # Reader errors
        alerts.extend(self.reader.alerts_from_errors(results))

        # ---------- Alert handling ----------
        if alerts:
            confirmed, suppressed = self.alert_mgr.process_alerts(alerts, key_for_alert_message)
            if confirmed:
                msg = "\n".join(confirmed)
                self._log(f"ALERT:\n{msg}")
                self.notifier.send("SolarEdge Monitor Alert", msg, priority=1)
                self.health.fail(confirmed[0])
                return 2
            # threshold not yet reached
            return 0

        else:
            self._log("OK: all inverters normal.")
            self.health.ok("All normal")

        # ---------- Daily Summary ----------
        try:
            summary = self.daily_mgr.maybe_generate_summary(read_ok, force=self.args.force_summary)
            if summary:
                date_str = dt_local.strftime("%Y-%m-%d")
                self.notifier.send(f"SolarEdge Daily Summary — {date_str}", summary)
                self._log(summary)
        except Exception as e:
            self._log(f"⚠️ Failed to compute/send daily summary: {e}", err=True)

        return 0

    # ---------------------------------------------------------
    # Public entry point
    # ---------------------------------------------------------
    def run(self):
        return self.run_once()
