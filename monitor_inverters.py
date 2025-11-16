#!/usr/bin/env python3
"""
SolarEdge inverter monitor via Modbus TCP + optional Cloud API
--------------------------------------------------------------
- Reads config from monitor_inverters.conf (INI format)
- Detects low/zero production, SafeDC conditions, and abnormal statuses
- Uses Astral for daylight logic (cached)
- Sends Pushover notifications on alerts
- Optionally validates inverter/optimizer reporting via SolarEdge Cloud API
- Supports repeated-detection filtering (X detections over Y minutes)
- Supports --simulate mode to safely test alerts and suppression
- Supports --quiet for cron-friendly output
"""

import sys
from astral import LocationInfo
from astral.sun import sun
import argparse
from argparse import RawTextHelpFormatter
from pathlib import Path
import importlib.util

# Custom classes
from config import ConfigManager
from inverter_reader import InverterReader, ReaderSettings
from anomaly_detector import AnomalyDetector, DetectionSettings
from solaredge_api_checker import SolarEdgeAPIChecker
from daily_summary import DailySummaryManager, DailySummaryConfig
from notifiers import Notifier, Healthchecks
from alert_state import AlertStateManager, AlertStateConfig
from simulation import SimulationEngine
from output_formats import json_output

from utils import (
    extract_serial_from_text,
    status_human,
    DaylightPolicy,
)


# -------- Load developmental solaredge_modbus module instead of system version --------
mod_path = Path("/home/jeff/projects/personal/solaredge_modbus/src/solaredge_modbus/__init__.py")
spec = importlib.util.spec_from_file_location("solaredge_modbus", mod_path)
solaredge_modbus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(solaredge_modbus)
sys.modules["solaredge_modbus"] = solaredge_modbus


def key_for_alert_message(msg: str) -> str:
    """Stable key for dedupe / repeat-suppression: prefer serial, else prefix text."""
    ser = extract_serial_from_text(msg)
    if ser:
        return ser
    return (msg.split(":", 1)[0].strip().upper()) if ":" in msg else msg.strip().upper()

# ---------------- CLI ARGUMENTS ----------------
def build_arg_parser():
    examples = """\
Examples:
  Normal run (verbose):
    python3 monitor_inverters.py --verbose

  Output raw JSON for one run:
    python3 monitor_inverters.py --json

  Simulate issues:
    python3 monitor_inverters.py --simulate low --simulate-target SE7600H

  Cron-friendly (quiet, pings Healthchecks):
    */5 * * * * /usr/bin/python3 /opt/solaredge/monitor_inverters.py --quiet
"""
    exit_codes = """\
Exit Codes:
  0  All OK or alert suppressed (within repeat window)
  1  No inverter responded (communication failure)
  2  Confirmed alert triggered (notification sent)
"""
    ap = argparse.ArgumentParser(
        description=(
            "Monitor SolarEdge inverters via Modbus + optional Cloud API.\n"
            "Sends alerts only after repeated detections (X over Y)."
        ),
        formatter_class=RawTextHelpFormatter,
        epilog=f"{exit_codes}\n{examples}"
    )
    ap.add_argument("--json", action="store_true", help="print full inverter readings as JSON and exit")
    ap.add_argument("--verbose", action="store_true", help="emit detailed logs during checks")
    ap.add_argument("--quiet", action="store_true", help="suppress non-error output (cron-friendly)")
    ap.add_argument("--simulate", choices=["off", "low", "fault", "offline"], default="off",
                    help="simulate a failure mode on an inverter (default: off)")
    ap.add_argument("--simulate-target", metavar="NAME",
                    help="apply simulation to inverter by configured name (from [inverters] INVERTERS)")
    ap.add_argument("--test-pushover", action="store_true",
                    help="send a test notification to verify Pushover configuration")
    ap.add_argument("--force-summary", action="store_true",
                    help="force immediate daily summary (bypass sunset/time guard)")
    ap.add_argument("--debug", action="store_true", help="enable extra debug output (API and Modbus details)")
    ap.add_argument("--config", "-c", metavar="PATH", help="path to monitor_inverters.conf (overrides default)")
    ap.add_argument("--test-healthchecks-ok",
                action="store_true",
                help="send a test OK ping to verify Healthchecks.io")
    ap.add_argument("--test-healthchecks-fail",
                    action="store_true",
                    help="send a test FAIL ping to verify Healthchecks.io")

    return ap


# ---------------- MAIN ----------------
def main():
    global cfg

    ap = build_arg_parser()
    args = ap.parse_args()

    # Load config
    cfg = ConfigManager(args.config or "monitor_inverters.conf")

    # Simulation engine
    sim = SimulationEngine(args.simulate, args.simulate_target)

    # Site / Astral
    ASTRAL_LOC = LocationInfo(
        cfg.site.city_name,
        "USA",
        cfg.site.tzname,
        cfg.site.lat,
        cfg.site.lon,
    )

    # ---- Stage 3: new AlertStateManager ----
    state_cfg = AlertStateConfig(
        path=cfg.alerts.state_file,
        repeat_count=cfg.alerts.repeat_count,
        repeat_window_min=cfg.alerts.repeat_window_min,
    )

    alert_mgr = AlertStateManager(state_cfg, debug=args.debug)

    # Detection engine
    detector = AnomalyDetector(
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

    # Alerts
    notifier = Notifier(
        user_key=cfg.pushover.user_key,
        api_token=cfg.pushover.api_token,
    )
    health = Healthchecks(cfg.alerts.healthchecks_url)

    # Daily Summary
    daily_cfg = DailySummaryConfig(
        enabled=cfg.alerts.daily_enabled,
        method=cfg.alerts.daily_method,
        offset_min=cfg.alerts.daily_offset_min,
        api_key=cfg.api.api_key,
        site_id=cfg.api.site_id,
    )

    daily_mgr = DailySummaryManager(
        cfg=daily_cfg,
        astral_loc=ASTRAL_LOC,
        status_func=status_human,
        state=alert_mgr,
        debug=args.debug,
    )

    api_checker = SolarEdgeAPIChecker(
        api_key=cfg.api.api_key,
        site_id=cfg.api.site_id,
        optimizer_expected_per_inv=cfg.optimizer_expected_by_serial,
        debug=args.debug,
    )

    reader = InverterReader(
        ReaderSettings(
            timeout=cfg.thresholds.modbus_timeout,
            retries=cfg.thresholds.modbus_retries,
        )
    )

    def log(msg, err=False):
        if err:
            print(msg, file=sys.stderr)
        elif not args.quiet:
            print(msg)

    # Verbose modbus module info
    if args.verbose and not args.quiet:
        print(f"solaredge_modbus version: {getattr(solaredge_modbus, '__version__', '(unknown)')}")
        print(f"Loaded from: {getattr(solaredge_modbus, '__file__', '(unknown path)')}")

    # Pushover test mode
    if args.test_pushover:
        notifier.send_test(log)
        return 0

    # Healthchecks test modes
    if args.test_healthchecks_ok:
        health.send_test_ok(log)
        return 0

    if args.test_healthchecks_fail:
        health.send_test_fail(log)
        return 0

    # Daylight policy (Astral daylight logic + simulation overrides)
    daylight = DaylightPolicy(
        astral_loc=ASTRAL_LOC,
        thresholds=cfg.thresholds,
        tzname=cfg.site.tzname,
        log=log,
        simulation_engine=sim,
    )

    dt_local = daylight.now_local()

    results, any_success = reader.read_all(
        cfg.inverters,
        verbose=args.verbose,
        quiet=args.quiet,
    )

    dayinfo = daylight.evaluate(
        dt_local,
        results=results,
        verbose=args.verbose,
        quiet=args.quiet,
    )

    is_day = dayinfo["is_day"]
    skip_modbus = dayinfo["skip_modbus"]

    if args.verbose and not args.quiet:
        log(
            f"[time] now={dayinfo['dt_local'].strftime('%Y-%m-%d %H:%M:%S %Z')} "
            f"day={dayinfo['is_day']} "
            f"sunrise+grace={dayinfo['sunrise'].strftime('%H:%M')} "
            f"sunset-grace={dayinfo['sunset'].strftime('%H:%M')}"
        )

    # Apply simulation layer
    simulation_info = sim.apply_to_results(results, log, verbose=args.verbose)

    # JSON output mode
    if args.json:
        print(json_output(results, dt_local, simulation_info))
        return 0

    if not any_success:
        confirmed, suppressed = alert_mgr.process_alerts(
            ["All inverters: Modbus communication failed"],
            key_for_alert_message,
        )

        if confirmed:
            notifier.send(confirmed)
        return 1

    read_ok = [r for r in results if not r.get("error")]
    alerts = []
    if not skip_modbus:
        alerts = detector.detect(read_ok, is_day=is_day)

    alerts.extend(api_checker.generate_alerts(read_ok))

    recoveries = alert_mgr.update_inverter_states(read_ok, notifier)
    for msg in recoveries:
        log(f"ℹ️ {msg}")

    alerts.extend(reader.alerts_from_errors(results))

    exit_code = 0

    if alerts:
        confirmed, suppressed = alert_mgr.process_alerts(alerts, key_for_alert_message)

        if confirmed:
            msg = "\n".join(confirmed)
            log(f"ALERT:\n{msg}")
            notifier.send("SolarEdge Monitor Alert", msg, priority=1)
            health.fail(confirmed[0])
            exit_code = 2
        else:
            # Detections were recorded but thresholds not reached
            exit_code = 0
    else:
        log("OK: all inverters normal.")
        health.ok("All normal")


    try:
        if args.force_summary:
            log("📊 Forcing daily summary now (--force-summary).")
        summary = daily_mgr.maybe_generate_summary(read_ok, force=args.force_summary)
        if summary:
            log(summary)
            date_str = daylight.now_local().strftime("%Y-%m-%d")
            notifier.send(f"SolarEdge Daily Summary — {date_str}", summary, priority=0)
    except Exception as e:
        log(f"⚠️ Failed to compute/send daily summary: {e}", err=True)

    return exit_code


# ---------------- ENTRY POINT ----------------
if __name__ == "__main__":
    sys.exit(main())
