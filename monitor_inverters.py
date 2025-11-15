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
import json
import pytz
from astral import LocationInfo
from astral.sun import sun
from datetime import datetime, timedelta
import argparse
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse, urlunparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    clean_serial,
    inv_display_from_parts,
    extract_serial_from_text,
    status_human
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
    # fallback to prefix before ':' normalized
    return (msg.split(":", 1)[0].strip().upper()) if ":" in msg else msg.strip().upper()

# ---------------- UTILITIES ----------------
def now_local(tzname: str):
    """Pure: return current datetime in the given timezone."""
    return datetime.now(pytz.timezone(tzname))

def solar_window(dt_local, astral_loc, morning_grace, evening_grace):
    """Pure: compute day/sunrise/sunset using explicit parameters."""
    s = sun(astral_loc.observer, date=dt_local.date(), tzinfo=dt_local.tzinfo)
    sunrise = s["sunrise"] + morning_grace
    sunset = s["sunset"] - evening_grace
    return (sunrise <= dt_local <= sunset, sunrise, sunset)

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
    ap.add_argument("--json", action="store_true",
                    help="print full inverter readings as JSON and exit")
    ap.add_argument("--verbose", action="store_true",
                    help="emit detailed logs during checks")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress non-error output (cron-friendly)")
    ap.add_argument("--simulate", choices=["off", "low", "fault", "offline"], default="off",
                    help="simulate a failure mode on an inverter (default: off)")
    ap.add_argument("--simulate-target", metavar="NAME",
                    help="apply simulation to inverter by configured name (from [inverters] INVERTERS)")
    ap.add_argument("--test-pushover", action="store_true",
                    help="send a test notification to verify Pushover configuration")
    ap.add_argument("--force-summary", action="store_true",
                    help="force immediate daily summary (bypass sunset/time guard)")
    ap.add_argument("--debug", action="store_true",
                    help="enable extra debug output (API and Modbus details)")
    ap.add_argument("--config", "-c", metavar="PATH",
                    help="path to monitor_inverters.conf (overrides default)")
    return ap


# ---------------- MAIN ----------------
def main():
    global cfg

    ap = build_arg_parser()
    args = ap.parse_args()

    # Load config using our new class
    cfg = ConfigManager(args.config or "monitor_inverters.conf")

    # Simulation engine now needs both mode and optional target name
    sim = SimulationEngine(args.simulate, args.simulate_target)

    # Site / Astral
    CITY_NAME = cfg.site.city_name
    LAT = cfg.site.lat
    LON = cfg.site.lon
    TZNAME = cfg.site.tzname
    ASTRAL_LOC = LocationInfo(CITY_NAME, "USA", TZNAME, LAT, LON)

    # Inverters
    INVERTERS = cfg.inverters

    # Thresholds
    MORNING_GRACE = cfg.thresholds.morning_grace
    EVENING_GRACE = cfg.thresholds.evening_grace
    ABS_MIN_WATTS = cfg.thresholds.abs_min_watts
    SAFE_DC_VOLT_MAX = cfg.thresholds.safe_dc_volt_max
    ZERO_CURRENT_EPS = cfg.thresholds.zero_current_eps
    PEER_COMPARE = cfg.thresholds.peer_compare
    PEER_MIN_WATTS = cfg.thresholds.peer_min_watts
    PEER_LOW_RATIO = cfg.thresholds.peer_low_ratio
    MODBUS_TIMEOUT = cfg.thresholds.modbus_timeout
    MODBUS_RETRIES = cfg.thresholds.modbus_retries

    # ---- Stage 3: new AlertStateManager ----
    state_cfg = AlertStateConfig(
        path=cfg.alerts.state_file,
        repeat_count=cfg.alerts.repeat_count,
        repeat_window_min=cfg.alerts.repeat_window_min,
    )

    alert_mgr = AlertStateManager(state_cfg, debug=args.debug)

    # Detection engine (Stage 3)
    detector = AnomalyDetector(
        DetectionSettings(
            abs_min_watts=ABS_MIN_WATTS,
            safe_dc_volt_max=SAFE_DC_VOLT_MAX,
            zero_current_eps=ZERO_CURRENT_EPS,
            peer_compare=PEER_COMPARE,
            peer_min_watts=PEER_MIN_WATTS,
            peer_low_ratio=PEER_LOW_RATIO,
        ),
        status_formatter=status_human,
    )

    # Alerts
    HEALTHCHECKS_URL = cfg.alerts.healthchecks_url

    # Pushover
    PUSHOVER_USER_KEY = cfg.pushover.user_key
    PUSHOVER_API_TOKEN = cfg.pushover.api_token

    # Stage 4.5: unified notifier + healthcheck interface
    notifier = Notifier(
        user_key=PUSHOVER_USER_KEY,
        api_token=PUSHOVER_API_TOKEN,
    )

    health = Healthchecks(HEALTHCHECKS_URL)

    # Daily Summary
    DAILY_SUMMARY_ENABLED = cfg.alerts.daily_enabled
    DAILY_SUMMARY_METHOD = cfg.alerts.daily_method
    DAILY_SUMMARY_OFFSET_MIN = cfg.alerts.daily_offset_min

    # Daily Summary Manager (Stage 4.4)
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

    # Instantiate SolarEdge API checker (Stage 4.1)
    # cfg.optimizers is: dict[str, OptimizerExpectation]
    optimizer_expectations = cfg.optimizers

    expected_by_serial = {
        clean_serial(serial): o.count
        for serial, o in optimizer_expectations.items()
    }

    api_checker = SolarEdgeAPIChecker(
        api_key=cfg.api.api_key,
        site_id=cfg.api.site_id,
        optimizer_expected_per_inv=expected_by_serial,
        debug=args.debug,
    )

    reader = InverterReader(
        ReaderSettings(
            timeout=MODBUS_TIMEOUT,
            retries=MODBUS_RETRIES,
        )
    )

    # --- Verbose module info ---
    if args.verbose and not args.quiet:
        print(f"solaredge_modbus version: {getattr(solaredge_modbus, '__version__', '(unknown)')}")
        print(f"Loaded from: {getattr(solaredge_modbus, '__file__', '(unknown path)')}")

    def log(msg, err=False):
        if err:
            print(msg, file=sys.stderr)
        elif not args.quiet:
            print(msg)

    # --- Pushover test mode ---
    if args.test_pushover:
        log("🔔 Sending test notification via Pushover...")
        msg = f"Test message from SolarEdge inverter monitor\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        notifier.send("SolarEdge Monitor Test", msg, priority=0)
        log("✅ Test notification sent (check your device).")
        return 0

    dt_local = now_local(TZNAME)
    is_day, sunrise, sunset = solar_window(
        dt_local,
        ASTRAL_LOC,
        MORNING_GRACE,
        EVENING_GRACE,
    )

    # Simulation: always treat as day if active
    is_day = sim.override_daylight(is_day)


    if args.verbose and not args.quiet:
        log(f"[time] now={dt_local.strftime('%Y-%m-%d %H:%M:%S %Z')} day={is_day} "
            f"sunrise+grace={sunrise.strftime('%H:%M')} sunset-grace={sunset.strftime('%H:%M')}")

    results, any_success = reader.read_all(INVERTERS, verbose=args.verbose, quiet=args.quiet)

    # --- Simulation overrides applied to inverter results ---
    simulation_info = sim.apply_to_results(results, log, verbose=args.verbose)

    # --- JSON output ---
    if args.json:
        print(json_output(results, dt_local, simulation_info))
        return 0

    if not any_success:
        # All modbus communication failed → generate a real alert
        alerts = ["All inverters: Modbus communication failed"]

        confirmed = []
        for msg in alerts:
            k = key_for_alert_message(msg)
            if alert_mgr.should_alert(k):
                confirmed.append(msg)
                alert_mgr.record_alert(k)

        if confirmed:
            msg = "\n".join(confirmed)
            log(f"ALERT:\n{msg}")
            notifier.send("SolarEdge Monitor Alert", msg, priority=1)
            health.fail(confirmed[0])
            return 2

        # Suppressed; still count as error but not an alert
        log("Modbus communication failed (suppressed during repeat window)")
        health.fail("Modbus comm failure")
        return 1

    all_sleeping = all(r.get("status") == 2 for r in results if not r.get("error"))

    # Skip Modbus production checks at night only
    if all_sleeping or not is_day:
        if args.verbose and not args.quiet:
            reason = "all Sleeping" if all_sleeping else "Astral night"
            log(f"Night window ({reason}): skipping Modbus anomaly checks.")
        # But still allow cloud API checks below

    read_ok = [r for r in results if not r.get("error")]
    alerts = detector.detect(read_ok, is_day=is_day)

    # Cloud API alerts (Stage 4.3: moved to centralized checker)
    cloud_alerts = api_checker.check(read_ok)
    alerts.extend(cloud_alerts)

    # Track and notify recoveries ---
    recoveries = alert_mgr.update_inverter_states(read_ok, notifier)
    for msg in recoveries:
        log(f"ℹ️ {msg}")

    for r in results:
        if r.get("error"):
            # Use canonical display even for errors
            display = inv_display_from_parts(r.get("model"), r.get("serial"))
            alerts.append(f"{display}: Modbus read failed")

    # --- Merge duplicate alerts (same inverter, by serial) ---
    unique_alerts = {}
    for msg in alerts:
        k = key_for_alert_message(msg)  # serial if present; else normalized prefix
        if k not in unique_alerts or len(msg) > len(unique_alerts[k]):
            unique_alerts[k] = msg
    alerts = list(unique_alerts.values())

    # --- Apply repeat-suppression AFTER merge ---
    exit_code = 0
    if alerts:
        confirmed = []
        for msg in alerts:
            k = key_for_alert_message(msg)
            if alert_mgr.should_alert(k):
                confirmed.append(msg)
                alert_mgr.record_alert(k)

        if confirmed:
            msg = "\n".join(confirmed)
            log(f"ALERT:\n{msg}")
            notifier.send("SolarEdge Monitor Alert", msg, priority=1)
            health.fail(confirmed[0])
            exit_code = 2
        else:
            exit_code = 0
    else:
        log("OK: all inverters normal.")
        health.ok("All normal")

    # Always try sending summary, even if alert occurred
    try:
        if args.force_summary:
            log("📊 Forcing daily summary now (--force-summary).")
        summary = daily_mgr.maybe_generate_summary(read_ok, force=args.force_summary)
        if summary:
            log(summary)
            date_str = now_local(TZNAME).strftime("%Y-%m-%d")
            notifier.send(f"SolarEdge Daily Summary — {date_str}", summary, priority=0)
    except Exception as e:
        log(f"⚠️ Failed to compute/send daily summary: {e}", err=True)

    return exit_code

# ---------------- ENTRY POINT ----------------
#   0 = OK or suppressed alert
#   1 = No inverter responded
#   2 = Confirmed alert triggered
if __name__ == "__main__":
    sys.exit(main())
