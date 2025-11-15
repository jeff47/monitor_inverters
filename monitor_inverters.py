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

import os
import sys
import json
#import socket
import time
import urllib.request
import urllib.parse
import urllib.error
import pytz
# import configparser
# import solaredge_modbus
from astral import LocationInfo
from astral.sun import sun
import requests
#import datetime as dt
from datetime import datetime, timedelta
import argparse
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse, urlunparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
#import re
from pathlib import Path
import importlib.util

# Custom classes
from config import ConfigManager
from inverter_reader import InverterReader, ReaderSettings
from anomaly_detector import AnomalyDetector, DetectionSettings
from solaredge_api_checker import SolarEdgeAPIChecker
from daily_summary import DailySummaryManager, DailySummaryConfig
from notifiers import Notifier, Healthchecks

from utils import (
    clean_serial,
    inv_display_from_parts,
    extract_serial_from_text,
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

def status_text(code: int) -> str:
    """Return descriptive status name."""
    explicit = {
        1: "Off",
        2: "Sleeping",
        3: "Starting",
        4: "Producing",
        5: "Throttled",
        6: "Shutting down",
        7: "Fault",
        8: "Standby",
    }
    return explicit.get(code, f"Unknown({code})")

# ---------------- ALERT REPETITION CONTROL ----------------

_ALERT_STATE_CACHE = None

def load_alert_state():
    global _ALERT_STATE_CACHE
    if _ALERT_STATE_CACHE is not None:
        return _ALERT_STATE_CACHE
    try:
        with open(ALERT_STATE_FILE, "r") as f:
            _ALERT_STATE_CACHE = json.load(f)
    except Exception:
        _ALERT_STATE_CACHE = {}
    return _ALERT_STATE_CACHE

def save_alert_state(state):
    try:
        with open(ALERT_STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"⚠️ Failed to save alert state: {e}", file=sys.stderr)

def should_alert(key_text):
    """Return True if alert for 'key_text' should be triggered now (after X/Y rule)."""
    serial = clean_serial(key_text)
    key = serial if serial else key_text.strip().upper()
    state = load_alert_state()
    now = time.time()

    record = state.get(key) or {}
    first_ts = record.get("first", now)
    count = record.get("count", 0)

    # reset window if expired or malformed
    if not isinstance(first_ts, (int, float)) or now - first_ts > ALERT_REPEAT_WINDOW_MIN * 60:
        first_ts = now
        count = 0

    count += 1
    record.update({"first": first_ts, "count": count})
    state[key] = record
    save_alert_state(state)

    return count >= ALERT_REPEAT_COUNT


# ---------------- RECOVERY TRACKING ----------------
def update_inverter_states(results, notifier):
    """Track inverter mode transitions and issue recovery notifications."""
    state = load_alert_state()
    recoveries = []
    for r in results:
        key_display = inv_display_from_parts(r.get("model"), r.get("serial"))
        key_state = clean_serial(r.get("serial")) or key_display.upper()
        st_txt = status_text(r.get("status", 0))
        last_mode = state.get(key_state, {}).get("last_mode")
        if last_mode in ("Fault", "Off") and st_txt == "Producing":
            msg = f"{key_display}: recovered from {last_mode} → Producing"
            recoveries.append(msg)
            notifier.send("SolarEdge Recovery", msg, priority=0)
        state.setdefault(key_state, {})["last_mode"] = st_txt
    save_alert_state(state)
    return recoveries


# ---------------- SIMULATION CONSTANTS ----------------
SIMULATED_NORMAL = {"status": 4, "pac_W": 5000.0, "vdc_V": 380.0, "idc_A": 13.0}

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
        status_formatter=status_text,
    )

    # Alerts
    global ALERT_STATE_FILE, ALERT_REPEAT_COUNT, ALERT_REPEAT_WINDOW_MIN
    ALERT_REPEAT_COUNT = cfg.alerts.repeat_count
    ALERT_REPEAT_WINDOW_MIN = cfg.alerts.repeat_window_min
    ALERT_STATE_FILE = cfg.alerts.state_file
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

    # Cloud API
    # ENABLE_SOLAREDGE_API = cfg.api.enabled
    # SOLAREDGE_API_KEY = cfg.api.api_key
    # SOLAREDGE_SITE_ID = cfg.api.site_id

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
        status_func=status_text,
        state_file=ALERT_STATE_FILE,
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

    if args.verbose and not args.quiet:
        log(f"[time] now={dt_local.strftime('%Y-%m-%d %H:%M:%S %Z')} day={is_day} "
            f"sunrise+grace={sunrise.strftime('%H:%M')} sunset-grace={sunset.strftime('%H:%M')}")

    results, any_success = reader.read_all(INVERTERS, verbose=args.verbose, quiet=args.quiet)

    # --- Simulation injection ---
    simulation_info = None
    if args.simulate != "off" and results:
        target = None
        if args.simulate_target:
            for r in results:
                if r.get("name") == args.simulate_target:
                    target = r
                    break
            if target is None:
                log(f"⚠️ No inverter found with name '{args.simulate_target}', using first available inverter instead.")
                # prefer a non-error candidate if possible
                target = next((x for x in results if not x.get("error") and x.get("name")), results[0])
        else:
            # Default: lowest kW model
            def extract_kw(inv):
                import re
                model = inv.get("model") or inv.get("name", "")
                m = re.search(r"(\d{4,5})", model)
                return int(m.group(1)) if m else 99999
            candidates = [r for r in results if not r.get("error")]
            if not candidates:
                candidates = results
            target = min(candidates, key=extract_kw)

        log(f"🔧 Simulating inverter '{target['name']}' in mode '{args.simulate}'")
        simulation_info = f"{args.simulate} on {target['name']}"

        for r in results:
            if r is target:
                continue
            if not r.get("error"):
                r.update(SIMULATED_NORMAL)
                if args.verbose:
                    log(f"(Simulation) {r['id']} simulating normal output")

        if args.simulate == "low":
            target.update({"pac_W": 0.0, "status": 4})
            log(f"(Simulation) {target['id']} simulating 0W output")
        elif args.simulate == "fault":
            target["status"] = 7
            log(f"(Simulation) {target['id']} simulating FAULT state")
        elif args.simulate == "offline":
            target["error"] = True
            log(f"(Simulation) {target['id']} simulating unreachable state")

    # --- JSON output ---
    if args.json:
        out = {"results": results, "timestamp": dt_local.isoformat()}
        if simulation_info:
            out["simulation"] = simulation_info
        print(json.dumps(out, indent=2, default=str))
        return 0

    if not any_success:
        # All modbus communication failed → generate a real alert
        alerts = ["All inverters: Modbus communication failed"]

        confirmed = []
        for msg in alerts:
            k = key_for_alert_message(msg)
            if should_alert(k):
                confirmed.append(msg)

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
    recoveries = update_inverter_states(read_ok, notifier)
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
            if should_alert(k):
                confirmed.append(msg)
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
