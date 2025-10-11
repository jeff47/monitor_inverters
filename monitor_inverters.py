#!/usr/bin/env python3
"""
SolarEdge inverter monitor via Modbus TCP + optional Cloud API
--------------------------------------------------------------
- Reads config from monitor_inverters.conf (INI format)
- Detects low/zero production, SafeDC conditions, and abnormal statuses
- Uses Astral for daylight logic
- Sends Pushover notifications on alerts
- Optionally validates inverter/optimizer reporting via SolarEdge cloud API
- Supports repeated-detection filtering (X detections over Y minutes)
- Supports --simulate mode to safely test alerts and suppression
"""

import os
import sys
import json
import socket
import time
from datetime import datetime, timedelta
import urllib.request
import urllib.parse
import pytz
import configparser
import solaredge_modbus
from astral import LocationInfo
from astral.sun import sun
import requests
import datetime as dt
import argparse
from argparse import RawTextHelpFormatter


# ---------------- CONFIG LOADING ----------------

def load_config(path="monitor_inverters.conf"):
    """Read configuration from INI file using configparser."""
    parser = configparser.ConfigParser()
    parser.optionxform = str  # preserve case
    if not os.path.exists(path):
        print(f"⚠️ Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    parser.read(path)
    return parser


cfg = load_config()


# ---------------- CONFIG VALUES ----------------

CITY_NAME = cfg.get("site", "CITY_NAME")
LAT = cfg.getfloat("site", "LAT")
LON = cfg.getfloat("site", "LON")
TZNAME = cfg.get("site", "TZNAME")

# Inverters
INVERTERS = []
for part in cfg.get("inverters", "INVERTERS").split(","):
    part = part.strip()
    if not part:
        continue
    name, host, port, unit = [x.strip() for x in part.split(":")]
    INVERTERS.append({
        "name": name,
        "host": host,
        "port": int(port),
        "unit": int(unit),
    })

# Thresholds
MORNING_GRACE = timedelta(minutes=cfg.getfloat("thresholds", "MORNING_GRACE_MIN", fallback=20))
EVENING_GRACE = timedelta(minutes=cfg.getfloat("thresholds", "EVENING_GRACE_MIN", fallback=10))
ABS_MIN_WATTS = cfg.getfloat("thresholds", "ABS_MIN_WATTS", fallback=150)
SAFE_DC_VOLT_MAX = cfg.getfloat("thresholds", "SAFE_DC_VOLT_MAX", fallback=150)
ZERO_CURRENT_EPS = cfg.getfloat("thresholds", "ZERO_CURRENT_EPS", fallback=0.05)
PEER_COMPARE = cfg.getboolean("thresholds", "PEER_COMPARE", fallback=True)
PEER_MIN_WATTS = cfg.getfloat("thresholds", "PEER_MIN_WATTS", fallback=600)
PEER_LOW_RATIO = cfg.getfloat("thresholds", "PEER_LOW_RATIO", fallback=0.20)

# Alert repetition
ALERT_REPEAT_COUNT = cfg.getint("alerts", "ALERT_REPEAT_COUNT", fallback=3)
ALERT_REPEAT_WINDOW_MIN = cfg.getint("alerts", "ALERT_REPEAT_WINDOW_MIN", fallback=30)
ALERT_STATE_FILE = cfg.get("alerts", "ALERT_STATE_FILE", fallback="/tmp/inverter_alert_state.json")

# Pushover
PUSHOVER_USER_KEY = cfg.get("pushover", "PUSHOVER_USER_KEY", fallback=None)
PUSHOVER_API_TOKEN = cfg.get("pushover", "PUSHOVER_API_TOKEN", fallback=None)

# SolarEdge Cloud API
ENABLE_SOLAREDGE_API = cfg.getboolean("solaredge_api", "ENABLE_SOLAREDGE_API", fallback=False)
SOLAREDGE_API_KEY = cfg.get("solaredge_api", "SOLAREDGE_API_KEY", fallback=None)
SOLAREDGE_SITE_ID = cfg.get("solaredge_api", "SOLAREDGE_SITE_ID", fallback=None)


# ---------------- UTILITIES ----------------

def pushover_notify(title: str, message: str, priority: int = 0):
    """
    Send a Pushover notification if credentials are configured.

    - If BOTH PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN are blank or missing → skip silently.
    - If ONE is missing but not the other → print error and exit(1).
    - Otherwise, send the notification.
    """
    user_key = (PUSHOVER_USER_KEY or "").strip()
    api_token = (PUSHOVER_API_TOKEN or "").strip()

    # Case 1: both missing/blank → feature disabled
    if not user_key and not api_token:
        if os.environ.get("DEBUG"):
            print("ℹ️  Pushover disabled (no credentials configured).", file=sys.stderr)
        return

    # Case 2: one missing but not both → configuration error
    if bool(user_key) != bool(api_token):
        print("❌ Configuration error: Both PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN must be set for Pushover.", file=sys.stderr)
        sys.exit(1)

    # Case 3: both provided → proceed normally
    data = urllib.parse.urlencode({
        "token": api_token,
        "user": user_key,
        "title": title,
        "message": message,
        "priority": str(priority),
    }).encode("utf-8")

    try:
        req = urllib.request.Request("https://api.pushover.net/1/messages.json", data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"⚠️ Failed to send Pushover alert: {e}", file=sys.stderr)



import urllib.error

def ping_healthcheck(status: str, message: str = ""):
    """
    Ping a Healthchecks.io URL with optional status message.

    - If HEALTHCHECKS_URL is unset or blank, this function does nothing.
    - Sends an OK ping by default.
    - Sends a /fail ping if status == "fail".
    """
    url = cfg.get("alerts", "HEALTHCHECKS_URL", fallback="").strip()
    if not url:
        if os.environ.get("DEBUG"):
            print("ℹ️  Healthchecks disabled (no URL configured).", file=sys.stderr)
        return

    full_url = url.rstrip("/")
    if status == "fail":
        full_url += "/fail"

    if message:
        full_url += f"?{urllib.parse.urlencode({'msg': message[:200]})}"

    try:
        urllib.request.urlopen(full_url, timeout=5)
    except urllib.error.URLError as e:
        print(f"⚠️ Failed to ping Healthchecks.io: {e}", file=sys.stderr)



def now_local():
    return datetime.now(pytz.timezone(TZNAME))


def solar_window(dt_local):
    """Return (is_daylight, sunrise, sunset) with grace windows."""
    loc = LocationInfo(CITY_NAME, "USA", TZNAME, LAT, LON)
    s = sun(loc.observer, date=dt_local.date(), tzinfo=dt_local.tzinfo)
    sunrise = s["sunrise"] + MORNING_GRACE
    sunset = s["sunset"] - EVENING_GRACE
    return (sunrise <= dt_local <= sunset, sunrise, sunset)


def scaled(values, name):
    """Return scaled numeric value (applies *_scale if present)."""
    if name not in values:
        return None
    raw = values.get(name)
    scale = 10 ** values.get(f"{name}_scale", 0)
    try:
        return float(raw) * float(scale)
    except Exception:
        return None


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


def read_inverter(inv, verbose=False):
    """Read key metrics from one inverter."""
    try:
        socket.gethostbyname(inv["host"])
        inverter = solaredge_modbus.Inverter(
            host=inv["host"],
            port=inv["port"],
            timeout=2,
            unit=inv["unit"],
        )
        v = inverter.read_all()
    except Exception as e:
        if verbose:
            print(f"[{inv['name']}] ERROR reading inverter: {e}", file=sys.stderr)
        return {"id": inv["name"], "error": True}

    model = v.get("c_model") or v.get("model")
    serial = v.get("c_serialnumber") or v.get("serialnumber")
    id_str = f"{model} [{serial}]" if model and serial else model or serial or inv["name"]

    return {
        "name": inv["name"],
        "id": id_str,
        "model": model,
        "serial": serial,
        "status": v.get("status"),
        "vendor_status": v.get("vendor_status"),
        "pac_W": scaled(v, "power_ac"),
        "vdc_V": scaled(v, "voltage_dc"),
        "idc_A": scaled(v, "current_dc"),
        "temp_C": scaled(v, "temperature"),
        "freq_Hz": scaled(v, "frequency"),
        "raw": v,
    }


# ---------------- ALERT REPETITION CONTROL ----------------

def load_alert_state():
    try:
        with open(ALERT_STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_alert_state(state):
    try:
        with open(ALERT_STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"⚠️ Failed to save alert state: {e}", file=sys.stderr)


def should_alert(key):
    """Return True if alert for 'key' should be triggered now (after X/Y rule)."""
    state = load_alert_state()
    now = time.time()
    record = state.get(key, {"count": 0, "first": now})
    if now - record["first"] > ALERT_REPEAT_WINDOW_MIN * 60:
        record = {"count": 0, "first": now}
    record["count"] += 1
    state[key] = record
    save_alert_state(state)
    return record["count"] >= ALERT_REPEAT_COUNT


# ---------------- DETECTION ----------------
# (unchanged from prior version)

# ---------------- MAIN ----------------

def build_arg_parser(inverter_names):
    choices_str = ", ".join(inverter_names) if inverter_names else "none available"
    ap = argparse.ArgumentParser(
        description="Monitor SolarEdge inverters via Modbus + optional Cloud API.\n"
                    "Sends alerts only after repeated detections (X over Y).",
        formatter_class=RawTextHelpFormatter,
        epilog=f"(Available inverters: {choices_str})"
    )
    ap.add_argument("--json", action="store_true", help="print full inverter readings as JSON and exit")
    ap.add_argument("--verbose", action="store_true", help="emit detailed logs during checks")
    ap.add_argument("--simulate", choices=["off", "low", "fault", "offline"], default="off",
                    help="simulate a failure mode on an inverter (default: off)")
    ap.add_argument("--simulate-target", metavar="NAME", choices=inverter_names,
                    help=f"apply simulation to inverter (choices: {choices_str})")
    ap.add_argument("--test-pushover", action="store_true",
                    help="send a test notification to verify Pushover configuration")
    return ap


def main():
    inverter_names = [inv["name"] for inv in INVERTERS]
    ap = build_arg_parser(inverter_names)
    args = ap.parse_args()

    # --- Pushover test mode ---
    if args.test_pushover:
        print("🔔 Sending test notification via Pushover...")
        msg = f"Test message from SolarEdge inverter monitor\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        pushover_notify("SolarEdge Monitor Test", msg, priority=0)
        print("✅ Test notification sent (check your device).")
        return 0

    dt_local = now_local()
    is_day, sunrise, sunset = solar_window(dt_local)

    if args.verbose:
        print(f"[time] now={dt_local.strftime('%Y-%m-%d %H:%M:%S %Z')} day={is_day} "
              f"sunrise+grace={sunrise.strftime('%H:%M')} sunset-grace={sunset.strftime('%H:%M')}")

    results, any_success = [], False
    for inv in INVERTERS:
        r = read_inverter(inv, verbose=args.verbose)
        results.append(r)
        if not r.get("error"):
            any_success = True
            if args.verbose:
                print(f"[{r['id']}] PAC={r['pac_W']:.0f}W Vdc={r['vdc_V']:.1f}V "
                      f"Idc={r['idc_A']:.2f}A status={status_text(r['status'])}")

    simulation_info = None

    # --- Simulation injection ---
    if args.simulate != "off" and results:
        target = None

        # User-specified target
        if args.simulate_target:
            for r in results:
                if r["name"] == args.simulate_target:
                    target = r
                    break
            if target is None:
                print(f"⚠️  No inverter found with name '{args.simulate_target}', using first inverter instead.")
                target = results[0]
        else:
            # Default to smallest model number
            def extract_kw(inv):
                model = inv.get("model", "") or inv["name"]
                import re
                m = re.search(r"(\d{4,5})", model)
                return int(m.group(1)) if m else 99999
            target = min(results, key=extract_kw)

        print(f"🔧 Simulating inverter '{target['name']}' in mode '{args.simulate}'")
        simulation_info = f"{args.simulate} on {target['name']}"

        # All other inverters simulate normal
        for r in results:
            if r is target:
                continue
            if not r.get("error"):
                r["status"] = 4
                r["pac_W"] = 5000.0
                r["vdc_V"] = 380.0
                r["idc_A"] = 13.0
                if args.verbose:
                    print(f"(Simulation) {r['id']} simulating normal output")

        # Target inverter behavior
        if args.simulate == "low":
            target["pac_W"] = 0.0
            target["status"] = 4
            print(f"(Simulation) {target['id']} simulating 0W output")
        elif args.simulate == "fault":
            target["status"] = 7
            print(f"(Simulation) {target['id']} simulating FAULT state")
        elif args.simulate == "offline":
            target["error"] = True
            print(f"(Simulation) {target['id']} simulating unreachable state")

    # --- JSON output ---
    if args.json:
        out = {"results": results, "timestamp": dt_local.isoformat()}
        if simulation_info:
            out["simulation"] = simulation_info
        print(json.dumps(out, indent=2, default=str))
        return 0

    # ... (rest of main unchanged: anomaly detection, alerts, API checks)


    if not any_success:
        print("ERROR: no inverter responded", file=sys.stderr)
        ping_healthcheck("fail", message="No inverter responded")
        return 1

    all_sleeping = all(r.get("status") == 2 for r in results if not r.get("error"))
    if all_sleeping or not is_day:
        if args.verbose:
            reason = "all Sleeping" if all_sleeping else "Astral night"
            print(f"Night window ({reason}): skipping checks.")
        return 0

    read_ok = [r for r in results if not r.get("error")]
    alerts = detect_anomalies(read_ok)

    for r in results:
        if r.get("error"):
            alerts.append(f"{r['id']}: Modbus read failed")

    # --- Cloud API checks ---
    cloud_alerts = check_solaredge_api()
    if cloud_alerts:
        print("Cloud API Alerts:")
        for a in cloud_alerts:
            print("  -", a)
        alerts.extend(cloud_alerts)

    if alerts:
        confirmed = []
        for msg in alerts:
            key = msg.split(":")[0]
            if should_alert(key):
                confirmed.append(msg)
        if confirmed:
            msg = "\n".join(confirmed)
            print(f"ALERT:\n{msg}")
            pushover_notify("SolarEdge Monitor Alert", msg, priority=1)
            ping_healthcheck("fail", message=confirmed[0])
            return 2
        else:
            # Suppressed (not repeated enough within the window)
            return 0

    if args.verbose:
        print("OK: all inverters normal.")
    ping_healthcheck("ok", message="All normal")
    return 0


if __name__ == "__main__":
    sys.exit(main())
