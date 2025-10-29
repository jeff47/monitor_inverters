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
import socket
import time
import urllib.request
import urllib.parse
import urllib.error
import pytz
import configparser
#import solaredge_modbus
from astral import LocationInfo
from astral.sun import sun
import requests
import datetime as dt
from datetime import datetime, timedelta
import argparse
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse, urlunparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------- Load developmental solaredge_modbus module instead of system version --------
import importlib.util
from pathlib import Path

# Absolute path to your module
mod_path = Path("/home/jeff/projects/personal/solaredge_modbus/src/solaredge_modbus/__init__.py")

# Dynamically load only this specific module
spec = importlib.util.spec_from_file_location("solaredge_modbus", mod_path)
solaredge_modbus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(solaredge_modbus)

# Optionally register in sys.modules for dependent imports to see it
sys.modules["solaredge_modbus"] = solaredge_modbus

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


def get_cfg(section, key, fallback=None, cast=None):
    """Safer config accessor with fallback and optional casting."""
    try:
        val = cfg.get(section, key, fallback=fallback)
        if cast and val is not None:
            return cast(val)
        return val
    except (configparser.NoSectionError, configparser.NoOptionError):
        return fallback


# ---------------- CONFIG VALUES ----------------

CITY_NAME = get_cfg("site", "CITY_NAME")
LAT = get_cfg("site", "LAT", cast=float)
LON = get_cfg("site", "LON", cast=float)
TZNAME = get_cfg("site", "TZNAME")

# Cache Astral location
ASTRAL_LOC = LocationInfo(CITY_NAME, "USA", TZNAME, LAT, LON)

# Inverters
INVERTERS = []
for part in get_cfg("inverters", "INVERTERS", fallback="").split(","):
    part = part.strip()
    if not part:
        continue
    try:
        name, host, port, unit = [x.strip() for x in part.split(":")]
        INVERTERS.append({
            "name": name,
            "host": host,
            "port": int(port),
            "unit": int(unit),
        })
    except ValueError:
        print(f"⚠️ Invalid inverter entry: '{part}'", file=sys.stderr)

# Thresholds
MORNING_GRACE = timedelta(minutes=get_cfg("thresholds", "MORNING_GRACE_MIN", fallback=20, cast=float))
EVENING_GRACE = timedelta(minutes=get_cfg("thresholds", "EVENING_GRACE_MIN", fallback=10, cast=float))
ABS_MIN_WATTS = get_cfg("thresholds", "ABS_MIN_WATTS", fallback=150, cast=float)
SAFE_DC_VOLT_MAX = get_cfg("thresholds", "SAFE_DC_VOLT_MAX", fallback=150, cast=float)
ZERO_CURRENT_EPS = get_cfg("thresholds", "ZERO_CURRENT_EPS", fallback=0.05, cast=float)
PEER_COMPARE = cfg.getboolean("thresholds", "PEER_COMPARE", fallback=True)
PEER_MIN_WATTS = get_cfg("thresholds", "PEER_MIN_WATTS", fallback=600, cast=float)
PEER_LOW_RATIO = get_cfg("thresholds", "PEER_LOW_RATIO", fallback=0.20, cast=float)
MODBUS_TIMEOUT = get_cfg("thresholds", "MODBUS_TIMEOUT", fallback=1.0, cast=float)
MODBUS_RETRIES = get_cfg("thresholds", "MODBUS_RETRIES", fallback=3, cast=int)

# Alert repetition
ALERT_REPEAT_COUNT = get_cfg("alerts", "ALERT_REPEAT_COUNT", fallback=3, cast=int)
ALERT_REPEAT_WINDOW_MIN = get_cfg("alerts", "ALERT_REPEAT_WINDOW_MIN", fallback=30, cast=int)
ALERT_STATE_FILE = get_cfg("alerts", "ALERT_STATE_FILE", fallback="/tmp/inverter_alert_state.json")

# Healthchecks
HEALTHCHECKS_URL = get_cfg("alerts", "HEALTHCHECKS_URL", fallback="").strip()

# Pushover
PUSHOVER_USER_KEY = get_cfg("pushover", "PUSHOVER_USER_KEY", fallback=None)
PUSHOVER_API_TOKEN = get_cfg("pushover", "PUSHOVER_API_TOKEN", fallback=None)

# SolarEdge Cloud API
ENABLE_SOLAREDGE_API = cfg.getboolean("solaredge_api", "ENABLE_SOLAREDGE_API", fallback=False)
SOLAREDGE_API_KEY = get_cfg("solaredge_api", "SOLAREDGE_API_KEY", fallback=None)
SOLAREDGE_SITE_ID = get_cfg("solaredge_api", "SOLAREDGE_SITE_ID", fallback=None)


# ---------------- UTILITIES ----------------
def load_optimizer_expectations():
    """
    Reads [optimizers] section.
    - TOTAL_EXPECTED (int): optional
    - Other keys are inverter serial numbers with expected optimizer counts.
    """
    total_expected = None
    per_inv_expected = {}

    if cfg.has_section("optimizers"):
        for key, val in cfg.items("optimizers"):
            key = key.strip().upper()
            try:
                count = int(str(val).strip())
            except Exception:
                continue
            if key == "TOTAL_EXPECTED":
                total_expected = count
            else:
                # Always treat as serial number
                per_inv_expected[key] = count

    return total_expected, per_inv_expected



def pushover_notify(title: str, message: str, priority: int = 0):
    """
    Send a Pushover notification if credentials are configured.
    - If BOTH PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN are blank → skip silently.
    - If ONE missing → raise RuntimeError (config error).
    """
    user_key = (PUSHOVER_USER_KEY or "").strip()
    api_token = (PUSHOVER_API_TOKEN or "").strip()

    if not user_key and not api_token:
        if os.environ.get("DEBUG"):
            print("ℹ️  Pushover disabled (no credentials configured).", file=sys.stderr)
        return

    if bool(user_key) != bool(api_token):
        raise RuntimeError("Configuration error: Both PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN must be set for Pushover.")

    data = urlencode({
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


def ping_healthcheck(status: str, message: str = ""):
    """
    Ping Healthchecks.io with optional status message.
    Disabled if HEALTHCHECKS_URL missing/blank.
    """
    if not HEALTHCHECKS_URL:
        if os.environ.get("DEBUG"):
            print("ℹ️  Healthchecks disabled (no URL configured).", file=sys.stderr)
        return

    url = HEALTHCHECKS_URL.rstrip("/")
    if status == "fail":
        url += "/fail"

    parsed = list(urlparse(url))
    query = {}
    if message:
        query["msg"] = message[:200]
    parsed[4] = urlencode(query)
    full_url = urlunparse(parsed)

    try:
        urllib.request.urlopen(full_url, timeout=5)
    except urllib.error.URLError as e:
        print(f"⚠️ Failed to ping Healthchecks.io: {e}", file=sys.stderr)


def now_local():
    return datetime.now(pytz.timezone(TZNAME))


def solar_window(dt_local):
    """Return (is_daylight, sunrise, sunset) with grace windows."""
    s = sun(ASTRAL_LOC.observer, date=dt_local.date(), tzinfo=dt_local.tzinfo)
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
            timeout=MODBUS_TIMEOUT,
            retries=MODBUS_RETRIES,
            unit=inv["unit"],
        )

        v = inverter.read_all()
    except (socket.error, OSError, Exception) as e:
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


# ---------------- SIMULATION CONSTANTS ----------------

SIMULATED_NORMAL = {"status": 4, "pac_W": 5000.0, "vdc_V": 380.0, "idc_A": 13.0}


# ---------------- CLI ARGUMENTS ----------------

def build_arg_parser(inverter_names):
    choices_str = ", ".join(inverter_names) if inverter_names else "none available"

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
            "Sends alerts only after repeated detections (X over Y).\n\n"
            f"(Available inverters: {choices_str})"
        ),
        formatter_class=RawTextHelpFormatter,
        epilog=f"{exit_codes}\n{examples}"
    )

    ap.add_argument("--json", action="store_true", help="print full inverter readings as JSON and exit")
    ap.add_argument("--verbose", action="store_true", help="emit detailed logs during checks")
    ap.add_argument("--quiet", action="store_true", help="suppress non-error output (cron-friendly)")
    ap.add_argument("--simulate", choices=["off", "low", "fault", "offline"], default="off",
                    help="simulate a failure mode on an inverter (default: off)")
    ap.add_argument("--simulate-target", metavar="NAME", choices=inverter_names,
                    help=f"apply simulation to inverter (choices: {choices_str})")
    ap.add_argument("--test-pushover", action="store_true",
                    help="send a test notification to verify Pushover configuration")

    return ap



# ---------------- MAIN ----------------

def main():
    inverter_names = [inv["name"] for inv in INVERTERS]
    ap = build_arg_parser(inverter_names)
    args = ap.parse_args()

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
        pushover_notify("SolarEdge Monitor Test", msg, priority=0)
        log("✅ Test notification sent (check your device).")
        return 0

    dt_local = now_local()
    is_day, sunrise, sunset = solar_window(dt_local)

    if args.verbose and not args.quiet:
        log(f"[time] now={dt_local.strftime('%Y-%m-%d %H:%M:%S %Z')} day={is_day} "
            f"sunrise+grace={sunrise.strftime('%H:%M')} sunset-grace={sunset.strftime('%H:%M')}")

    results, any_success = [], False

    # Threaded Modbus reads
    with ThreadPoolExecutor(max_workers=min(8, len(INVERTERS) or 1)) as executor:
        futures = {executor.submit(read_inverter, inv, args.verbose): inv for inv in INVERTERS}

        for future in as_completed(futures):
            inv = futures[future]
            try:
                r = future.result()
            except Exception as e:
                r = {"id": inv["name"], "error": True}
                print(f"[{inv['name']}] Threaded read exception: {e}", file=sys.stderr)
            results.append(r)
            if not r.get("error"):
                any_success = True
                if args.verbose and not args.quiet:
                    log(f"[{r['id']}] PAC={r['pac_W']:.0f}W Vdc={r['vdc_V']:.1f}V "
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
                log(f"⚠️ No inverter found with name '{args.simulate_target}', using first inverter instead.")
                target = results[0]
        else:
            # Default: lowest kW model
            def extract_kw(inv):
                import re
                model = inv.get("model", "") or inv["name"]
                m = re.search(r"(\d{4,5})", model)
                return int(m.group(1)) if m else 99999
            target = min(results, key=extract_kw)

        log(f"🔧 Simulating inverter '{target['name']}' in mode '{args.simulate}'")
        simulation_info = f"{args.simulate} on {target['name']}"

        # All others simulate normal
        for r in results:
            if r is target:
                continue
            if not r.get("error"):
                r.update(SIMULATED_NORMAL)
                if args.verbose:
                    log(f"(Simulation) {r['id']} simulating normal output")

        # Target inverter behavior
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
        log("ERROR: no inverter responded", err=True)
        ping_healthcheck("fail", message="No inverter responded")
        return 1

    all_sleeping = all(r.get("status") == 2 for r in results if not r.get("error"))

    # Skip only Modbus-based production checks at night,
    # but still allow SolarEdge API health/fault checks.
    if not ENABLE_SOLAREDGE_API:
        if all_sleeping or not is_day:
            if args.verbose and not args.quiet:
                reason = "all Sleeping" if all_sleeping else "Astral night"
                log(f"Night window ({reason}): skipping checks.")
            return 0


    # ---------------- DETECTION ----------------

    def detect_anomalies(results):
        """Return list of alert strings based on status and power rules."""
        alerts = []
        for r in results:
            st, st_txt = r["status"], status_text(r["status"])
            pac, vdc, idc = r["pac_W"], r["vdc_V"], r["idc_A"]

            # Skip production/safety checks at night
            if not is_day:
                continue

            if st not in (2, 4):
                alerts.append(f"{r['id']}: Abnormal status ({st_txt})")



            if vdc is not None and idc is not None:
                if abs(idc) <= ZERO_CURRENT_EPS and vdc < SAFE_DC_VOLT_MAX:
                    alerts.append(
                        f"{r['id']}: SafeDC/open-DC suspected "
                        f"(Vdc={vdc:.1f}V, Idc≈0A, status={st_txt})"
                    )

            if pac is not None and pac < ABS_MIN_WATTS and st == 4:
                alerts.append(
                    f"{r['id']}: Low production "
                    f"(PAC={pac:.0f}W < {ABS_MIN_WATTS:.0f}W, status={st_txt})"
                )

        if PEER_COMPARE and len(results) >= 2:
            pacs = [r["pac_W"] for r in results if r["pac_W"] is not None]
            if pacs and max(pacs) >= PEER_MIN_WATTS:
                med = sorted(pacs)[len(pacs) // 2]
                threshold = max(med * PEER_LOW_RATIO, ABS_MIN_WATTS)
                for r in results:
                    pac = r["pac_W"]
                    if pac is None:
                        continue
                    if pac < threshold:
                        alerts.append(
                            f"{r['id']}: Under peer median "
                            f"(PAC={pac:.0f}W < {threshold:.0f}W, peers median≈{med:.0f}W)"
                        )

        # Merge duplicate keys for cleaner output
        merged = {}
        for msg in alerts:
            key = msg.split(":")[0]
            merged.setdefault(key, []).append(msg)
        out = []
        for k, msgs in merged.items():
            if len(msgs) == 1:
                out.append(msgs[0])
            else:
                out.append(f"{k}: " + " | ".join(m.split(": ", 1)[1] for m in msgs))
        return out


    # ---------------- SOLAREDGE API CHECK ----------------

    def check_solaredge_api():
        """Check inverter health/faults and optimizer connectivity via SolarEdge Cloud API."""
        if not ENABLE_SOLAREDGE_API:
            return []
        if not SOLAREDGE_API_KEY or not SOLAREDGE_SITE_ID:
            return ["SolarEdge API not configured (missing SOLAREDGE_SITE_ID or SOLAREDGE_API_KEY)"]

        base_url = "https://monitoringapi.solaredge.com"
        alerts = []
        session = requests.Session()
        total_expected, expected_by_serial = load_optimizer_expectations()

        # --- (A) Fetch inverter list ---
        try:
            eq_url = f"{base_url}/equipment/{SOLAREDGE_SITE_ID}/list?api_key={SOLAREDGE_API_KEY}"
            resp = session.get(eq_url, timeout=15)
            resp.raise_for_status()
            eq_list = resp.json().get("reporters", {}).get("list", [])
        except Exception as e:
            return [f"SolarEdge API equipment list error: {e}"]

        # Map serial → human name for output clarity
        serial_to_name = {e.get("serialNumber"): e.get("name", e.get("serialNumber")) for e in eq_list}

        # --- (B) Check inverter telemetry for FAULT / OFF / 0W-with-DC ---
        now = dt.datetime.now()
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
        dt_local = now_local()
        is_day, _, _ = solar_window(dt_local)

        for e in eq_list:
            serial = e.get("serialNumber")
            name = serial_to_name.get(serial, serial)
            if not serial:
                continue
            try:
                params = {
                    "startTime": start.strftime("%Y-%m-%d %H:%M:%S"),
                    "endTime":   end.strftime("%Y-%m-%d %H:%M:%S"),
                    "api_key":   SOLAREDGE_API_KEY,
                }
                r = session.get(f"{base_url}/equipment/{SOLAREDGE_SITE_ID}/{serial}/data",
                                params=params, timeout=20)

                if r.status_code != 200:
                    alerts.append(f"{name}: API returned {r.status_code} for inverter data")
                    continue

                tele = r.json().get("data", {}).get("telemetries", [])
                if not tele:
                    alerts.append(f"{name}: no telemetry data received today")
                    continue

                # --- Scan all telemetry for faults during the day ---
                # Some systems report a brief FAULT then recover, so we look across all samples.

                fault_modes = []
                zero_output_intervals = []

                for t in tele:
                    mode = t.get("inverterMode")
                    pac = t.get("totalActivePower", 0.0)
                    vdc = t.get("dcVoltage")
                    if mode in ("FAULT", "OFF"):
                        fault_modes.append(t)
                    elif is_day and pac == 0 and (vdc is None or vdc > 50):
                        zero_output_intervals.append(t)

                if fault_modes:
                    first_fault = fault_modes[0]["date"]
                    last_fault = fault_modes[-1]["date"]
                    alerts.append(f"{name}: inverterMode=FAULT/OFF observed {first_fault} → {last_fault}")
                elif zero_output_intervals:
                    first_zero = zero_output_intervals[0]["date"]
                    alerts.append(f"{name}: 0 W output with DC present (since {first_zero})")

            except Exception as ex:
                alerts.append(f"{name}: failed to read inverter data ({ex})")

        # --- (C) Optimizer connectivity via /inventory ---
        try:
            inv_url = f"{base_url}/site/{SOLAREDGE_SITE_ID}/inventory?api_key={SOLAREDGE_API_KEY}"
            inv_resp = session.get(inv_url, timeout=15)
            inv_resp.raise_for_status()
            inv_json = inv_resp.json()
        except Exception as e:
            alerts.append(f"Inventory read error: {e}")
            return alerts

        inverters = inv_json.get("Inventory", {}).get("inverters", []) or []
        per_serial_counts = {}
        total_connected = 0

        for inv in inverters:
            serial = (
                inv.get("serialNumber")
                or inv.get("sn")
                or inv.get("SN")
                or inv.get("serial")
                or inv.get("SerialNumber")
         )
            count = inv.get("connectedOptimizers", 0)
            try:
                count = int(count)
            except Exception:
                count = 0
            per_serial_counts[str(serial).upper()] = count
            total_connected += count

        # (C1) Check total
        if isinstance(total_expected, int) and total_connected < total_expected:
            alerts.append(
                f"Optimizers: {total_connected} connected < expected {total_expected} (total)"
            )

        # (C2) Check per-inverter expectations by serial
        for serial, expected in expected_by_serial.items():
            actual = per_serial_counts.get(serial.upper())
            name = serial_to_name.get(serial, serial)
            if actual is None:
                alerts.append(f"{name}: optimizer count unavailable (serial {serial})")
            elif actual < expected:
                alerts.append(f"{name}: {actual} optimizers < expected {expected}")

        return alerts




    read_ok = [r for r in results if not r.get("error")]
    alerts = detect_anomalies(read_ok)

    for r in results:
        if r.get("error"):
            alerts.append(f"{r['id']}: Modbus read failed")

    cloud_alerts = check_solaredge_api()
    if cloud_alerts:
        log("Cloud API Alerts:")
        for a in cloud_alerts:
            log("  - " + a)
        alerts.extend(cloud_alerts)

    if alerts:
        confirmed = []
        for msg in alerts:
            key = msg.split(":")[0]
            if should_alert(key):
                confirmed.append(msg)
        if confirmed:
            msg = "\n".join(confirmed)
            log(f"ALERT:\n{msg}")
            pushover_notify("SolarEdge Monitor Alert", msg, priority=1)
            ping_healthcheck("fail", message=confirmed[0])
            return 2
        else:
            return 0

    log("OK: all inverters normal.")
    ping_healthcheck("ok", message="All normal")
    return 0


# ---------------- ENTRY POINT ----------------

# Exit codes:
#   0 = OK or suppressed alert
#   1 = No inverter responded
#   2 = Confirmed alert triggered
if __name__ == "__main__":
    sys.exit(main())
