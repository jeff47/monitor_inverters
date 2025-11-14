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
# import solaredge_modbus
from astral import LocationInfo
from astral.sun import sun
import requests
import datetime as dt
from datetime import datetime, timedelta
import argparse
from argparse import RawTextHelpFormatter
from urllib.parse import urlparse, urlunparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from pathlib import Path
import importlib.util

# -------- Load developmental solaredge_modbus module instead of system version --------
mod_path = Path("/home/jeff/projects/personal/solaredge_modbus/src/solaredge_modbus/__init__.py")
spec = importlib.util.spec_from_file_location("solaredge_modbus", mod_path)
solaredge_modbus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(solaredge_modbus)
sys.modules["solaredge_modbus"] = solaredge_modbus

# ---------------- IDENTITY HELPERS ----------------

SERIAL_RE = re.compile(r"([0-9A-Fa-f]{6,})")

def clean_serial(s: str) -> str:
    """Return uppercased serial without SolarEdge suffixes like '-CF'."""
    if not s:
        return ""
    return s.split("-")[0].upper().strip()

def model_base(model: str) -> str:
    """Return model truncated at first hyphen (e.g., 'SE7600H-US000BNI4' -> 'SE7600H')."""
    if not model:
        return ""
    return model.split("-", 1)[0].strip()

def inv_display_from_parts(model: str, serial: str) -> str:
    """Canonical visible identity: 'MODELBASE [SERIAL]' when both present."""
    mb = model_base(model)
    ser = clean_serial(serial)
    if mb and ser:
        return f"{mb} [{ser}]"
    if ser:
        return f"[{ser}]"
    return mb or "UNKNOWN"

def extract_serial_from_text(s: str) -> str:
    """Find serial inside square brackets or anywhere in text."""
    if not s:
        return ""
    m = re.search(r"\[([0-9A-Fa-f]{6,})\]", s)
    if m:
        return m.group(1).upper()
    m2 = SERIAL_RE.search(s)
    return m2.group(1).upper() if m2 else ""

def key_for_alert_message(msg: str) -> str:
    """Stable key for dedupe / repeat-suppression: prefer serial, else prefix text."""
    ser = extract_serial_from_text(msg)
    if ser:
        return ser
    # fallback to prefix before ':' normalized
    return (msg.split(":", 1)[0].strip().upper()) if ":" in msg else msg.strip().upper()

# ---------------- CONFIG LOADING ----------------

def load_config(path="monitor_inverters.conf"):
    """Read configuration from INI file using configparser."""
    parser = configparser.ConfigParser()
    parser = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
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

# ---------------- DAILY SUMMARY CONFIG ----------------
DAILY_SUMMARY_ENABLED = cfg.getboolean("alerts", "DAILY_SUMMARY_ENABLED", fallback=True)
DAILY_SUMMARY_METHOD = get_cfg("alerts", "DAILY_SUMMARY_METHOD", fallback="api").strip().lower()  # "api" or "modbus"
DAILY_SUMMARY_OFFSET_MIN = get_cfg("alerts", "DAILY_SUMMARY_OFFSET_MIN", fallback=60, cast=int)  # sunset + 60 min

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
            key_up = key.strip().upper()
            try:
                count = int(str(val).strip())
            except Exception:
                continue
            if key_up == "TOTAL_EXPECTED":
                total_expected = count
            else:
                per_inv_expected[clean_serial(key_up)] = count

    return total_expected, per_inv_expected

def pushover_notify(title: str, message: str, priority: int = 0):
    """Send a Pushover notification if credentials are configured."""
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
    """Ping Healthchecks.io with optional status message."""
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
    id_str = inv_display_from_parts(model, serial)

    return {
        "name": inv["name"],     # configured nickname
        "id": id_str,            # canonical visible identity
        "model": model,
        "serial": clean_serial(serial),
        "status": v.get("status"),
        "vendor_status": v.get("vendor_status"),
        "pac_W": scaled(v, "power_ac"),
        "vdc_V": scaled(v, "voltage_dc"),
        "idc_A": scaled(v, "current_dc"),
        "temp_C": scaled(v, "temperature"),
        "freq_Hz": scaled(v, "frequency"),
        "e_total_Wh": scaled(v, "energy_total") or scaled(v, "total_energy"),
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
def update_inverter_states(results):
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
            pushover_notify("SolarEdge Recovery", msg, priority=0)
        state.setdefault(key_state, {})["last_mode"] = st_txt
    save_alert_state(state)
    return recoveries

# ---------------- DAILY SUMMARY ----------------
def _fetch_site_daily_kwh_api():
    """Return dict {"site_total": kWh} for today using SolarEdge API, with verbose debug."""
    if not (ENABLE_SOLAREDGE_API and SOLAREDGE_API_KEY and SOLAREDGE_SITE_ID):
        print("🔍 [DEBUG] API disabled or missing key/site id.")
        return None
    base = "https://monitoringapi.solaredge.com"
    session = requests.Session()
    today = datetime.now().strftime("%Y-%m-%d")
    params = {
        "timeUnit": "DAY",
        "startDate": today,
        "endDate": today,
        "api_key": SOLAREDGE_API_KEY,
    }
    url = f"{base}/site/{SOLAREDGE_SITE_ID}/energy"
    try:
        r = session.get(url, params=params, timeout=20)
        if r.status_code != 200:
            print("⚠️ [DEBUG] Non-200 from API; aborting site energy fetch.")
            return None
        j = r.json()
        energy = j.get("energy", {})
        values = energy.get("values", [])
        if not values:
            return None
        first = values[0]
        total_Wh = first.get("value")
        if total_Wh is None:
            return None
        total_kWh = round(float(total_Wh) / 1000.0, 2)
        return {"site_total": total_kWh}
    except Exception as e:
        print(f"⚠️ [DEBUG] Exception in _fetch_site_daily_kwh_api: {e}", file=sys.stderr)
        return None

def _compute_per_inverter_daily_kwh_modbus(results):
    """Compute per-inverter kWh for today from lifetime Wh deltas."""
    state = load_alert_state()
    date_str = now_local().strftime("%Y-%m-%d")
    totals = {}
    for r in results:
        key_display = inv_display_from_parts(r.get("model"), r.get("serial"))
        key_state = f"{clean_serial(r.get('serial')) or key_display.upper()}:{date_str}"
        e_total_Wh = r.get("e_total_Wh")
        if e_total_Wh is None:
            continue
        energy_state = state.setdefault("energy", {})
        baseline = energy_state.get(key_state)
        if baseline is None:
            energy_state[key_state] = e_total_Wh
            delta_Wh = 0.0
        else:
            delta_Wh = max(0.0, e_total_Wh - float(baseline))
        totals[key_display] = round(delta_Wh / 1000.0, 2)
    save_alert_state(state)
    return totals

def maybe_send_daily_summary(results):
    """Send once-per-day summary at (sunset + DAILY_SUMMARY_OFFSET_MIN) or immediately if forced."""
    if not DAILY_SUMMARY_ENABLED:
        return
    dt_local = now_local()
    date_str = dt_local.strftime("%Y-%m-%d")
    state = load_alert_state()
    last = state.get("daily_summary", {})
    forced = "--force-summary" in sys.argv
    if not forced:
        if last.get("date") == date_str and last.get("sent"):
            return
        _, _, sunset = solar_window(dt_local)
        trigger_time = sunset + timedelta(minutes=DAILY_SUMMARY_OFFSET_MIN)
        if dt_local < trigger_time:
            return
    per_inv = None
    if DAILY_SUMMARY_METHOD == "api":
        per_inv = _fetch_site_daily_kwh_api()
    if per_inv is None:
        print("🔍 [DEBUG] API fetch failed or empty; trying Modbus fallback.")
        per_inv = _compute_per_inverter_daily_kwh_modbus(results)
    if not per_inv:
        print("⚠️ [DEBUG] No daily summary data found; aborting.")
        return
    total = round(sum(v for v in per_inv.values()), 2)
    lines = [f"{n}: {v:.2f} kWh" for n, v in sorted(per_inv.items())]
    lines.append(f"Total: {total:.2f} kWh")
    msg = "\n".join(lines)
    print(msg)
    pushover_notify(f"SolarEdge Daily Summary — {date_str}", msg, priority=0)
    state["daily_summary"] = {"date": date_str, "sent": True}
    save_alert_state(state)

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
    ap.add_argument("--force-summary", action="store_true",
                    help="force immediate daily summary (bypass sunset/time guard)")
    ap.add_argument("--debug", action="store_true",
                help="enable extra debug output (API and Modbus details)")
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
                    log(f"[{r['id']}] (modbus) PAC={r['pac_W']:.0f}W Vdc={r['vdc_V']:.1f}V "
                        f"Idc={r['idc_A']:.2f}A status={status_text(r['status'])}")


    # --- Simulation injection ---
    simulation_info = None
    if args.simulate != "off" and results:
        target = None
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

        # Merge duplicate keys for cleaner output (within Modbus-generated alerts)
        merged = {}
        for msg in alerts:
            key = extract_serial_from_text(msg) or msg.split(":", 1)[0].strip().upper()
            merged.setdefault(key, []).append(msg)
        out = []
        for k, msgs in merged.items():
            if len(msgs) == 1:
                out.append(msgs[0])
            else:
                out.append(f"{msgs[0].split(':',1)[0]}: " + " | ".join(m.split(": ", 1)[1] for m in msgs))
        return out

    # ---------------- SOLAREDGE API CHECK ----------------
    def check_solaredge_api(modbus_results):
        """Fetch inverter and optimizer data from the SolarEdge Cloud API."""
        if not ENABLE_SOLAREDGE_API:
            return []
        if not SOLAREDGE_API_KEY or not SOLAREDGE_SITE_ID:
            return ["SolarEdge API not configured (missing SOLAREDGE_SITE_ID or SOLAREDGE_API_KEY)"]

        base_url = "https://monitoringapi.solaredge.com"
        session = requests.Session()
        alerts = []
        total_expected, expected_by_serial = load_optimizer_expectations()

        # Build Modbus serial→modelbase map for consistent display in API alerts
        serial_to_modelbase = {}
        for r in (m for m in modbus_results if not m.get("error")):
            serial_to_modelbase[clean_serial(r.get("serial"))] = model_base(r.get("model"))

        # --- (A) Equipment list ---
        try:
            eq_url = f"{base_url}/equipment/{SOLAREDGE_SITE_ID}/list?api_key={SOLAREDGE_API_KEY}"
            resp = session.get(eq_url, timeout=15)
            resp.raise_for_status()
            eq_list = resp.json().get("reporters", {}).get("list", [])
            if args.debug:
                print(f"[DEBUG] (api) Equipment list: {len(eq_list)} devices retrieved")
        except Exception as e:
            return [f"SolarEdge API equipment list error: {e}"]

        # --- (B) Inverter telemetry ---
        now = dt.datetime.now()
        start = now - timedelta(hours=1)
        end = now

        for e in eq_list:
            serial = clean_serial(e.get("serialNumber"))
            if not serial:
                continue
            mb = serial_to_modelbase.get(serial, "")  # prefer Modbus model base
            display = inv_display_from_parts(mb, serial)

            params = {
                "startTime": start.strftime("%Y-%m-%d %H:%M:%S"),
                "endTime": end.strftime("%Y-%m-%d %H:%M:%S"),
                "api_key": SOLAREDGE_API_KEY,
            }
            try:
                url = f"{base_url}/equipment/{SOLAREDGE_SITE_ID}/{serial}/data"
                r = session.get(url, params=params, timeout=20)
                r.raise_for_status()
                tele = r.json().get("data", {}).get("telemetries", [])
                if not tele:
                    alerts.append(f"{display}: no telemetry data in past hour")
                    if args.debug:
                        print(f"[DEBUG] (api) {display}: no telemetry in {start:%H:%M}–{end:%H:%M}")
                    continue

                latest = tele[-1]
                pac = latest.get("totalActivePower", 0.0)
                vdc = latest.get("dcVoltage")
                mode = latest.get("inverterMode", "UNKNOWN")
                ts = latest.get("date")

                if args.debug:
                    print(f"[DEBUG] (api) {display}: {pac:.1f} W, {vdc} Vdc, mode={mode}, time={ts}")

                if mode in ("FAULT", "OFF"):
                    alerts.append(f"{display}: inverterMode={mode} (API time {ts})")
                elif pac == 0 and vdc and vdc > 50:
                    alerts.append(f"{display}: 0 W output with DC present (API time {ts})")

            except Exception as ex:
                alerts.append(f"{display}: failed to read inverter data ({ex})")
                if args.debug:
                    print(f"[DEBUG] (api) {display}: telemetry request failed → {ex}")

        # --- (C) Optimizer connectivity (from /site/.../inventory) ---
        try:
            inv_url = f"{base_url}/site/{SOLAREDGE_SITE_ID}/inventory?api_key={SOLAREDGE_API_KEY}"
            inv_resp = session.get(inv_url, timeout=15)
            inv_resp.raise_for_status()
            inv_json = inv_resp.json()
            if args.debug:
                print(f"[DEBUG] (api) Inventory query OK, keys: {list(inv_json.keys())}")
        except Exception as e:
            alerts.append(f"Inventory read error: {e}")
            return alerts

        inverters = inv_json.get("Inventory", {}).get("inverters", []) or []
        per_serial_counts = {}
        total_connected = 0

        for inv in inverters:
            serial_raw = inv.get("serialNumber") or inv.get("SN") or ""
            serial = clean_serial(serial_raw)
            mb = serial_to_modelbase.get(serial, "")
            display = inv_display_from_parts(mb, serial)
            count = inv.get("connectedOptimizers")
            try:
                count = int(count) if count is not None else 0
            except Exception:
                count = 0
            per_serial_counts[serial] = count
            total_connected += count
            if args.debug:
                print(f"[DEBUG] (api) {display}: {count} optimizers connected")

        if args.debug:
            print(f"[DEBUG] (api) Total optimizers connected: {total_connected}")

        # --- (D) Compare against expected counts ---
        if isinstance(total_expected, int) and total_connected < total_expected:
            alerts.append(f"Optimizers: {total_connected} connected < expected {total_expected} (total)")

        # --- (E) Compare against expected counts per inverter (normalized serials) ---
        for exp_serial, expected in expected_by_serial.items():
            s = clean_serial(exp_serial)
            actual = per_serial_counts.get(s)
            display = inv_display_from_parts(serial_to_modelbase.get(s, ""), s)
            if actual is None:
                if args.debug:
                    print(f"[DEBUG] No optimizer data match for expected serial {s}")
                if total_connected == 0:
                    alerts.append(f"{display}: optimizer count unavailable")
            elif actual < expected:
                alerts.append(f"{display}: {actual} optimizers < expected {expected}")

        return alerts


    read_ok = [r for r in results if not r.get("error")]
    alerts = detect_anomalies(read_ok)

    # Track and notify recoveries ---
    recoveries = update_inverter_states(read_ok)
    for msg in recoveries:
        log(f"ℹ️ {msg}")

    for r in results:
        if r.get("error"):
            # Use canonical display even for errors
            display = inv_display_from_parts(r.get("model"), r.get("serial"))
            alerts.append(f"{display}: Modbus read failed")

    # Cloud API checks
    cloud_alerts = check_solaredge_api(read_ok)
    if cloud_alerts:
        log("Cloud API Alerts:")
        for a in cloud_alerts:
            log("  - " + a)
        alerts.extend(cloud_alerts)

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
            pushover_notify("SolarEdge Monitor Alert", msg, priority=1)
            ping_healthcheck("fail", message=confirmed[0])
            exit_code = 2
        else:
            exit_code = 0
    else:
        log("OK: all inverters normal.")
        ping_healthcheck("ok", message="All normal")

    # Always try sending summary, even if alert occurred
    try:
        if args.force_summary:
            log("📊 Forcing daily summary now (--force-summary).")
        maybe_send_daily_summary(read_ok)
    except Exception as e:
        log(f"⚠️ Failed to compute/send daily summary: {e}", err=True)

    return exit_code

# ---------------- ENTRY POINT ----------------
#   0 = OK or suppressed alert
#   1 = No inverter responded
#   2 = Confirmed alert triggered
if __name__ == "__main__":
    sys.exit(main())
