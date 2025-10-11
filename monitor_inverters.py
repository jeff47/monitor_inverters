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
    """Send a Pushover notification if credentials are configured."""
    if not PUSHOVER_USER_KEY or not PUSHOVER_API_TOKEN:
        return

    data = urllib.parse.urlencode({
        "token": PUSHOVER_API_TOKEN,
        "user": PUSHOVER_USER_KEY,
        "title": title,
        "message": message,
        "priority": str(priority),
    }).encode("utf-8")

    try:
        req = urllib.request.Request("https://api.pushover.net/1/messages.json", data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"⚠️ Failed to send Pushover alert: {e}", file=sys.stderr)


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
    """Return True if alert should be triggered now (after X/Y rule)."""
    state = load_alert_state()
    now = time.time()
    record = state.get(key, {"count": 0, "first": now})
    # Reset if outside time window
    if now - record["first"] > ALERT_REPEAT_WINDOW_MIN * 60:
        record = {"count": 0, "first": now}
    record["count"] += 1
    state[key] = record
    save_alert_state(state)
    return record["count"] >= ALERT_REPEAT_COUNT


# ---------------- DETECTION ----------------

def detect_anomalies(results):
    """Return list of alert strings based on status and power rules."""
    alerts = []
    for r in results:
        st, st_txt = r["status"], status_text(r["status"])
        pac, vdc, idc = r["pac_W"], r["vdc_V"], r["idc_A"]

        if st not in (2, 4):
            alerts.append(f"{r['id']}: Abnormal status ({st_txt})")

        if vdc is not None and idc is not None:
            if abs(idc) <= ZERO_CURRENT_EPS and vdc < SAFE_DC_VOLT_MAX:
                alerts.append(f"{r['id']}: SafeDC/open-DC suspected (Vdc={vdc:.1f}V, Idc≈0A, status={st_txt})")

        if pac is not None and pac < ABS_MIN_WATTS and st == 4:
            alerts.append(f"{r['id']}: Low production (PAC={pac:.0f}W < {ABS_MIN_WATTS:.0f}W, status={st_txt})")

    if PEER_COMPARE and len(results) >= 2:
        pacs = [r["pac_W"] for r in results if r["pac_W"] is not None]
        if pacs and max(pacs) >= PEER_MIN_WATTS:
            med = sorted(pacs)[len(pacs)//2]
            threshold = max(med * PEER_LOW_RATIO, ABS_MIN_WATTS)
            for r in results:
                pac = r["pac_W"]
                if pac is None:
                    continue
                if pac < threshold:
                    alerts.append(f"{r['id']}: Under peer median (PAC={pac:.0f}W < {threshold:.0f}W, peers median≈{med:.0f}W)")

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
    """Check inverter and optimizer reporting via SolarEdge cloud API."""
    if not ENABLE_SOLAREDGE_API:
        return []

    if not SOLAREDGE_API_KEY or not SOLAREDGE_SITE_ID:
        return ["SolarEdge API not configured (missing SOLAREDGE_SITE_ID or SOLAREDGE_API_KEY)"]

    base_url = "https://monitoringapi.solaredge.com"
    alerts = []
    now = dt.datetime.now(dt.timezone.utc)
    start = (now - dt.timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    end = now.strftime("%Y-%m-%d %H:%M:%S")

    def get_json(url):
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            alerts.append(f"SolarEdge API error: {e}")
            return None

    eq_url = f"{base_url}/equipment/{SOLAREDGE_SITE_ID}/list.json?api_key={SOLAREDGE_API_KEY}"
    data = get_json(eq_url)
    if not data:
        return alerts
    reporters = data.get("reporters", [])
    if not reporters:
        alerts.append("No equipment found via SolarEdge API.")
        return alerts

    for r in reporters:
        serial = r.get("serialNumber")
        name = r.get("name", serial)
        model = r.get("model", "")
        url = (f"{base_url}/equipment/{SOLAREDGE_SITE_ID}/{serial}/data.json"
               f"?startTime={start}&endTime={end}&api_key={SOLAREDGE_API_KEY}")
        d = get_json(url)
        if not d or "data" not in d:
            alerts.append(f"{model} ({serial}): No data available from SolarEdge API.")
            continue
        datapoints = d.get("data", [])
        if len(datapoints) == 0:
            alerts.append(f"{model} ({serial}): No production data in past hour.")
        else:
            total_wh = sum(x.get("value", 0) for x in datapoints if isinstance(x, dict))
            if total_wh == 0:
                alerts.append(f"{model} ({serial}): Optimizers reporting zero Wh (possible fault).")
    return alerts


# ---------------- MAIN ----------------

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

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

    if args.json:
        print(json.dumps(results, indent=2, default=str))

    if not any_success:
        print("ERROR: no inverter responded", file=sys.stderr)
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
            if should_alert(msg.split(":")[0]):
                confirmed.append(msg)
        if confirmed:
            msg = "\n".join(confirmed)
            print(f"ALERT:\n{msg}")
            pushover_notify("SolarEdge Monitor Alert", msg, priority=1)
            return 2
        else:
            if args.verbose:
                print("(Alerts suppressed until repeated)")
            return 0

    if args.verbose:
        print("OK: all inverters normal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
