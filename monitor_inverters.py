#!/usr/bin/env python3
"""
SolarEdge inverter monitor via Modbus TCP
-----------------------------------------
- Reads config from monitor_inverters.conf (key=value format)
- Detects low/zero production, SafeDC conditions, and abnormal statuses
- Uses Astral for daylight logic
- Sends Pushover notifications on alerts
"""

import os
import sys
import json
import socket
from datetime import datetime, timedelta
import urllib.request
import urllib.parse

import pytz
from astral import LocationInfo
from astral.sun import sun
import solaredge_modbus


# ---------------- CONFIG LOADING ----------------

def load_config(path="monitor_inverters.conf"):
    """Read key=value pairs into os.environ (non-overwriting)."""
    if not os.path.exists(path):
        print(f"⚠️ Config file not found: {path}", file=sys.stderr)
        return

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, val = [x.strip() for x in line.split("=", 1)]
            os.environ.setdefault(key, val)


load_config()  # load config before reading env vars


# ---------------- CONFIG VALUES ----------------

def get_bool(var, default=False):
    val = os.getenv(var, str(default))
    return str(val).lower() in ("1", "true", "yes", "on")

CITY_NAME = os.getenv("CITY_NAME", "Local")
LAT = float(os.getenv("LAT", "40.7128"))
LON = float(os.getenv("LON", "-74.0060"))
TZNAME = os.getenv("TZNAME", "America/New_York")

MORNING_GRACE = timedelta(minutes=float(os.getenv("MORNING_GRACE_MIN", 20)))
EVENING_GRACE = timedelta(minutes=float(os.getenv("EVENING_GRACE_MIN", 10)))

ABS_MIN_WATTS = float(os.getenv("ABS_MIN_WATTS", 150))
SAFE_DC_VOLT_MAX = float(os.getenv("SAFE_DC_VOLT_MAX", 150))
ZERO_CURRENT_EPS = float(os.getenv("ZERO_CURRENT_EPS", 0.05))

PEER_COMPARE = get_bool("PEER_COMPARE", True)
PEER_MIN_WATTS = float(os.getenv("PEER_MIN_WATTS", 600))
PEER_LOW_RATIO = float(os.getenv("PEER_LOW_RATIO", 0.20))

DEFAULT_VERBOSE = False
MODBUS_TIMEOUT = 2
MODBUS_UNIT = 1

# Parse inverter list: "name:ip:port:unit"
INVERTERS = []
inv_list = os.getenv("INVERTERS", "")
for part in inv_list.split(","):
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


# ---------------- UTILITIES ----------------

def pushover_notify(title: str, message: str, priority: int = 0):
    """Send a Pushover notification if credentials are configured."""
    user = os.getenv("PUSHOVER_USER_KEY")
    token = os.getenv("PUSHOVER_API_TOKEN")
    if not user or not token:
        return  # silently skip if not configured

    data = urllib.parse.urlencode({
        "token": token,
        "user": user,
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
    if code is None:
        return "No status (unavailable)"
    return explicit.get(code, f"Unknown({code})")


def read_inverter(inv, verbose=False):
    """Read key metrics from one inverter."""
    try:
        socket.gethostbyname(inv["host"])
        inverter = solaredge_modbus.Inverter(
            host=inv["host"],
            port=inv.get("port", 1502),
            timeout=MODBUS_TIMEOUT,
            unit=inv.get("unit", MODBUS_UNIT),
        )
        v = inverter.read_all()
    except Exception as e:
        if verbose:
            print(f"[{inv['name']}] ERROR reading inverter: {e}", file=sys.stderr)
        raise

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


def detect_anomalies(results):
    """Return list of alert strings based on status and power rules."""
    alerts = []
    for r in results:
        st, st_txt = r["status"], status_text(r["status"])
        pac, vdc, idc = r["pac_W"], r["vdc_V"], r["idc_A"]

        if st in (1, 2) or st is None:
            continue

        if st not in (2, 4):
            alerts.append(f"{r['id']}: Abnormal status ({st_txt})")

        if vdc is not None and idc is not None:
            if abs(idc) <= ZERO_CURRENT_EPS and vdc < SAFE_DC_VOLT_MAX:
                alerts.append(
                    f"{r['id']}: SafeDC/open-DC suspected (Vdc={vdc:.1f}V, Idc≈0A, status={st_txt})"
                )

        if pac is not None and pac < ABS_MIN_WATTS and st == 4:
            alerts.append(
                f"{r['id']}: Low production (PAC={pac:.0f}W < {ABS_MIN_WATTS:.0f}W, status={st_txt})"
            )

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
                    alerts.append(
                        f"{r['id']}: Under peer median (PAC={pac:.0f}W < {threshold:.0f}W, peers median≈{med:.0f}W)"
                    )

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


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--verbose", action="store_true", default=DEFAULT_VERBOSE)
    args = ap.parse_args()

    dt = now_local()
    is_day, sunrise, sunset = solar_window(dt)

    if args.verbose:
        print(f"[time] now={dt.strftime('%Y-%m-%d %H:%M:%S %Z')} day={is_day} "
              f"sunrise+grace={sunrise.strftime('%H:%M')} sunset-grace={sunset.strftime('%H:%M')}")

    results, any_success = [], False
    for inv in INVERTERS:
        try:
            r = read_inverter(inv, verbose=args.verbose)
            results.append(r)
            any_success = True
            if args.verbose:
                print(f"[{r['id']}] PAC={r['pac_W']:.0f}W Vdc={r['vdc_V']:.1f}V "
                      f"Idc={r['idc_A']:.2f}A status={status_text(r['status'])}")
        except Exception:
            results.append({"id": inv["name"], "error": True})

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

    if alerts:
        msg = "\n".join(alerts)
        print(f"ALERT:\n{msg}")
        pushover_notify("SolarEdge Monitor Alert", msg, priority=1)
        return 2

    if args.verbose:
        print("OK: all inverters normal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
