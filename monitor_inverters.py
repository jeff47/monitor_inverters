#!/usr/bin/env python3
"""
SolarEdge inverter monitor via Modbus TCP

Features
--------
- Uses both Astral (sunrise/sunset) and inverter status (Sleeping) to skip night checks.
- Warns on:
    * Low or zero production during daylight
    * SafeDC/open-DC (low Vdc + zero Idc)
    * Status not 2 (Sleeping) or 4 (Producing)
    * Peer imbalance between multiple inverters
- Exits 0 for OK/night, 2 for alerts, 1 for fatal errors.
"""

import os
import sys
import json
import socket
from datetime import datetime, timedelta

import pytz
from astral import LocationInfo
from astral.sun import sun
import solaredge_modbus


# ---------------------- CONFIG ----------------------

INVERTERS = [
    {"name": "SE10000H", "host": "192.168.3.50", "port": 1502, "unit": 1},
    {"name": "SE7600H", "host": "192.168.3.51", "port": 1502, "unit": 1},
]

LAT = float(os.getenv("LAT", "39.0716"))
LON = float(os.getenv("LON", "-77.1496"))
TZNAME = os.getenv("TZ", "America/New_York")
CITY_NAME = os.getenv("CITY_NAME", "Rockville, MD")

MORNING_GRACE = timedelta(minutes=20)
EVENING_GRACE = timedelta(minutes=10)

ABS_MIN_WATTS = 150.0
SAFE_DC_VOLT_MAX = 150.0
ZERO_CURRENT_EPS = 0.05

PEER_COMPARE = True
PEER_MIN_WATTS = 600.0
PEER_LOW_RATIO = 0.20

DEFAULT_VERBOSE = False
MODBUS_TIMEOUT = 2
MODBUS_UNIT = 1

# ----------------------------------------------------


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
    mapping = getattr(solaredge_modbus, "INVERTER_STATUS_MAP", None)
    if isinstance(mapping, dict):
        text = mapping.get(code)
    elif isinstance(mapping, (list, tuple)) and isinstance(code, int):
        text = mapping[code] if 0 <= code < len(mapping) else None
    else:
        text = None

    # Fallback explicit mapping (always available)
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
    return text or explicit.get(code, f"Unknown({code})")


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

        # --- 1. Faulty status code ---
        if st not in (2, 4):
            alerts.append(f"{r['id']}: Abnormal status ({st_txt})")

        # --- 2. SafeDC / open string heuristic ---
        if vdc is not None and idc is not None:
            if abs(idc) <= ZERO_CURRENT_EPS and vdc < SAFE_DC_VOLT_MAX:
                alerts.append(
                    f"{r['id']}: SafeDC/open-DC suspected (Vdc={vdc:.1f}V, Idc≈0A, status={st_txt})"
                )

        # --- 3. Low power during daylight ---
        if pac is not None and pac < ABS_MIN_WATTS and st == 4:
            alerts.append(
                f"{r['id']}: Low production (PAC={pac:.0f}W < {ABS_MIN_WATTS:.0f}W, status={st_txt})"
            )

    # --- 4. Peer comparison ---
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

    # Merge duplicates
    merged = {}
    for msg in alerts:
        key = msg.split(":")[0]
        merged.setdefault(key, []).append(msg)
    output = []
    for k, msgs in merged.items():
        if len(msgs) == 1:
            output.append(msgs[0])
        else:
            output.append(f"{k}: " + " | ".join(m.split(": ", 1)[1] for m in msgs))
    return output


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--verbose", action="store_true", default=DEFAULT_VERBOSE)
    args = ap.parse_args()

    dt = now_local()
    is_day, sunrise, sunset = solar_window(dt)

    if args.verbose:
        print(f"[time] now={dt.strftime('%Y-%m-%d %H:%M:%S %Z')}  day={is_day}  "
              f"sunrise+grace={sunrise.strftime('%H:%M')}  sunset-grace={sunset.strftime('%H:%M')}")

    results, any_success = [], False
    for inv in INVERTERS:
        try:
            r = read_inverter(inv, verbose=args.verbose)
            results.append(r)
            any_success = True
            if args.verbose:
                st_txt = status_text(r["status"])
                print(f"[{r['id']}] PAC={r['pac_W']:.0f}W  Vdc={r['vdc_V']:.1f}V  "
                      f"Idc={r['idc_A']:.2f}A  status={st_txt}")
        except Exception:
            results.append({"id": inv["name"], "error": True})

    if args.json:
        print(json.dumps(results, indent=2, default=str))

    if not any_success:
        print("ERROR: no inverter responded", file=sys.stderr)
        return 1

    # Night skip: if ALL inverters report Sleeping (2) OR Astral night
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
        for a in alerts:
            print(f"ALERT: {a}")
        return 2

    if args.verbose:
        print("OK: all inverters normal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
