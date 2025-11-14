# daily_summary.py
"""
DailySummaryManager
-------------------
Handles daily energy summary logic for SolarEdge systems.

Responsibilities:
  - Fetch per-day site energy from cloud API
  - Fallback to Modbus lifetime-Wh-based calculation
  - Ensure summaries are sent once per day
  - Honor sunset + offset logic
  - Maintain state in alert_state.json
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import requests
import pytz
import json
import os

from utils import inv_display_from_parts, clean_serial


@dataclass
class DailySummaryConfig:
    enabled: bool
    method: str               # "api" or "modbus"
    offset_min: int
    api_key: Optional[str]
    site_id: Optional[str]


class DailySummaryManager:
    def __init__(
        self,
        cfg: DailySummaryConfig,
        astral_loc,
        status_func,
        state_file: str,
        debug: bool = False,
    ):
        self.cfg = cfg
        self.astral_loc = astral_loc
        self.status_func = status_func
        self.state_file = state_file
        self.debug = debug

        self.session = requests.Session()

    # ---------------- STATE FILE ----------------

    def _load_state(self) -> dict:
        try:
            with open(self.state_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_state(self, state: dict):
        try:
            with open(self.state_file, "w") as f:
                json.dump(state, f)
        except Exception as e:
            if self.debug:
                print(f"[DailySummary] Failed to save state: {e}")

    # ---------------- TIME HELPERS ----------------

    def _now_local(self):
        tz = pytz.timezone(self.astral_loc.timezone)
        return datetime.now(tz)

    def _solar_window(self, dt_local):
        """
        Returns (sunrise, sunset). Uses main script's MORNING_GRACE / EVENING_GRACE
        indirectly because sunset offset is applied later.
        """
        from astral.sun import sun
        s = sun(self.astral_loc.observer, date=dt_local.date(), tzinfo=dt_local.tzinfo)
        return s["sunrise"], s["sunset"]

    # ---------------- PUBLIC ENTRYPOINT ----------------

    def maybe_generate_summary(self, local_results: List[Dict[str, Any]], force: bool = False) -> Optional[str]:
        """
        Returns a summary string if it is time to send the daily summary.
        Returns None if no summary should be sent.
        """
        if not self.cfg.enabled:
            return None

        dt_local = self._now_local()
        date_str = dt_local.strftime("%Y-%m-%d")

        state = self._load_state()
        last = state.get("daily_summary", {})
        already_sent = last.get("date") == date_str and last.get("sent")

        if self.debug:
            print(f"[DailySummary] date={date_str} already_sent={already_sent} force={force}")

        if not force and already_sent:
            return None

        if not self._should_run_now(dt_local, force):
            return None

        # --- Build summary ---
        if self.cfg.method == "api":
            per_inv = self._fetch_api_summary()
        else:
            per_inv = None

        if per_inv is None:
            if self.debug:
                print("[DailySummary] API summary unavailable; using Modbus fallback")
            per_inv = self._compute_modbus_summary(local_results)

        if not per_inv:
            if self.debug:
                print("[DailySummary] No summary data; aborting")
            return None

        # Compose message text
        total = round(sum(v for v in per_inv.values()), 2)
        lines = [f"{n}: {v:.2f} kWh" for n, v in sorted(per_inv.items())]
        lines.append(f"Total: {total:.2f} kWh")
        summary_text = "\n".join(lines)

        # Mark sent
        state["daily_summary"] = {"date": date_str, "sent": True}
        self._save_state(state)

        return summary_text

    # ---------------- WHEN TO SEND ----------------

    def _should_run_now(self, dt_local, force: bool) -> bool:
        if force:
            return True

        sunrise, sunset = self._solar_window(dt_local)
        trigger_time = sunset + timedelta(minutes=self.cfg.offset_min)

        if self.debug:
            print(f"[DailySummary] now={dt_local}, trigger={trigger_time}")

        return dt_local >= trigger_time

    # ---------------- API SUMMARY ----------------

    def _fetch_api_summary(self) -> Optional[Dict[str, float]]:
        """Return {"site_total": kWh} or {"Inverter1": val, ...} or None."""
        if not (self.cfg.api_key and self.cfg.site_id):
            return None

        today = datetime.utcnow().strftime("%Y-%m-%d")
        params = {
            "timeUnit": "DAY",
            "startDate": today,
            "endDate": today,
            "api_key": self.cfg.api_key,
        }

        url = f"https://monitoringapi.solaredge.com/site/{self.cfg.site_id}/energy"
        try:
            r = self.session.get(url, params=params, timeout=20)
            if r.status_code != 200:
                if self.debug:
                    print(f"[DailySummary] API non-200: {r.status_code}")
                return None
            j = r.json()
            energy = j.get("energy", {})
            values = energy.get("values", [])
            if not values:
                return None
            val = values[0].get("value")
            if val is None:
                return None
            total_kWh = round(float(val) / 1000.0, 2)
            return {"site_total": total_kWh}
        except Exception as e:
            if self.debug:
                print(f"[DailySummary] API exception: {e}")
            return None

    # ---------------- MODBUS SUMMARY ----------------

    def _compute_modbus_summary(self, local_results: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Compute per-inverter deltas based on lifetime Wh (e_total_Wh).
        """
        dt_local = self._now_local()
        date_str = dt_local.strftime("%Y-%m-%d")

        state = self._load_state()
        energy_state = state.setdefault("energy", {})

        totals = {}

        for r in local_results:
            disp = inv_display_from_parts(r.get("model"), r.get("serial"))
            ser = clean_serial(r.get("serial")) or disp.upper()
            key = f"{ser}:{date_str}"

            e_total_Wh = r.get("e_total_Wh")
            if e_total_Wh is None:
                continue

            baseline = energy_state.get(key)
            if baseline is None:
                # first sample of the day
                energy_state[key] = e_total_Wh
                delta_Wh = 0.0
            else:
                delta_Wh = max(0.0, e_total_Wh - float(baseline))

            totals[disp] = round(delta_Wh / 1000.0, 2)

        self._save_state(state)
        return totals
