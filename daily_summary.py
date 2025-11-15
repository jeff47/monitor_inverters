"""
DailySummaryManager
-------------------
Handles daily energy summary logic for SolarEdge systems.

Responsibilities:
  - Fetch per-day site energy from cloud API
  - Fallback to Modbus lifetime-Wh-based calculation
  - Ensure summaries are sent once per day
  - Honor sunset + offset logic
  - Maintain state in alert_state through AlertStateManager
"""

from dataclasses import dataclass
from typing import Dict, Optional, List, Any
from datetime import datetime, timedelta
import requests
import pytz

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
        state,           # <-- AlertStateManager injected here
        debug: bool = False,
    ):
        self.cfg = cfg
        self.astral_loc = astral_loc
        self.status_func = status_func
        self.state = state          # AlertStateManager
        self.debug = debug

        self.session = requests.Session()

    # ---------------- TIME HELPERS ----------------

    def _now_local(self):
        tz = pytz.timezone(self.astral_loc.timezone)
        return datetime.now(tz)

    def _solar_window(self, dt_local):
        """
        Returns (sunrise, sunset). Offset is handled separately.
        """
        from astral.sun import sun
        s = sun(self.astral_loc.observer, date=dt_local.date(), tzinfo=dt_local.tzinfo)
        return s["sunrise"], s["sunset"]

    # ---------------- PUBLIC ENTRYPOINT ----------------

    def maybe_generate_summary(
        self,
        local_results: List[Dict[str, Any]],
        force: bool = False
    ) -> Optional[str]:
        """
        Returns a summary string if it is time to send the daily summary,
        or None if not.
        """
        if not self.cfg.enabled:
            return None

        dt_local = self._now_local()
        date_str = dt_local.strftime("%Y-%m-%d")

        # Load last-sent record from alert_state
        daily_state = self.state.get_daily_state()
        last_date = daily_state.get("date")
        already_sent = (last_date == date_str) and daily_state.get("sent")

        if self.debug:
            print(f"[DailySummary] date={date_str} already_sent={already_sent} force={force}")

        # If we've already sent today and not forcing → no summary
        if not force and already_sent:
            return None

        # If time is not right → skip
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
        lines = [f"{name}: {val:.2f} kWh" for name, val in sorted(per_inv.items())]
        lines.append(f"Total: {total:.2f} kWh")
        summary_text = "\n".join(lines)

        # Mark as sent in unified alert_state
        self.state.set_daily_state({"date": date_str, "sent": True})

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
        """Return {"site_total": kWh} or {"InverterX": val, ...} or None."""
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
        Compute per-inverter deltas using lifetime Wh (e_total_Wh).
        Uses unified alert_state instead of a module-level JSON file.
        """
        dt_local = self._now_local()
        date_str = dt_local.strftime("%Y-%m-%d")

        # Load per-day baseline from alert_state
        baseline = self.state.get_energy_baseline()

        totals = {}

        for r in local_results:
            disp = inv_display_from_parts(r.get("model"), r.get("serial"))
            ser = clean_serial(r.get("serial")) or disp.upper()
            key = f"{ser}:{date_str}"

            e_total_Wh = r.get("e_total_Wh")
            if e_total_Wh is None:
                continue

            first = baseline.get(key)
            if first is None:
                # first seen value of the day → initialize baseline
                baseline[key] = e_total_Wh
                delta_Wh = 0.0
            else:
                delta_Wh = max(0.0, e_total_Wh - float(first))

            totals[disp] = round(delta_Wh / 1000.0, 2)

        # Save updated baseline
        self.state.set_energy_baseline(baseline)

        return totals
