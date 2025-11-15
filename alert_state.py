"""
Unified alert-state and daily-summary manager.

This replaces the module-level globals and functions that handled:
- alert repeat suppression
- inverter alert state tracking
- daily summary storage
- energy baseline storage
- shared state-file JSON persistence

The public API is designed so monitor_inverters.py and daily_summary.py
can use a *single* state manager instead of having separate JSON access
paths and caches.
"""

from __future__ import annotations

import json
import time
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, List
from threading import Lock
from utils import clean_serial, inv_display_from_parts


# ---------------------------------------------------------------------------
# Configuration wrapper
# ---------------------------------------------------------------------------

@dataclass
class AlertStateConfig:
    path: str
    repeat_count: int
    repeat_window_min: int


# ---------------------------------------------------------------------------
# AlertStateManager
# ---------------------------------------------------------------------------

class AlertStateManager:
    """
    Centralized manager for all persistent state stored in the JSON file.

    State file keys used:
        "alerts": {
            <key_text>: [ timestamps_of_recent_alerts ]
        }
        "inverter_states": {
            <serial>: { ... }   # whatever monitor_inverters currently writes
        }
        "daily_summary": { ... }    # from DailySummaryManager
        "energy_baseline": { ... }  # from DailySummaryManager

    Features:
        - Thread-safe file access (simple Lock around load/save)
        - Lazy loading with caching
        - Internal JSON dict reused across features
        - Unified code paths for daily summary and alert logic
    """

    def __init__(self, cfg: AlertStateConfig, debug: bool = False):
        self.cfg = cfg
        self.debug = debug

        self._path = cfg.path
        self._repeat_count = cfg.repeat_count
        self._repeat_window_min = cfg.repeat_window_min

        self._lock = Lock()
        self._state: Optional[Dict[str, Any]] = None
        self._file_mtime: Optional[float] = None

        # Ensure directory exists
        os.makedirs(os.path.dirname(self._path), exist_ok=True)

    # -------------------------------------------------------------------
    # Internal load & save helpers
    # -------------------------------------------------------------------

    def _load(self) -> Dict[str, Any]:
        """
        Loads JSON state file with caching.
        Reloads only if file mtime changes or cache is empty.
        """
        with self._lock:
            try:
                st = os.stat(self._path)
                mtime = st.st_mtime
            except FileNotFoundError:
                if self.debug:
                    print(f"[AlertState] No state file yet at {self._path}")
                self._state = {}
                self._file_mtime = None
                return self._state

            if self._state is not None and self._file_mtime == mtime:
                return self._state

            try:
                with open(self._path, "r") as f:
                    self._state = json.load(f)
                    if self.debug:
                        print(f"[AlertState] Loaded state from {self._path}")
            except Exception as e:
                if self.debug:
                    print(f"[AlertState] Failed to read {self._path}: {e}")
                self._state = {}

            self._file_mtime = mtime
            return self._state

    def _save(self) -> None:
        """
        Writes the internal JSON state back to disk.
        """
        with self._lock:
            if self._state is None:
                self._state = {}

            tmp_path = self._path + ".tmp"
            try:
                with open(tmp_path, "w") as f:
                    json.dump(self._state, f, indent=2, sort_keys=True)
                os.replace(tmp_path, self._path)

                self._file_mtime = os.stat(self._path).st_mtime

                if self.debug:
                    print(f"[AlertState] Saved state to {self._path}")

            except Exception as e:
                if self.debug:
                    print(f"[AlertState] Failed to save state: {e}")

    # -------------------------------------------------------------------
    # Alert repeat-check logic
    # -------------------------------------------------------------------

    def should_alert(self, key_text: str) -> bool:
        """
        Returns True if we should emit an alert for key_text.
        Applies repeat_count and repeat_window_min logic.
        """
        now = time.time()
        state = self._load()

        alerts = state.setdefault("alerts", {})
        timestamps: List[float] = alerts.get(key_text, [])

        # Filter timestamps within window
        window_sec = self._repeat_window_min * 60
        cutoff = now - window_sec
        recent = [ts for ts in timestamps if ts >= cutoff]

        if self.debug:
            print(f"[AlertState] For key '{key_text}': "
                  f"recent={len(recent)}, required={self._repeat_count}")

        # Should alert if we haven't met repeat_count occurrences yet
        return len(recent) < self._repeat_count

    def record_alert(self, key_text: str) -> None:
        """
        Record that an alert has been emitted. The result of should_alert()
        should almost always be paired with record_alert().
        """
        now = time.time()
        state = self._load()

        alerts = state.setdefault("alerts", {})
        timestamps = alerts.setdefault(key_text, [])

        timestamps.append(now)

        # Trim old entries
        window_sec = self._repeat_window_min * 60
        cutoff = now - window_sec
        alerts[key_text] = [ts for ts in timestamps if ts >= cutoff]

        self._save()

    # -------------------------------------------------------------------
    # Inverter alert-state updater (replaces update_inverter_states)
    # -------------------------------------------------------------------

    def update_inverter_states(self, results, notifier) -> List[str]:
        """
        Track inverter status transitions (Fault/Off → Producing).
        `results` are inverter dicts, not objects.
        Returns a list of alert messages emitted.
        """

        alerts_emitted: List[str] = []
        state = self._load()
        inv_state = state.setdefault("inverter_states", {})

        now = time.time()

        for r in results:
            # r is a dict from InverterReader
            serial = r.get("serial")
            model = r.get("model")
            status = r.get("status")

            if serial is None:
                # Should never happen, but avoid crashing
                if self.debug:
                    print(f"[AlertState] Missing serial in inverter record: {r}")
                continue

            key = clean_serial(serial)

            prev = inv_state.get(key, {})
            prev_status = prev.get("status")

            # Convert numeric status to human-readable text (matches your main script)
            from utils import status_human
            current_status_txt = status_human(status)
            prev_status_txt = prev_status

            # Transition: Fault/Off → Producing
            if prev_status_txt in ("Fault", "Off") and current_status_txt == "Producing":
                display = inv_display_from_parts(model, serial)
                msg = f"{display}: recovered from {prev_status_txt} → Producing"

                notifier.send("SolarEdge Recovery", msg, priority=0)
                alerts_emitted.append(msg)

            # Save updated state
            inv_state[key] = {
                "status": current_status_txt,
                "last_change": now,
            }

        self._save()
        return alerts_emitted


    # -------------------------------------------------------------------
    # Daily summary / energy baseline
    # -------------------------------------------------------------------

    def get_daily_state(self) -> Dict[str, Any]:
        """
        Returns the dict stored in 'daily_summary', creating if needed.
        """
        state = self._load()
        return state.setdefault("daily_summary", {})

    def set_daily_state(self, data: Dict[str, Any]) -> None:
        state = self._load()
        state["daily_summary"] = data
        self._save()

    def get_energy_baseline(self) -> Dict[str, Any]:
        """
        Return dict stored in 'energy_baseline'.
        """
        state = self._load()
        return state.setdefault("energy_baseline", {})

    def set_energy_baseline(self, data: Dict[str, Any]) -> None:
        state = self._load()
        state["energy_baseline"] = data
        self._save()

    # -------------------------------------------------------------------
    # Generic helpers (optional)
    # -------------------------------------------------------------------

    def get(self, key: str, default=None):
        state = self._load()
        return state.get(key, default)

    def set(self, key: str, value):
        state = self._load()
        state[key] = value
        self._save()
