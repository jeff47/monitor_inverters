# simulation.py

import re
from typing import Callable, List, Dict, Optional, Any

class SimulationEngine:
    """
    Encapsulate simulation behavior for inverter readings.

    Modes:
      - off      : no simulation
      - low      : 0W output on target inverter, others normal
      - fault    : FAULT status on target inverter, others normal
      - offline  : target inverter marked unreachable (error=True)

    All non-target, non-error inverters are set to a synthetic "normal"
    production profile so real-world noise doesn't interfere with tests.
    """

    def __init__(self, mode: str = "off", target_name: Optional[str] = None):
        # mode is one of: "off", "low", "fault", "offline"
        self.mode = mode or "off"
        self.target_name = target_name

    # ------------- basic helpers -------------

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    def _simulated_normal(self) -> Dict[str, Any]:
        # Status code 4 == Producing in your existing logic
        return {
            "status": 4,
            "pac_W": 5000.0,
            "vdc_V": 380.0,
            "idc_A": 13.0,
        }

    # ------------- daylight override -------------

    def override_daylight(self, is_day: bool) -> bool:
        """
        In simulation, always treat as day so anomaly checks run
        regardless of actual Astral window.
        """
        if not self.enabled:
            return is_day
        return True

    # ------------- main application -------------

    def apply_to_results(
        self,
        results: List[Dict[str, Any]],
        log: Callable[[str], None],
        verbose: bool = False,
    ) -> Optional[str]:
        """
        Apply simulation to the inverter results in place.

        Returns a human-readable description like 'fault on SE7600H'
        or None if no simulation is applied.
        """
        if not self.enabled or not results:
            return None

        # 1) pick target inverter
        target = self._select_target(results, log)

        # 2) log what we're doing
        target_label = target.get("name") or target.get("id") or target.get("serial") or "unknown"
        log(f"🔧 Simulating inverter '{target_label}' in mode '{self.mode}'")

        # 3) set all *other* non-error inverters to simulated normal
        for r in results:
            if r is target or r.get("error"):
                continue
            r.update(self._simulated_normal())
            if verbose:
                rid = r.get("id") or r.get("serial") or r.get("name") or "?"
                log(f"(Simulation) {rid} simulating normal output")

        # 4) apply mode-specific change to target
        rid_t = target.get("id") or target.get("serial") or target.get("name") or "?"

        if self.mode == "low":
            target["pac_W"] = 0.0
            target["status"] = 4  # still Producing, but 0W → low-production detection
            log(f"(Simulation) {rid_t} simulating 0W output")

        elif self.mode == "fault":
            target["status"] = 7  # your existing FAULT status code
            log(f"(Simulation) {rid_t} simulating FAULT state")

        elif self.mode == "offline":
            target["error"] = True
            log(f"(Simulation) {rid_t} simulating unreachable state")

        # Unknown mode: leave target unmodified beyond any earlier normalizing
        return f"{self.mode} on {target_label}"

    # ------------- alert code hook (currently a no-op) -------------

    def override_alert_state(self, exit_code: int) -> int:
        """
        For now we keep this as a pass-through, so exit codes behave
        exactly as the detector/alert logic decide. You can add
        policy here later (e.g., always force exit_code=2 in simulation).
        """
        return exit_code

    # ------------- internal: target selection -------------

    def _select_target(
        self,
        results: List[Dict[str, Any]],
        log: Callable[[str], None],
    ) -> Dict[str, Any]:
        # 1) If a --simulate-target name is given, try to match it
        if self.target_name:
            for r in results:
                if r.get("name") == self.target_name:
                    return r
            # fall back with a warning
            log(
                f"⚠️ No inverter found with name '{self.target_name}', "
                f"using first non-error inverter instead."
            )

        # 2) Prefer non-error inverters
        candidates = [r for r in results if not r.get("error")]
        if not candidates:
            candidates = results

        # 3) Among candidates, choose lowest kW model (as before)
        def extract_kw(inv: Dict[str, Any]) -> int:
            model = inv.get("model") or inv.get("name") or ""
            m = re.search(r"(\d{4,5})", model)
            return int(m.group(1)) if m else 99999

        return min(candidates, key=extract_kw)
