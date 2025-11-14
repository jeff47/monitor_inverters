# solaredge_api_checker.py
"""
SolarEdgeAPIChecker
-------------------
Centralizes all SolarEdge Monitoring API validation logic.

Primary responsibilities:
  - Fetch cloud-side inverter & optimizer reporting
  - Compare expected optimizer counts (if configured)
  - Detect inverters that appear offline / faulted in cloud data
  - Detect mismatches between Modbus-local reads and cloud status
  - Return alert strings which the main script can merge normally

Daily summary calculations (energy totals) are intentionally *not*
included here — Stage 4.4 will move that into a separate class.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import requests
import time

from utils import clean_serial, inv_display_from_parts

API_BASE = "https://monitoringapi.solaredge.com"


@dataclass
class APICheckerConfig:
    api_key: Optional[str]
    site_id: Optional[str]
    optimizer_expected_total: Optional[int]
    optimizer_expected_per_inv: Dict[str, int]
    debug: bool = False


class SolarEdgeAPIChecker:
    def __init__(
        self,
        api_key: Optional[str],
        site_id: Optional[str],
        optimizer_expected_total: Optional[int],
        optimizer_expected_per_inv: Dict[str, int],
        debug: bool = False,
    ):
        self.cfg = APICheckerConfig(
            api_key=api_key,
            site_id=site_id,
            optimizer_expected_total=optimizer_expected_total,
            optimizer_expected_per_inv=optimizer_expected_per_inv or {},
            debug=debug,
        )
        self.session = requests.Session()

    # ------------------------------------------------------------------
    # Internal: Request helper
    # ------------------------------------------------------------------
    def _get(self, path: str, params: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Internal GET wrapper. Returns parsed JSON on success, else None."""
        if not self.cfg.api_key or not self.cfg.site_id:
            return None

        url = f"{API_BASE}{path}"
        params = params.copy()
        params["api_key"] = self.cfg.api_key

        try:
            r = self.session.get(url, params=params, timeout=20)
            if r.status_code != 200:
                if self.cfg.debug:
                    print(f"[API] Non-200 for {path}: {r.status_code}")
                return None
            return r.json()
        except Exception as e:
            if self.cfg.debug:
                print(f"[API] Exception for {path}: {e}")
            return None

    # ------------------------------------------------------------------
    # Internal: Fetch cloud inverter list
    # ------------------------------------------------------------------
    def _fetch_inverters_cloud(self) -> Optional[List[Dict[str, Any]]]:
        """
        Robust inventory fetcher.
        Supports SolarEdge variations:
        - inventory/inverters
        - Inventory/inverters (YOUR SITE)
        - empty or missing inverters list
        - error JSON formats
        - HTML masquerading as 200 OK
        Returns a list (possibly empty) or None on hard failure.
        """
        j = self._get(f"/site/{self.cfg.site_id}/inventory", params={})
        if j is None:
            return None

        # HTML or non-JSON responses:
        if isinstance(j, str):
            if self.cfg.debug:
                print("[API] HTML or string instead of JSON")
            return None

        # API-level error object
        if "errors" in j:
            if self.cfg.debug:
                print(f"[API] Error: {j['errors']}")
            return None

        # SolarEdge inconsistently uses Inventory vs inventory
        inv = j.get("inventory") or j.get("Inventory") or {}

        # Inverter list may appear under several key forms
        inverters = (
            inv.get("inverters")
            or inv.get("Inverters")
            or inv.get("inverter")
            or []
        )

        if self.cfg.debug:
            print(f"[API] Inventory fetched: {len(inverters)} inverters.")

        return inverters

    # ------------------------------------------------------------------
    # Internal: Fetch optimizer count (if supported by cloud)
    # ------------------------------------------------------------------
    def _fetch_optimizer_counts(self) -> Optional[Dict[str, int]]:
        """
        Return mapping {serial -> optimizer_count} or None if unavailable.
        """
        j = self._get(f"/site/{self.cfg.site_id}/inventory", params={})
        if not j:
            return None

        inv = j.get("inventory") or j.get("Inventory") or {}
        inverters = inv.get("inverters") or inv.get("Inverters") or []

        out = {}
        for inv in inverters:
            ser = clean_serial(inv.get("serialNumber") or inv.get("SN") or "")
            if not ser:
                continue

            # Some sites provide connectedOptimizers instead of "optimizers" list
            if "optimizers" in inv and isinstance(inv["optimizers"], list):
                out[ser] = len(inv["optimizers"])
            elif "connectedOptimizers" in inv:
                out[ser] = int(inv["connectedOptimizers"])
        return out or None


    # ------------------------------------------------------------------
    # Public API: perform full check
    # ------------------------------------------------------------------
    def check(self, local_results: List[Dict[str, Any]]) -> List[str]:
        """
        Main entrypoint. Accepts the local Modbus readings and returns
        a list of alert messages based on cloud-side checks.
        """
        if not (self.cfg.api_key and self.cfg.site_id):
            # API disabled: no alerts, but clean behavior
            return []

        alerts = []

        # 1. Fetch cloud-side inverter list
        cloud_invs = self._fetch_inverters_cloud()
        if cloud_invs is None:
            if self.cfg.debug:
                alerts.append("Cloud API: failed to fetch inventory data.")
            # If cloud unreachable, we choose NOT to make this fatal.
            return alerts

        # --------------------------------------------------------------
        # Build lookup tables
        # --------------------------------------------------------------
        local_by_serial = {}
        for r in local_results:
            ser = clean_serial(r.get("serial"))
            if ser:
                local_by_serial[ser] = r

        cloud_by_serial = {}
        for c in cloud_invs:
            ser = clean_serial(c.get("serialNumber"))
            if ser:
                cloud_by_serial[ser] = c

        # --------------------------------------------------------------
        # 2. Check optimizer counts if expectations exist
        # --------------------------------------------------------------
        exp_total = self.cfg.optimizer_expected_total
        exp_per_inv = self.cfg.optimizer_expected_per_inv

        if exp_total or exp_per_inv:
            opt_counts = self._fetch_optimizer_counts()
        else:
            opt_counts = None

        # Per-inverter expected count
        if opt_counts:
            for ser, expected in exp_per_inv.items():
                actual = opt_counts.get(ser)
                if actual is not None and actual != expected:
                    alerts.append(
                        f"[{ser}] Cloud: optimizer count mismatch "
                        f"(expected {expected}, got {actual})"
                    )

            # Total expected optimizer count
            if exp_total is not None:
                total_actual = sum(opt_counts.values())
                if total_actual != exp_total:
                    alerts.append(
                        f"Cloud: total optimizer count mismatch "
                        f"(expected {exp_total}, got {total_actual})"
                    )

        # --------------------------------------------------------------
        # 3. Check cloud-side inverter status vs local status
        # --------------------------------------------------------------
        for ser, cloud_inv in cloud_by_serial.items():
            cloud_status = (
                cloud_inv.get("status", {}).get("status")
                if isinstance(cloud_inv.get("status"), dict)
                else None
            )
            cloud_name = cloud_inv.get("name") or ser

            local = local_by_serial.get(ser)
            if local:
                local_status = local.get("status")
                display = inv_display_from_parts(local.get("model"), ser)
            else:
                display = f"[{ser}]"
                local_status = None

            # detect mismatches
            if cloud_status is not None and local_status is not None:
                if cloud_status != local_status:
                    alerts.append(
                        f"{display}: Cloud/local status mismatch "
                        f"(cloud={cloud_status}, local={local_status})"
                    )

        # --------------------------------------------------------------
        # 4. Detect inverters missing from cloud
        # --------------------------------------------------------------
        for ser, local in local_by_serial.items():
            if ser not in cloud_by_serial:
                display = inv_display_from_parts(local.get("model"), ser)
                alerts.append(f"{display}: missing from Cloud API inventory")

        return alerts
