# solaredge_api_checker.py

import datetime as dt
from datetime import timedelta
from typing import List, Dict, Optional
import requests

from utils import clean_serial, model_base, inv_display_from_parts


class SolarEdgeAPIChecker:
    """
    Performs all SolarEdge cloud API checks:
    - inverter telemetry
    - optimizer connectivity
    - expected-per-inverter optimizer counts
    - expected-total-optimizer count
    """

    def __init__(
        self,
        api_key: str,
        site_id: str,
        optimizer_expected_total: Optional[int],
        optimizer_expected_per_inv: Dict[str, int],
        debug: bool = False,
    ):
        self.api_key = api_key
        self.site_id = site_id
        self.expected_total = optimizer_expected_total
        self.expected_per_inv = optimizer_expected_per_inv  # normalized serials
        self.debug = debug

        self.base_url = "https://monitoringapi.solaredge.com"
        self.session = requests.Session()

    # --------------------------------------------------------------
    def check(self, modbus_results: List[Dict]) -> List[str]:
        if not self.api_key or not self.site_id:
            return ["SolarEdge API not configured (missing SOLAREDGE_SITE_ID or SOLAREDGE_API_KEY)"]

        alerts = []

        # map serial → model base for display
        serial_to_model = {}
        for r in (m for m in modbus_results if not m.get("error")):
            serial_to_model[clean_serial(r.get("serial"))] = model_base(r.get("model"))

        # A) Equipment list
        eq_list = self._fetch_equipment_list()
        if isinstance(eq_list, str):
            return [eq_list]

        # B) Telemetry
        alerts.extend(
            self._check_inverter_telemetry(eq_list, serial_to_model)
        )

        # C) Optimizer inventory
        inv_json = self._fetch_inventory()
        if isinstance(inv_json, str):
            alerts.append(inv_json)
            return alerts

        # D/E) Expected vs actual optimizer counts
        alerts.extend(
            self._check_optimizers(inv_json, serial_to_model)
        )

        return alerts

    # --------------------------------------------------------------
    def _fetch_equipment_list(self):
        try:
            url = f"{self.base_url}/equipment/{self.site_id}/list?api_key={self.api_key}"
            resp = self.session.get(url, timeout=15)
            resp.raise_for_status()
            eq_list = resp.json().get("reporters", {}).get("list", [])
            if self.debug:
                print(f"[DEBUG] (api) Equipment list: {len(eq_list)} devices retrieved")
            return eq_list
        except Exception as e:
            return f"SolarEdge API equipment list error: {e}"

    # --------------------------------------------------------------
    def _check_inverter_telemetry(self, eq_list, serial_to_model):
        alerts = []
        now = dt.datetime.now()
        start = now - timedelta(hours=1)

        for e in eq_list:
            serial = clean_serial(e.get("serialNumber"))
            if not serial:
                continue

            mb = serial_to_model.get(serial, "")
            display = inv_display_from_parts(mb, serial)

            params = {
                "startTime": start.strftime("%Y-%m-%d %H:%M:%S"),
                "endTime":   now.strftime("%Y-%m-%d %H:%M:%S"),
                "api_key":   self.api_key,
            }

            try:
                url = f"{self.base_url}/equipment/{self.site_id}/{serial}/data"
                r = self.session.get(url, params=params, timeout=20)
                r.raise_for_status()
                tele = r.json().get("data", {}).get("telemetries", [])
                if not tele:
                    alerts.append(f"{display}: no telemetry data in past hour")
                    if self.debug:
                        print(f"[DEBUG] (api) {display}: no telemetry in {start:%H:%M}–{now:%H:%M}")
                    continue

                latest = tele[-1]
                pac = latest.get("totalActivePower", 0.0)
                vdc = latest.get("dcVoltage")
                mode = latest.get("inverterMode", "UNKNOWN")
                ts   = latest.get("date")

                if self.debug:
                    print(f"[DEBUG] (api) {display}: {pac:.1f}W, {vdc}V, mode={mode}, time={ts}")

                if mode in ("FAULT", "OFF"):
                    alerts.append(f"{display}: inverterMode={mode} (API time {ts})")
                elif pac == 0 and vdc and vdc > 50:
                    alerts.append(f"{display}: 0 W output with DC present (API time {ts})")

            except Exception as ex:
                alerts.append(f"{display}: failed to read inverter data ({ex})")
                if self.debug:
                    print(f"[DEBUG] (api) {display}: telemetry request failed → {ex}")

        return alerts

    # --------------------------------------------------------------
    def _fetch_inventory(self):
        try:
            url = f"{self.base_url}/site/{self.site_id}/inventory?api_key={self.api_key}"
            resp = self.session.get(url, timeout=15)
            resp.raise_for_status()
            inv_json = resp.json()
            if self.debug:
                print(f"[DEBUG] (api) Inventory query OK, keys: {list(inv_json.keys())}")
            return inv_json
        except Exception as e:
            return f"Inventory read error: {e}"

    # --------------------------------------------------------------
    def _check_optimizers(self, inv_json, serial_to_model):
        alerts = []
        inverters = inv_json.get("Inventory", {}).get("inverters", []) or []
        per_serial_counts = {}
        total_connected = 0

        for inv in inverters:
            serial_raw = inv.get("serialNumber") or inv.get("SN") or ""
            serial = clean_serial(serial_raw)
            mb = serial_to_model.get(serial, "")
            display = inv_display_from_parts(mb, serial)

            try:
                count = int(inv.get("connectedOptimizers") or 0)
            except Exception:
                count = 0

            per_serial_counts[serial] = count
            total_connected += count

            if self.debug:
                print(f"[DEBUG] (api) {display}: {count} optimizers connected")

        if self.debug:
            print(f"[DEBUG] (api) Total optimizers connected: {total_connected}")

        # Total expected
        if isinstance(self.expected_total, int) and total_connected < self.expected_total:
            alerts.append(
                f"Optimizers: {total_connected} connected < expected {self.expected_total} (total)"
            )

        # Per-inverter expected
        for exp_serial, expected in self.expected_per_inv.items():
            s = clean_serial(exp_serial)
            actual = per_serial_counts.get(s)
            display = inv_display_from_parts(serial_to_model.get(s, ""), s)

            if actual is None:
                if total_connected == 0:
                    alerts.append(f"{display}: optimizer count unavailable")
            elif actual < expected:
                alerts.append(f"{display}: {actual} optimizers < expected {expected}")

        return alerts
