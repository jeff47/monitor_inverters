# inverter_reader.py

from dataclasses import dataclass
import socket
from datetime import datetime
from typing import Any, Dict

import solaredge_modbus


# ---------------- IDENTITY HELPERS ----------------

def clean_serial(s: str) -> str:
    if not s:
        return ""
    return s.split("-")[0].upper().strip()

def model_base(model: str) -> str:
    if not model:
        return ""
    return model.split("-", 1)[0].strip()

def inv_display_from_parts(model: str, serial: str) -> str:
    mb = model_base(model)
    ser = clean_serial(serial)
    if mb and ser:
        return f"{mb} [{ser}]"
    if ser:
        return f"[{ser}]"
    return mb or "UNKNOWN"


# ---------------- READER CLASS ----------------

@dataclass
class ReaderSettings:
    timeout: float
    retries: int


class InverterReader:
    """
    Responsible for:
      - Creating Modbus sessions
      - Reading all values
      - Applying scaling
      - Producing normalized dicts identical to previous Stage 1 output
    """

    def __init__(self, settings: ReaderSettings):
        self.settings = settings

    def _scaled(self, values: Dict[str, Any], name: str):
        raw = values.get(name)
        if raw is None:
            return None
        scale = 10 ** values.get(f"{name}_scale", 0)
        try:
            return float(raw) * float(scale)
        except Exception:
            return None

    def read_one(self, inv_cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        inv_cfg keys:
          - name
          - host
          - port
          - unit
        Returns exactly the same dict format used before Stage 2.
        """
        try:
            socket.gethostbyname(inv_cfg["host"])
            inverter = solaredge_modbus.Inverter(
                host=inv_cfg["host"],
                port=inv_cfg["port"],
                timeout=self.settings.timeout,
                retries=self.settings.retries,
                unit=inv_cfg["unit"],
            )
            v = inverter.read_all()
        except Exception:
            return {
                "name": inv_cfg["name"],
                "id": inv_cfg["name"],
                "model": None,
                "serial": None,
                "error": True,
            }

        model = v.get("c_model") or v.get("model")
        serial = v.get("c_serialnumber") or v.get("serialnumber")
        id_str = inv_display_from_parts(model, serial)

        return {
            "name": inv_cfg["name"],     # configured nickname
            "id": id_str,                # visible identity
            "model": model,
            "serial": clean_serial(serial),
            "status": v.get("status"),
            "vendor_status": v.get("vendor_status"),
            "pac_W": self._scaled(v, "power_ac"),
            "vdc_V": self._scaled(v, "voltage_dc"),
            "idc_A": self._scaled(v, "current_dc"),
            "temp_C": self._scaled(v, "temperature"),
            "freq_Hz": self._scaled(v, "frequency"),
            "e_total_Wh": self._scaled(v, "energy_total") or self._scaled(v, "total_energy"),
            "raw": v,
        }
