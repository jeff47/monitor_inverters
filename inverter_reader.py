# inverter_reader.py

from dataclasses import dataclass
import socket
from datetime import datetime
from typing import Any, Dict
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import solaredge_modbus
from config import InverterConfig
from utils import status_human

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

    def read_one(self, inv: InverterConfig) -> dict:
        """
        Read a single inverter using Modbus TCP and return a normalized snapshot dict.
        Compatible with Jeff47 solaredge_modbus fork (lowercase keys).
        """
        from solaredge_modbus import Inverter as SEInverter

        host = inv.host
        port = inv.port
        unit = inv.unit

        last_exc = None

        # --- Retry loop ---
        for attempt in range(self.settings.retries):
            try:
                dev = SEInverter(host=host, port=port, unit=unit, timeout=self.settings.timeout)
                try:
                    dev.connect()
                    values = dev.read_all()
                    break
                finally:
                    try:
                        dev.close()
                    except Exception:
                        pass
            except Exception as e:
                last_exc = e
                time.sleep(0.05)
        else:
            raise RuntimeError(f"Modbus read failed for {inv.name}: {last_exc}")

        # --- Scaling helper ---
        def _scaled(values, key, scale_key):
            v = values.get(key)
            s = values.get(scale_key, 0)
            if v is None:
                return None
            try:
                return v * (10 ** s)
            except Exception:
                return None

        # --- Extract real keys from Jeff-modbus ---
        model = values.get("c_model", "Unknown")
        serial = values.get("c_serialnumber", "Unknown")  # the unique device ID
        raw_status = values.get("status")  # numeric code
        status = raw_status                # keep internal numeric
        vendor_status = values.get("vendor_status")

        pac = _scaled(values, "power_ac", "power_ac_scale")
        vdc = _scaled(values, "voltage_dc", "voltage_dc_scale")
        idc = _scaled(values, "current_dc", "current_dc_scale")
        temp = _scaled(values, "temperature", "temperature_scale")
        freq = _scaled(values, "frequency", "frequency_scale")
        e_total = _scaled(values, "energy_total", "energy_total_scale")

        # --- Normalized dictionary returned to main ---
        return {
            "name": inv.name,
            "id": serial,                  # physical identity of the inverter
            "model": model,
            "serial": serial,
            "status": status,
            "vendor_status": vendor_status,
            "pac_W": pac,
            "vdc_V": vdc,
            "idc_A": idc,
            "temp_C": temp,
            "freq_Hz": freq,
            "e_total_Wh": e_total,
            "raw": values,
        }

    def read_all(self, inverters: list[InverterConfig], verbose=False, quiet=False):
        results = []
        any_success = False

        with ThreadPoolExecutor(max_workers=min(8, len(inverters) or 1)) as ex:
            futures = {ex.submit(self.read_one, inv): inv for inv in inverters}

            for future in as_completed(futures):
                inv = futures[future]
                try:
                    r = future.result()
                except Exception as e:
                    r = {"id": inv.name, "name": inv.name, "error": True}
                    print(f"[{inv.name}] Threaded read exception: {e}", file=sys.stderr)
                else:
                    if not r.get("error"):
                        any_success = True

                results.append(r)

                if verbose and not quiet and not r.get("error"):
                    pac = r.get("pac_W")
                    vdc = r.get("vdc_V")
                    idc = r.get("idc_A")
                    status = r.get("status")

                    pac_s = f"{pac:.0f}W" if isinstance(pac, (int,float)) else "N/A"
                    vdc_s = f"{vdc:.1f}V" if isinstance(vdc,(int,float)) else "N/A"
                    idc_s = f"{idc:.2f}A" if isinstance(idc,(int,float)) else "N/A"
                    status_s = status_human(status)

                    print(f"[{r['id']}] (modbus) PAC={pac_s} Vdc={vdc_s} Idc={idc_s} status={status_s}")

        return results, any_success

    def _simulated(self, inv_cfg: InverterConfig) -> dict:
        serial = f"SIM-{inv_cfg.name}"
        return {
            "name": inv_cfg.name,
            "id": serial,
            "model": "SIMULATED",
            "serial": serial,
            "status": 4,          # Producing
            "vendor_status": 0,
            "pac_W": 1234.0,
            "vdc_V": 380.0,
            "idc_A": 4.1,
            "temp_C": 45.2,
            "freq_Hz": 60.01,
            "e_total_Wh": 999_999,
            "raw": {},
        }

