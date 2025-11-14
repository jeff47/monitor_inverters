# anomaly_detector.py
from dataclasses import dataclass
from typing import List, Dict, Any, Callable, Optional

from utils import (
    clean_serial,
    inv_display_from_parts,
    extract_serial_from_text,
)

@dataclass
class DetectionSettings:
    abs_min_watts: float
    safe_dc_volt_max: float
    zero_current_eps: float
    peer_compare: bool
    peer_min_watts: float
    peer_low_ratio: float


class AnomalyDetector:
    def __init__(
        self,
        settings: DetectionSettings,
        status_formatter: Optional[Callable[[int], str]] = None,
    ):
        self.s = settings
        self.status_text = status_formatter  # optional function: int → string

    # ---------------- ENTRYPOINT ----------------
    def detect(self, results: List[Dict[str, Any]], is_day: bool) -> List[str]:
        alerts = []

        if is_day:
            alerts.extend(self._detect_abnormal_status(results))
            alerts.extend(self._detect_safedc(results))
            alerts.extend(self._detect_low_production(results))

            if self.s.peer_compare and len(results) >= 2:
                alerts.extend(self._detect_peer_compare(results))

        return self._merge_duplicates(alerts)

    # ---------------- RULES ----------------
    def _detect_abnormal_status(self, results):
        out = []
        for r in results:
            st = r.get("status")

            # Human-readable string if formatter provided
            if self.status_text:
                st_txt = self.status_text(st)
            else:
                st_txt = st

            if st not in (2, 4):  # Sleeping or Producing
                out.append(f"{r['id']}: Abnormal status ({st_txt})")

        return out

    def _detect_safedc(self, results):
        out = []
        for r in results:
            vdc = r.get("vdc_V")
            idc = r.get("idc_A")
            st = r.get("status")

            if vdc is None or idc is None:
                continue

            if abs(idc) <= self.s.zero_current_eps and vdc < self.s.safe_dc_volt_max:
                out.append(
                    f"{r['id']}: SafeDC/open-DC suspected "
                    f"(Vdc={vdc:.1f}V, Idc≈0A, status={st})"
                )
        return out

    def _detect_low_production(self, results):
        out = []
        for r in results:
            pac = r.get("pac_W")
            st = r.get("status")
            if pac is not None and pac < self.s.abs_min_watts and st == 4:
                out.append(
                    f"{r['id']}: Low production "
                    f"(PAC={pac:.0f}W < {self.s.abs_min_watts:.0f}W)"
                )
        return out

    def _detect_peer_compare(self, results):
        out = []
        pacs = [r.get("pac_W") for r in results if r.get("pac_W") is not None]
        if not pacs:
            return out

        max_pac = max(pacs)
        if max_pac < self.s.peer_min_watts:
            return out

        median = sorted(pacs)[len(pacs) // 2]
        threshold = max(median * self.s.peer_low_ratio, self.s.abs_min_watts)

        for r in results:
            pac = r.get("pac_W")
            if pac is None:
                continue
            if pac < threshold:
                out.append(
                    f"{r['id']}: Under peer median "
                    f"(PAC={pac:.0f}W < {threshold:.0f}W, median≈{median:.0f}W)"
                )
        return out

    # ---------------- DEDUPLICATION ----------------
    def _merge_duplicates(self, alerts: List[str]) -> List[str]:
        merged = {}
        for msg in alerts:
            key = extract_serial_from_text(msg) or msg.split(":",1)[0].strip().upper()
            merged.setdefault(key, []).append(msg)

        out = []
        for k, msgs in merged.items():
            if len(msgs) == 1:
                out.append(msgs[0])
            else:
                head = msgs[0].split(":", 1)[0]
                parts = [m.split(": ", 1)[1] for m in msgs]
                out.append(f"{head}: " + " | ".join(parts))
        return out
