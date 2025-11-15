# utils.py
import re

SERIAL_RE = re.compile(r"([0-9A-Fa-f]{6,})")

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


def extract_serial_from_text(s: str) -> str:
    if not s:
        return ""
    m = re.search(r"\[([0-9A-Fa-f]{6,})\]", s)
    if m:
        return m.group(1).upper()
    m2 = SERIAL_RE.search(s)
    return m2.group(1).upper() if m2 else ""

# -----------------------------
# Status decoding helpers
# -----------------------------

SUNSPEC_STATUS_MAP = {
    1: "Off",
    2: "Sleeping",
    3: "Waking Up",
    4: "Producing",
    5: "Producing",
    6: "Power Reduction",
    7: "Shutdown",
    8: "Fault",
    9: "Maintenance",
}

def status_human(code):
    """Convert numeric SunSpec status to human-readable text."""
    if code is None:
        return "Unknown"
    return SUNSPEC_STATUS_MAP.get(code, f"Unknown({code})")
