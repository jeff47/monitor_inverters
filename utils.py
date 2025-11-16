# utils.py
import re
from datetime import datetime, timedelta
from astral.sun import sun
import pytz

class DaylightPolicy:
    """
    Encapsulates all daylight and night-window logic:
      - Astral sunrise/sunset calculation
      - Morning/evening grace periods
      - Sleeping-inverter detection
      - Simulation daylight override
      - Skip-Modbus decision logic
      - Low-light detection near sunrise/sunset
    """

    def __init__(self, astral_loc, thresholds, tzname, log, simulation_engine):
        self.astral_loc = astral_loc
        self.thresholds = thresholds
        self.tz = pytz.timezone(tzname)
        self.log = log
        self.simulation_engine = simulation_engine

    # ---------------------------
    # Time and daylight calculation
    # ---------------------------

    def now_local(self):
        """Return current datetime with site's timezone applied."""
        return datetime.now(self.tz)

    def compute_daylight_window(self, dt_local):
        """
        Compute raw Astral sunrise/sunset, apply morning/evening grace periods,
        and determine whether dt_local is within the adjusted daylight window.
        Returns: (is_day, sunrise_adj, sunset_adj)
        """
        s = sun(self.astral_loc.observer, date=dt_local.date(), tzinfo=self.tz)

        sunrise = s["sunrise"] + self.thresholds.morning_grace
        sunset = s["sunset"] - self.thresholds.evening_grace

        is_day = sunrise <= dt_local <= sunset
        return is_day, sunrise, sunset

    def _is_near_edges(self, dt_local, sunrise, sunset):
        """
        True if within a configurable window of sunrise or sunset.
        Used to suppress low-PAC alerts when both inverters are low.
        """
        # Default window: 45 minutes unless configured otherwise
        win = getattr(self.thresholds, "low_light_window", timedelta(minutes=45))

        # Allow an integer to mean "minutes"
        if isinstance(win, int):
            win = timedelta(minutes=win)

        return (
            sunrise <= dt_local <= sunrise + win or
            sunset - win <= dt_local <= sunset
        )

    # ---------------------------
    # Decision logic for Modbus checks
    # ---------------------------

    def should_skip_modbus(self, results, is_day, verbose, quiet):
        """
        Determine whether modbus anomaly checks should be skipped.

        Skip if:
            - Astral reports night (is_day == False)
            - All responding inverters report Sleeping (status == 2)
        """
        all_sleeping = all(
            r.get("status") == 2 for r in results if not r.get("error")
        )

        if all_sleeping or not is_day:
            if verbose and not quiet:
                reason = "all Sleeping" if all_sleeping else "Astral night"
                self.log(f"Night window ({reason}): skipping Modbus anomaly checks.")
            return True

        return False

    def evaluate(self, dt_local, results=None, verbose=False, quiet=False):
        is_day, sunrise, sunset = self.compute_daylight_window(dt_local)

        # Apply SimulationEngine daylight override once
        if self.simulation_engine:
            is_day = self.simulation_engine.override_daylight(is_day)

        # NEW: near sunrise/sunset detection
        near_edges = self._is_near_edges(dt_local, sunrise, sunset)

        if results is not None:
            skip_modbus = self.should_skip_modbus(
                results,
                is_day,
                verbose,
                quiet,
            )
        else:
            skip_modbus = False

        return {
            "dt_local": dt_local,
            "is_day": is_day,
            "sunrise": sunrise,
            "sunset": sunset,
            "near_edges": near_edges,
            "skip_modbus": skip_modbus,
        }


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

def key_for_alert_message(msg: str) -> str:
    """Stable key for dedupe / repeat-suppression."""
    ser = extract_serial_from_text(msg)
    if ser:
        return ser
    return (msg.split(":", 1)[0].strip().upper()) if ":" in msg else msg.strip().upper()

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
