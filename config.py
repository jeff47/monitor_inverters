# config.py
from dataclasses import dataclass
import configparser
from pathlib import Path
from datetime import timedelta

@dataclass
class OptimizerExpectation:
    count: int
    tolerance: int | None = None

@dataclass
class SiteConfig:
    city_name: str
    lat: float
    lon: float
    tzname: str

@dataclass
class InverterConfig:
    name: str
    host: str
    port: int
    unit: int

@dataclass
class ThresholdConfig:
    morning_grace: timedelta
    evening_grace: timedelta
    abs_min_watts: float
    safe_dc_volt_max: float
    zero_current_eps: float
    peer_compare: bool
    peer_min_watts: float
    peer_low_ratio: float
    modbus_timeout: float
    modbus_retries: int

@dataclass
class AlertConfig:
    repeat_count: int
    repeat_window_min: int
    state_file: str
    healthchecks_url: str
    daily_enabled: bool
    daily_method: str
    daily_offset_min: int

@dataclass
class APIConfig:
    enabled: bool
    api_key: str
    site_id: str

@dataclass
class PushoverConfig:
    user_key: str | None
    api_token: str | None


class ConfigManager:
    """
    Loads and exposes all configuration from monitor_inverters.conf.
    Replaces all previous globals: CITY_NAME, LAT, ABS_MIN_WATTS, etc.
    """

    def __init__(self, path: str):
        self.path = Path(path)
        self._raw = self._load()

        self.site = self._load_site()
        self.inverters = self._load_inverters()
        self.thresholds = self._load_thresholds()
        self.alerts = self._load_alerts()
        self.api = self._load_api()
        self.pushover = self._load_pushover()
        self.optimizers = self._load_optimizers()

    @property
    def parser(self):
        """Expose the underlying raw ConfigParser for backward compatibility."""
        return self._raw

    # ---------------- internal loaders ----------------

    def _load(self):
        if not self.path.exists():
            raise FileNotFoundError(f"Config file not found: {self.path}")

        parser = configparser.ConfigParser(inline_comment_prefixes=(';', '#'))
        parser.optionxform = str  # preserve case
        parser.read(self.path)
        return parser

    def _load_site(self) -> SiteConfig:
        p = self._raw
        return SiteConfig(
            city_name=p.get("site", "CITY_NAME"),
            lat=p.getfloat("site", "LAT"),
            lon=p.getfloat("site", "LON"),
            tzname=p.get("site", "TZNAME"),
        )

    def _load_inverters(self) -> list[InverterConfig]:
        raw = self._raw.get("inverters", "INVERTERS")
        items = []
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            name, host, port, unit = [x.strip() for x in entry.split(":")]
            items.append(InverterConfig(name, host, int(port), int(unit)))
        return items

    def _load_thresholds(self) -> ThresholdConfig:
        p = self._raw
        return ThresholdConfig(
            morning_grace=timedelta(
                minutes=p.getfloat("thresholds", "MORNING_GRACE_MIN", fallback=20)
            ),
            evening_grace=timedelta(
                minutes=p.getfloat("thresholds", "EVENING_GRACE_MIN", fallback=10)
            ),
            abs_min_watts=p.getfloat("thresholds", "ABS_MIN_WATTS", fallback=150),
            safe_dc_volt_max=p.getfloat("thresholds", "SAFE_DC_VOLT_MAX", fallback=150),
            zero_current_eps=p.getfloat("thresholds", "ZERO_CURRENT_EPS", fallback=0.05),
            peer_compare=p.getboolean("thresholds", "PEER_COMPARE", fallback=True),
            peer_min_watts=p.getfloat("thresholds", "PEER_MIN_WATTS", fallback=600),
            peer_low_ratio=p.getfloat("thresholds", "PEER_LOW_RATIO", fallback=0.20),
            modbus_timeout=p.getfloat("thresholds", "MODBUS_TIMEOUT", fallback=1.0),
            modbus_retries=p.getint("thresholds", "MODBUS_RETRIES", fallback=3),
        )

    def _load_alerts(self) -> AlertConfig:
        p = self._raw
        return AlertConfig(
            repeat_count=p.getint("alerts", "ALERT_REPEAT_COUNT", fallback=3),
            repeat_window_min=p.getint("alerts", "ALERT_REPEAT_WINDOW_MIN", fallback=30),
            state_file=p.get("alerts", "ALERT_STATE_FILE", fallback="/tmp/inverter_alert_state.json"),
            healthchecks_url=p.get("alerts", "HEALTHCHECKS_URL", fallback=""),
            daily_enabled=p.getboolean("alerts", "DAILY_SUMMARY_ENABLED", fallback=True),
            daily_method=p.get("alerts", "DAILY_SUMMARY_METHOD", fallback="api").lower(),
            daily_offset_min=p.getint("alerts", "DAILY_SUMMARY_OFFSET_MIN", fallback=60),
        )

    def _load_api(self) -> APIConfig:
        p = self._raw
        return APIConfig(
            enabled=p.getboolean("solaredge_api", "ENABLE_SOLAREDGE_API", fallback=False),
            api_key=p.get("solaredge_api", "SOLAREDGE_API_KEY", fallback=None),
            site_id=p.get("solaredge_api", "SOLAREDGE_SITE_ID", fallback=None),
        )

    def _load_pushover(self) -> PushoverConfig:
        p = self._raw
        return PushoverConfig(
            user_key=p.get("pushover", "PUSHOVER_USER_KEY", fallback=None),
            api_token=p.get("pushover", "PUSHOVER_API_TOKEN", fallback=None),
        )

    def _load_optimizers(self) -> dict[str, OptimizerExpectation]:
        """
        Load optimizer expected-counts using the legacy simple format:

            [optimizers]
            SERIAL1 = 19
            SERIAL2 = 26

        Tolerance is not used; OptimizerExpectation.tolerance is always None.
        """
        p = self._raw
        optimizers: dict[str, OptimizerExpectation] = {}

        if not p.has_section("optimizers"):
            return optimizers

        for key, val in p.items("optimizers"):
            key = key.strip()
            try:
                count = int(str(val).strip())
            except ValueError:
                continue  # ignore malformed/invalid entries

            optimizers[key] = OptimizerExpectation(count=count, tolerance=None)

        return optimizers
