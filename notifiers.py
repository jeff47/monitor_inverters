# notifiers.py
"""
Notifier + Healthchecks unified interface (Stage 4.5)
"""

import urllib.request
import urllib.parse
import urllib.error
import sys
from datetime import datetime

class Notifier:
    """
    Unified wrapper for Pushover notifications. Future expansion could
    include email, SMS, etc. For now it replaces the old pushover_notify().
    """

    def __init__(self, user_key: str | None, api_token: str | None):
        self.user_key = (user_key or "").strip()
        self.api_token = (api_token or "").strip()

        # If both empty → disabled
        if not self.user_key and not self.api_token:
            self.enabled = False
        elif bool(self.user_key) != bool(self.api_token):
            raise RuntimeError(
                "Configuration error: Both PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN "
                "must be set for Pushover notifications."
            )
        else:
            self.enabled = True

    def send(self, title: str, message: str, priority: int = 0):
        """Send notification if enabled."""
        if not self.enabled:
            return

        data = urllib.parse.urlencode({
            "token": self.api_token,
            "user": self.user_key,
            "title": title,
            "message": message,
            "priority": str(priority),
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                "https://api.pushover.net/1/messages.json", data=data
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as e:
            print(f"⚠️ Failed to send Pushover alert: {e}", file=sys.stderr)

    def send_test(self, log):
            """
            Send a simple test message to verify Pushover configuration.
            """
            log("🔔 Sending test notification via Pushover...")
            msg = (
                "Test message from SolarEdge inverter monitor\n"
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            self.send("SolarEdge Monitor Test", msg, priority=0)
            log("✅ Test notification sent (check your device).")

class Healthchecks:
    """
    Simple wrapper for Healthchecks.io ping URLs.
    """

    def __init__(self, base_url: str | None):
        self.url = (base_url or "").strip()

    def _hit(self, suffix: str = "", message: str = ""):
        if not self.url:
            return
        url = self.url.rstrip("/") + suffix
        parsed = list(urllib.parse.urlparse(url))
        query = {}
        if message:
            query["msg"] = message[:200]
        parsed[4] = urllib.parse.urlencode(query)
        full_url = urllib.parse.urlunparse(parsed)
        try:
            urllib.request.urlopen(full_url, timeout=5)
        except urllib.error.URLError as e:
            print(f"⚠️ Failed to ping Healthchecks.io: {e}", file=sys.stderr)

    def ok(self, message: str = ""):
        self._hit("", message)

    def fail(self, message: str = ""):
        self._hit("/fail", message)

    def send_test_ok(self, log):
        """
        Send a test OK ping to Healthchecks.io.
        """
        if not self.url:
            log("⚠️ No Healthchecks.io URL configured; skipping Healthchecks OK test.")
            return

        log("🔧 Sending Healthchecks.io TEST-OK ping...")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"TEST OK ping from SolarEdge Monitor at {ts}"

        self._hit("", message)
        log("✅ TEST-OK Healthchecks ping sent.")

    def send_test_fail(self, log):
        """
        Send a test FAIL ping to Healthchecks.io.
        """
        if not self.url:
            log("⚠️ No Healthchecks.io URL configured; skipping Healthchecks FAIL test.")
            return

        log("🔧 Sending Healthchecks.io TEST-FAIL ping...")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"TEST FAIL ping from SolarEdge Monitor at {ts}"

        self._hit("/fail", message)
        log("❌ TEST-FAIL Healthchecks ping sent.")
