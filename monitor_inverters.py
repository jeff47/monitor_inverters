#!/usr/bin/env python3
"""
SolarEdge inverter monitor via Modbus TCP + optional Cloud API
--------------------------------------------------------------
- Reads config from monitor_inverters.conf (INI format)
- Detects low/zero production, SafeDC conditions, and abnormal statuses
- Uses Astral for daylight logic (cached)
- Sends Pushover notifications on alerts
- Optionally validates inverter/optimizer reporting via SolarEdge Cloud API
- Supports repeated-detection filtering (X detections over Y minutes)
- Supports --simulate mode to safely test alerts and suppression
- Supports --quiet for cron-friendly output
"""

import sys
import argparse
from argparse import RawTextHelpFormatter
from pathlib import Path
import importlib.util

# Custom classes
from config import ConfigManager
from orchestrator import Orchestrator


# ---------------- CLI ARGUMENTS ----------------
def build_arg_parser():
    examples = """\
Examples:
  Normal run (verbose):
    python3 monitor_inverters.py --verbose

  Output raw JSON for one run:
    python3 monitor_inverters.py --json

  Simulate issues:
    python3 monitor_inverters.py --simulate low --simulate-target SE7600H

  Cron-friendly (quiet, pings Healthchecks):
    */5 * * * * /usr/bin/python3 /opt/solaredge/monitor_inverters.py --quiet
"""
    exit_codes = """\
Exit Codes:
  0  All OK or alert suppressed (within repeat window)
  1  No inverter responded (communication failure)
  2  Confirmed alert triggered (notification sent)
"""
    ap = argparse.ArgumentParser(
        description=(
            "Monitor SolarEdge inverters via Modbus + optional Cloud API.\n"
            "Sends alerts only after repeated detections (X over Y)."
        ),
        formatter_class=RawTextHelpFormatter,
        epilog=f"{exit_codes}\n{examples}"
    )
    ap.add_argument("--json", action="store_true", help="print full inverter readings as JSON and exit")
    ap.add_argument("--verbose", action="store_true", help="emit detailed logs during checks")
    ap.add_argument("--quiet", action="store_true", help="suppress non-error output (cron-friendly)")
    ap.add_argument("--simulate", choices=["off", "low", "fault", "offline"], default="off",
                    help="simulate a failure mode on an inverter (default: off)")
    ap.add_argument("--simulate-target", metavar="NAME",
                    help="apply simulation to inverter by configured name (from [inverters] INVERTERS)")
    ap.add_argument("--test-pushover", action="store_true",
                    help="send a test notification to verify Pushover configuration")
    ap.add_argument("--force-summary", action="store_true",
                    help="force immediate daily summary (bypass sunset/time guard)")
    ap.add_argument("--debug", action="store_true", help="enable extra debug output (API and Modbus details)")
    ap.add_argument("--config", "-c", metavar="PATH", help="path to monitor_inverters.conf (overrides default)")
    ap.add_argument("--test-healthchecks-ok",
                action="store_true",
                help="send a test OK ping to verify Healthchecks.io")
    ap.add_argument("--test-healthchecks-fail",
                    action="store_true",
                    help="send a test FAIL ping to verify Healthchecks.io")

    return ap


# ---------------- MAIN ----------------
def main():
    global cfg

    # ------------------------------
    # CLI
    # ------------------------------
    ap = build_arg_parser()
    args = ap.parse_args()

    # ------------------------------
    # Load configuration
    # ------------------------------
    cfg = ConfigManager(args.config or "monitor_inverters.conf")

    # ------------------------------
    # Load development solaredge_modbus
    # ------------------------------
    mod_path = Path("/home/jeff/projects/personal/solaredge_modbus/src/solaredge_modbus/__init__.py")
    spec = importlib.util.spec_from_file_location("solaredge_modbus", mod_path)
    solaredge_modbus = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(solaredge_modbus)
    sys.modules["solaredge_modbus"] = solaredge_modbus

    # ------------------------------
    # Instantiate orchestrator
    # ------------------------------
    orch = Orchestrator(args, cfg, solaredge_modbus)

    # ------------------------------
    # Test modes stay in main()
    # ------------------------------
    if args.test_pushover:
        orch.notifier.send_test(orch._log)
        return 0

    if args.test_healthchecks_ok:
        orch.health.send_test_ok(orch._log)
        return 0

    if args.test_healthchecks_fail:
        orch.health.send_test_fail(orch._log)
        return 0

    # ------------------------------
    # JSON output mode
    # (optional to move into orchestrator later)
    # ------------------------------
    if args.json:
        # Let orchestrator run so it performs Modbus + simulation,
        # but bypass alerting/summary afterwards.
        return orch.run()

    # ------------------------------
    # Normal monitoring cycle
    # ------------------------------
    return orch.run()



# ---------------- ENTRY POINT ----------------
if __name__ == "__main__":
    sys.exit(main())
