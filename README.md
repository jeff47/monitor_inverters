# SolarEdge Inverter Monitor

# This project is no longer being developed.  I suggest you look at https://github.com/jeff47/SolaredgeMonitor instead.


Monitor one or more **SolarEdge** inverters over **Modbus TCP** and optionally via the **SolarEdge Cloud API**.  This was tested using SolarEdge HD-Wave inverters connected via ethernet.

This tool detects low or zero production, SafeDC conditions, and inverter faults.
It’s daylight-aware, supports repeated-detection suppression, and can send **Pushover** alerts.

## Contents
- [Features](#features)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Testing Modbus connectivity](#testing-modbus-connectivity)
- [Running the Monitor](#running-the-monitor)
- [Full Usage](#full-usage)
  - [Exit Codes](#exit-codes)
- [Simulation Examples](#simulation-examples)
- [Files](#files)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Quick Reference](#quick-reference)

## Features

- ✅ Polls SolarEdge inverters using **Modbus TCP**
- ✅ Optional integration with **SolarEdge Cloud API**
- ✅ Detects:
  - Low or zero AC power while “Producing”
  - Fault / abnormal inverter statuses
  - SafeDC (low voltage + no current)
  - Production imbalance between inverters
- ✅ Astral-based daylight logic (skips checks at night)
- ✅ Pushover notifications
- ✅ “X detections over Y minutes” suppression logic
- ✅ Config-driven via `monitor_inverters.conf`
- ✅ Simulation mode for safe testing

## Requirements

### Python 3.10 or newer

Install dependencies:

`bash python3 -m pip install -r requirements.txt`


Or manually:

`python3 -m pip install -U pymodbus==3.6.8 astral pytz requests solaredge_modbus`

A [patched solaredge_modbus](https://github.com/jeff47/solaredge_modbus) version may be necessary if required for Python 3.12.


## Configuration

Create a configuration file named:  `monitor_inverters.conf`


Example:
```
[site]
CITY_NAME = Washington, DC
LAT = 38.8977
LON = -77.0365
TZNAME = America/New_York

[inverters]
# Format: name:ip:port:unit
INVERTERS = SE10000H:192.168.1.50:1502:1, SE7600H:192.168.1.51:1502:1

[thresholds]
MORNING_GRACE_MIN = 20
EVENING_GRACE_MIN = 10
ABS_MIN_WATTS = 150
SAFE_DC_VOLT_MAX = 150
ZERO_CURRENT_EPS = 0.05
PEER_COMPARE = True
PEER_MIN_WATTS = 600
PEER_LOW_RATIO = 0.20
MODBUS_TIMEOUT = 0.3
MODBUS_RETRIES = 1

[alerts]
ALERT_REPEAT_COUNT = 3
ALERT_REPEAT_WINDOW_MIN = 30
ALERT_STATE_FILE = /tmp/inverter_alert_state.json
HEALTHCHECKS_URL = https://hc-ping.com/XXXXXX/solaredge

[pushover]
PUSHOVER_USER_KEY = XXXXXX
PUSHOVER_API_TOKEN = YYYYYY

[solaredge_api]
ENABLE_SOLAREDGE_API = True
SOLAREDGE_API_KEY = ZZZZZZ
SOLAREDGE_SITE_ID = 123456
```

### Key Configuration Options
| Section             | Key                       | Description                                            | Allowed Values                                                    |
| ------------------- | ------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------- |
| **[site]**          | `CITY_NAME`               | Descriptive city name used for Astral sunrise/sunset   | Any string (e.g. `Washington, DC`)                                 |
|           | `LAT`                     | Latitude in decimal degrees                            | Float (e.g. `38.8977`)                                            |
|           | `LON`                     | Longitude in decimal degrees                           | Float (e.g. `-77.0365`)                                           |
|          | `TZNAME`                  | Timezone name (IANA format)                            | e.g. `America/New_York`, `Europe/London`                          |
| **[inverters]**     | `INVERTERS`               | Comma-separated list of inverter definitions           | Format: `name:ip:port:unit` (e.g. `SE10000H:192.168.1.50:1502:1`) |
| **[thresholds]**    | `MORNING_GRACE_MIN`       | Minutes after sunrise to start monitoring              | Integer or float minutes (e.g. `20`)                              |
|     | `EVENING_GRACE_MIN`       | Minutes before sunset to stop monitoring               | Integer or float minutes (e.g. `10`)                              |
|     | `ABS_MIN_WATTS`           | Minimum AC power expected while producing              | Integer or float watts (e.g. `150`)                               |
|     | `SAFE_DC_VOLT_MAX`        | Voltage below which SafeDC/open-circuit is suspected   | Float volts (e.g. `150`)                                          |
|     | `ZERO_CURRENT_EPS`        | Tolerance for “zero” DC current detection              | Float (e.g. `0.05`)                                               |
|     | `PEER_COMPARE`            | Enable cross-inverter power comparison                 | `True` / `False`                                                  |
|     | `PEER_MIN_WATTS`          | Minimum peer power before comparison applies           | Integer or float watts (e.g. `600`)                               |
|     | `PEER_LOW_RATIO`          | Ratio below peer median to trigger alert               | Float between `0.0` and `1.0` (e.g. `0.2`)                        |
| | `MODBUS_TIMEOUT` | Modbus to timeout, in seconds.  Defaults to `1.0`, try reducing to `0.3` or `0.5` for faster performance | Float(e.g. `0.3`) |
| | `MODBUS_RETRIES` | Number of times to retry.  Defaults to `3` | Integer (e.g. `1`) |
| **[alerts]**        | `ALERT_REPEAT_COUNT`      | Number of consecutive detections required before alert | Integer (e.g. `3`)                                                |
|        | `ALERT_REPEAT_WINDOW_MIN` | Time window for repeated detections                    | Integer minutes (e.g. `30`)                                       |
|         | `ALERT_STATE_FILE`        | JSON file storing persistent alert state               | Valid file path (e.g. `/tmp/inverter_alert_state.json`)           |
| | `HEALTHCHECKS_URL` | URL to Healthchecks | Valid URL (leave blank to disable)
| **[pushover]**      | `PUSHOVER_USER_KEY`       | User key from your Pushover account                    | 30–40 character alphanumeric string (leave blank to disable)                              |
|       | `PUSHOVER_API_TOKEN`      | API token from your Pushover app                       | 30–40 character alphanumeric string                               |
| **[solaredge_api]** | `ENABLE_SOLAREDGE_API`    | Enable optional SolarEdge Cloud API checks             | `True` / `False`                                                  |
|  | `SOLAREDGE_API_KEY`       | SolarEdge Cloud API key                                | 32-character alphanumeric                                         |
|  | `SOLAREDGE_SITE_ID`       | SolarEdge site ID                                      | Integer (e.g. `123456`)                                          |


## Testing Modbus Connectivity

Before running the monitor, ensure each inverter’s Modbus TCP port (typically 1502) is reachable.

```
Test with netcat (nc):
  nc -vz 192.168.1.50 1502
Expected result:
  Connection to 192.168.1.50 1502 port [tcp/*] succeeded!
```

If you see “Connection refused” or timeout:
- Verify Modbus TCP is enabled in inverter settings.
- Check VLAN/firewall rules.
- Confirm correct IP addresses.

## Running the Monitor
Verbose run (for initial setup):

`python3 monitor_inverters.py --verbose`

Cron mode (silent, only alerts):

`*/5 * * * * /usr/bin/python3 /path/to/monitor_inverters.py`

Output detailed JSON:

`python3 monitor_inverters.py --json`

## Full Usage

The monitor_inverters.py script supports several command-line options to control behavior, logging, simulation, and testing.

| Option	| Arguments	| Description |
| ------  | --------- | ----------- |
|-h, --help| N/A |	Show built-in help text, including exit codes and examples.|
| --json	| N/A	|Output full inverter readings (raw JSON), then exit. Useful for debugging, data collection, or integration with other tools.|
| --verbose	| N/A |	Show detailed logs for every inverter (PAC, VDC, IDC, status, etc.). Recommended when running interactively.|
| --quiet	| N/A |	Suppress all non-error output. Ideal for cron or systemd timers. Errors and alerts still appear on stderr. |
| --simulate	|{off, low, fault, offline}| Simulate inverter behavior without hardware impact.
| | | low → PAC=0 W while still “Producing” |
| | | fault → Reports inverter in FAULT state |
| | | offline → Pretend inverter unreachable |
| | | off → Normal operation (default) |
| --simulate-target	| NAME | Select which inverter to apply simulation to (default: smallest model inverter). All other inverters simulate normal output. |
| --test-pushover	| N/A |	Send a test Pushover notification to verify credentials and network reachability. |
| --quiet	| N/A |	Suppress informational logs, useful for cron or unattended operation.|
| --help	| N/A |	Display this help and exit.|

## Exit Codes
| Code | Meaning |
| ---- | ------- |
| 0	| All OK or alert suppressed (below repeat threshold). |
| 1	| No inverter responded — communication or connection failure.|
| 2	| Confirmed alert triggered — notification sent.|

### Simulation & Testing

Use simulation mode to safely test alert behavior without touching hardware.

Mode Description:
- `--simulate low`	Forces first inverter to 0 W output (low production)
- `--simulate fault`	Forces inverter status = “Fault”
- `--simulate offline`	Simulates inverter being unreachable
- `--simulate off`	Default; no simulation

Example:

`python3 monitor_inverters.py --simulate low --verbose`

If `ALERT_REPEAT_COUNT = 3`, you must see the same issue 3 times within the `ALERT_REPEAT_WINDOW_MIN` before an alert is sent.

### Daylight Awareness

Checks run only during daylight hours, defined by:

- sunrise + MORNING_GRACE_MIN
→
sunset  - EVENING_GRACE_MIN

If all inverters are sleeping (status 2) or it’s dark per Astral, the script skips checks.


### SolarEdge Cloud API (optional)

If enabled, verifies via the cloud that:

- All inverters are reporting data
- All optimizers are producing energy

Example output:

Cloud API Alerts:
  - SE10000H-US000BEI4: No production data in past hour.
  - SE7600H-US000BNI4: Optimizers reporting zero Wh (possible fault).

### 📱 Pushover Notifications

To enable notifications:

1. Install the Pushover app (Android/iOS)
2. Create an app token at https://pushover.net/apps
3. Add your PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN to [pushover]

Example message:

`SolarEdge Monitor Alert
SE10000H-US000BEI4: Low production (PAC=0W < 150W, status=Producing)`

## Simulation Examples
### 1. Low production test
`python3 monitor_inverters.py --simulate low --verbose`

### 2. Fault status test
`python3 monitor_inverters.py --simulate fault`

### 3. Offline test
`python3 monitor_inverters.py --simulate offline`

## Files
| File	| Purpose |
|---|---|
| monitor_inverters.py	| Main monitoring script |
| monitor_inverters.conf| Configuration (INI format) |
| /tmp/inverter_alert_state.json |	Persistent alert suppression state |

## Troubleshooting
| Symptom	| Cause / Fix |
| ------- | ----------- |
| Modbus read failed	| Check TCP 1502 reachability |
| 403 Client Error	| Use a site admin API key (Not user/account key!) |
| No sunrise/sunset	| Verify LAT, LON, TZNAME |
| No Pushover alert	| Check tokens and internet access |

## License

MIT License © 2025
You are free to modify and redistribute under the same license.

## Quick Reference
| Command | Purpose |
| ------- | ------- |
| python3 monitor_inverters.py --help	| Show usage and examples |
| python3 monitor_inverters.py --verbose	| Verbose check |
| python3 monitor_inverters.py --simulate low	| Simulate 0 W output |
| python3 monitor_inverters.py --json	| Dump inverter readings |
| nc -vz 192.168.1.50 1502	| Test Modbus TCP connection |
