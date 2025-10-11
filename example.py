#!/usr/bin/env python3
import argparse
import json
import solaredge_modbus


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("host", type=str, help="Modbus TCP address")
    argparser.add_argument("port", type=int, help="Modbus TCP port")
    argparser.add_argument("--timeout", type=int, default=1, help="Connection timeout")
    argparser.add_argument("--unit", type=int, default=1, help="Modbus device address")
    argparser.add_argument("--json", action="store_true", default=False, help="Output as JSON")
    args = argparser.parse_args()

    inverter = solaredge_modbus.Inverter(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        unit=args.unit,
    )

    # Read inverter and attached meters/batteries
    values = inverter.read_all()
    meters = inverter.meters()
    batteries = inverter.batteries()
    values["meters"] = {}
    values["batteries"] = {}

    for meter, params in meters.items():
        values["meters"][meter] = params.read_all()

    for battery, params in batteries.items():
        values["batteries"][battery] = params.read_all()

    # JSON output mode
    if args.json:
        print(json.dumps(values, indent=4))
        exit(0)

    # ---- Text output mode ----
    print(f"{inverter}:\n")
    print("Registers:")

    # Show available keys
    print(f"\tAvailable keys: {list(values.keys())}\n")

    # Helper for safe printing
    def show_field(label, key, fmt="{:.2f}", scale_key=None, unit_key=None):
        if key in values:
            val = values[key]
            if scale_key and scale_key in values:
                val *= 10 ** values[scale_key]
            try:
                text_val = fmt.format(val)
            except Exception:
                text_val = str(val)
            unit = ""
            if unit_key and unit_key in inverter.registers:
                unit = inverter.registers[unit_key][6]
            print(f"\t{label}: {text_val}{unit}")

    # Try to print identification info
    printed_header = False
    for lbl, key in [
        ("Manufacturer", "c_manufacturer"),
        ("Model", "c_model"),
        ("Type ID", "c_sunspec_did"),
        ("Version", "c_version"),
        ("Serial", "c_serialnumber"),
    ]:
        if key in values:
            printed_header = True
            if key == "c_sunspec_did":
                did = str(values[key])
                label = solaredge_modbus.C_SUNSPEC_DID_MAP.get(did, f"Unknown ({did})")
                print(f"\tType: {label}")
            else:
                print(f"\t{lbl}: {values[key]}")

    # Alternate field names (non-“c_”)
    for lbl, alt in [
        ("Manufacturer", "manufacturer"),
        ("Model", "model"),
        ("Version", "version"),
        ("Serial", "serialnumber"),
    ]:
        if alt in values and not printed_header:
            print(f"\t{lbl}: {values[alt]}")

    # Core metrics
    show_field("Temperature", "temperature", "{:.2f}", "temperature_scale", "temperature")
    show_field("Current", "current", "{:.2f}", "current_scale", "current")

    # Detect inverter type
    three_phase = (
        "c_sunspec_did" in values
        and values["c_sunspec_did"] == solaredge_modbus.sunspecDID.THREE_PHASE_INVERTER.value
    )

    if three_phase:
        for ph in (1, 2, 3):
            show_field(f"Phase {ph} Current", f"l{ph}_current", "{:.2f}", "current_scale", f"l{ph}_current")
            show_field(f"Phase {ph} Voltage", f"l{ph}_voltage", "{:.2f}", "voltage_scale", f"l{ph}_voltage")
            show_field(f"Phase {ph}-N Voltage", f"l{ph}n_voltage", "{:.2f}", "voltage_scale", f"l{ph}n_voltage")
    else:
        show_field("Voltage", "l1_voltage", "{:.2f}", "voltage_scale", "l1_voltage")

    show_field("Frequency", "frequency", "{:.2f}", "frequency_scale", "frequency")
    show_field("Power (AC)", "power_ac", "{:.2f}", "power_ac_scale", "power_ac")
    show_field("Power (Apparent)", "power_apparent", "{:.2f}", "power_apparent_scale", "power_apparent")
    show_field("Power (Reactive)", "power_reactive", "{:.2f}", "power_reactive_scale", "power_reactive")
    show_field("Power Factor", "power_factor", "{:.2f}", "power_factor_scale", "power_factor")
    show_field("Energy Total", "energy_total", "{:.2f}", "energy_total_scale", "energy_total")
    show_field("DC Current", "current_dc", "{:.2f}", "current_dc_scale", "current_dc")
    show_field("DC Voltage", "voltage_dc", "{:.2f}", "voltage_dc_scale", "voltage_dc")
    show_field("DC Power", "power_dc", "{:.2f}", "power_dc_scale", "power_dc")

    # ---- Dump every key/value for debugging ----
    print("\nFull key/value dump:")
    for k, v in sorted(values.items()):
        if isinstance(v, dict):
            print(f"\t{k}:")
            for subk, subv in v.items():
                print(f"\t  {subk}: {subv}")
        else:
            print(f"\t{k}: {v}")
