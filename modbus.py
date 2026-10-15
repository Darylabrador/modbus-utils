#!/usr/bin/env python3
"""Modbus TCP assessment tool: scan, identify and write-test a Modbus slave.

For use only against systems you are authorized to test.

Examples:
    # List every unit ID that responds behind the target IP
    ./venv/bin/python modbus.py --host 192.168.1.10 --scan-units \\
        --skip-coils --skip-discrete --skip-holding --skip-input

    # Read every coil and register exposed by unit 1
    ./venv/bin/python modbus.py --host 192.168.1.10 --unit 1

    # Identify the slave (vendor/product/version) behind unit 1
    ./venv/bin/python modbus.py --host 192.168.1.10 --unit 1 --device-info --write-only

    # Write a single coil on unit 1
    ./venv/bin/python modbus.py --host 192.168.1.10 --unit 1 --write-coil 0 1 --write-only

    # Write a single holding register on unit 2
    ./venv/bin/python modbus.py --host 192.168.1.10 --unit 2 --write-register 0 99 --write-only
"""

import argparse
import logging
import sys
import time

from pymodbus.client import ModbusTcpClient
from pymodbus.constants import DeviceInformation, MoreData
from pymodbus.exceptions import ModbusException

MAX_BITS_PER_READ = 2000   # coils / discrete inputs, per Modbus spec
MAX_REGS_PER_READ = 125    # holding / input registers, per Modbus spec
DEFAULT_ADDRESS_SPACE = 65536   # addresses 0..65535

DEVICE_INFO_READ_CODES = {
    "basic": DeviceInformation.BASIC,
    "regular": DeviceInformation.REGULAR,
    "extended": DeviceInformation.EXTENDED,
}

log = logging.getLogger("modbus")


# ---- value extraction (one table type -> one extractor) ----

def bits_values(response, count):
    """Pull `count` bit values out of a coil/discrete-input response."""
    return [int(bit) for bit in response.bits[:count]]


def register_values(response, count):
    """Pull `count` register values out of a holding/input-register response."""
    return list(response.registers[:count])


# ---- low-level read ----

def safe_read(read_fn, address, count, unit):
    """Read a block, returning None on any transport or protocol failure."""
    try:
        response = read_fn(address=address, count=count, device_id=unit)
    except ModbusException:
        return None
    if response is None or response.isError():
        return None
    return response


def read_values(read_fn, extract, address, count, unit):
    """Read a block and return typed values, or None on failure."""
    response = safe_read(read_fn, address, count, unit)
    return None if response is None else extract(response, count)


# ---- scanning ----

def chunks(total, size):
    """Yield (start, count) pairs covering [0, total) in blocks of `size`."""
    start = 0
    while start < total:
        count = min(size, total - start)
        yield start, count
        start += count


def _bisect_scan(read_fn, extract, lo, hi, max_chunk, unit, delay, found):
    """Scan [lo, hi] by splitting any rejected block in half.

    A Modbus read is accepted or rejected as a whole: one invalid address in
    a block fails the entire read. Bisecting a rejected block finds the
    valid addresses hidden inside it, which a fixed-block scan would miss.
    """
    count = hi - lo + 1
    if count > max_chunk:
        mid = lo + count // 2
        _bisect_scan(read_fn, extract, lo, mid - 1, max_chunk, unit, delay, found)
        _bisect_scan(read_fn, extract, mid, hi, max_chunk, unit, delay, found)
        return

    response = safe_read(read_fn, lo, count, unit)
    if delay:
        time.sleep(delay)

    if response is not None:
        for i, value in enumerate(extract(response, count)):
            found[lo + i] = value
        return

    if count == 1:
        return

    mid = lo + count // 2
    _bisect_scan(read_fn, extract, lo, mid - 1, max_chunk, unit, delay, found)
    _bisect_scan(read_fn, extract, mid, hi, max_chunk, unit, delay, found)


def scan_table(read_fn, extract, max_chunk, address_space, unit, delay, bisect):
    """Scan a full Modbus data table and return {address: value}."""
    found = {}
    if bisect:
        _bisect_scan(read_fn, extract, 0, address_space - 1, max_chunk, unit, delay, found)
        return found

    for start, count in chunks(address_space, max_chunk):
        response = safe_read(read_fn, start, count, unit)
        if delay:
            time.sleep(delay)
        if response is not None:
            for i, value in enumerate(extract(response, count)):
                found[start + i] = value

    return found


def scan_unit_ids(client, lo, hi):
    """Probe a range of unit IDs and return the ones that respond.

    A unit "exists" as soon as it returns a structured response, even a
    Modbus exception. Only a transport failure means no slave answered.
    """
    found = {}
    for unit in range(lo, hi + 1):
        try:
            response = client.read_holding_registers(address=0, count=1, device_id=unit)
        except ModbusException:
            continue
        if response is None:
            continue
        found[unit] = "exception (unit exists, address invalid)" if response.isError() else "OK"
    return found


# ---- device identification (FC43) ----

def read_device_info(client, unit):
    """Read slave identification strings via FC43 / MEI 0x0E."""
    info = {}
    for category, read_code in DEVICE_INFO_READ_CODES.items():
        object_id = 0
        while True:
            try:
                response = client.read_device_information(
                    read_code=read_code, object_id=object_id, device_id=unit
                )
            except ModbusException:
                break
            if response is None or response.isError():
                break

            for obj_id, value in response.information.items():
                info[(category, obj_id)] = _decode_info_value(value)

            if response.more_follows != MoreData.KEEP_READING:
                break
            object_id = response.next_object_id

    return info


def _decode_info_value(value):
    if not isinstance(value, bytes):
        return value
    try:
        return value.decode("ascii")
    except UnicodeDecodeError:
        return value.hex()


# ---- write + verify ----

def write_and_verify(label, read_fn, extract, write_fn, write_kwargs, address, count, unit):
    """Write a value, reporting the address state before and after."""
    before = read_values(read_fn, extract, address, count, unit)
    log.info("%s before = %s", label, before)

    try:
        response = write_fn(**write_kwargs)
    except ModbusException as exc:
        log.error("%s write error: %s", label, exc)
    else:
        log.info("%s -> %s", label, "FAILED" if response.isError() else "OK")

    after = read_values(read_fn, extract, address, count, unit)
    log.info("%s after  = %s", label, after)


def run_writes(client, unit, args):
    """Run every write action requested on the command line."""
    if args.write_coil is not None:
        address, value = args.write_coil
        write_and_verify(
            f"coil [{address}]", client.read_coils, bits_values, client.write_coil,
            {"address": address, "value": bool(value), "device_id": unit},
            address, 1, unit,
        )

    if args.write_register is not None:
        address, value = args.write_register
        write_and_verify(
            f"holding register [{address}]", client.read_holding_registers, register_values,
            client.write_register,
            {"address": address, "value": value, "device_id": unit},
            address, 1, unit,
        )

    if args.write_coils is not None:
        address, *values = args.write_coils
        write_and_verify(
            f"coils [{address}..{address + len(values) - 1}]", client.read_coils, bits_values,
            client.write_coils,
            {"address": address, "values": [bool(v) for v in values], "device_id": unit},
            address, len(values), unit,
        )

    if args.write_registers is not None:
        address, *values = args.write_registers
        write_and_verify(
            f"holding registers [{address}..{address + len(values) - 1}]", client.read_holding_registers,
            register_values, client.write_registers,
            {"address": address, "values": values, "device_id": unit},
            address, len(values), unit,
        )


# ---- output ----

def print_table(label, values, show_hex=False):
    print(f"\n=== {label}: {len(values)} active address(es) ===")
    for address in sorted(values):
        value = values[address]
        if show_hex:
            print(f"  [{address:5d}] = {value} (0x{value:04X})")
        else:
            print(f"  [{address:5d}] = {value}")


def print_unit_scan(found):
    print(f"\n=== Active unit IDs: {len(found)} found ===")
    for unit, status in sorted(found.items()):
        print(f"  unit {unit:3d}: {status}")


def print_device_info(info):
    print("\n=== Device identification (FC43) ===")
    if not info:
        print("  (no information returned - function likely unsupported)")
        return
    for (category, obj_id), value in sorted(info.items()):
        print(f"  [{category}] object {obj_id:#04x} = {value!r}")


# ---- CLI ----

def parse_args():
    parser = argparse.ArgumentParser(description="Modbus TCP scan, identification and write-testing tool")
    parser.add_argument("--host", required=True, help="Modbus slave IP address")
    parser.add_argument("--port", type=int, default=502, help="Modbus TCP port (default 502)")
    parser.add_argument("--unit", type=int, default=1, help="Unit/slave ID (default 1)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Socket timeout in seconds")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between requests, in seconds")
    parser.add_argument("--skip-coils", action="store_true", help="Skip scanning coils")
    parser.add_argument("--skip-discrete", action="store_true", help="Skip scanning discrete inputs")
    parser.add_argument("--skip-holding", action="store_true", help="Skip scanning holding registers")
    parser.add_argument("--skip-input", action="store_true", help="Skip scanning input registers")
    parser.add_argument("--max-address", type=int, default=DEFAULT_ADDRESS_SPACE,
                         help="Upper bound of the scanned range (default 65536)")
    parser.add_argument("--bisect", action="store_true",
                         help="Bisect rejected blocks to recover isolated valid addresses (slower, thorough)")
    parser.add_argument("--device-info", action="store_true",
                         help="Read slave identification (FC43 / Read Device Identification)")
    parser.add_argument("--scan-units", action="store_true",
                         help="Brute-force unit IDs to find which slaves respond")
    parser.add_argument("--unit-range", nargs=2, type=int, default=[0, 247], metavar=("LOW", "HIGH"),
                         help="Unit ID range tested by --scan-units (default 0 247)")
    parser.add_argument("--write-coil", nargs=2, type=int, metavar=("ADDRESS", "VALUE"),
                         help="Write a single coil, VALUE is 0 or 1 (FC05)")
    parser.add_argument("--write-register", nargs=2, type=int, metavar=("ADDRESS", "VALUE"),
                         help="Write a single holding register (FC06)")
    parser.add_argument("--write-coils", nargs="+", type=int, metavar="ADDRESS VAL",
                         help="Write consecutive coils starting at ADDRESS, values 0/1 (FC15)")
    parser.add_argument("--write-registers", nargs="+", type=int, metavar="ADDRESS VAL",
                         help="Write consecutive holding registers starting at ADDRESS (FC16)")
    parser.add_argument("--write-only", action="store_true",
                         help="Only run the requested write(s), skip the read scan")
    return parser.parse_args()


def connect(host, port, timeout):
    client = ModbusTcpClient(host, port=port, timeout=timeout)
    if not client.connect():
        log.error("Could not connect to %s:%s", host, port)
        sys.exit(1)
    return client


def scan_all_tables(client, args):
    """Scan every table that was not skipped and return {label: {address: value}}."""
    tables = [
        ("Coils", client.read_coils, bits_values, MAX_BITS_PER_READ, args.skip_coils),
        ("Discrete inputs", client.read_discrete_inputs, bits_values, MAX_BITS_PER_READ, args.skip_discrete),
        ("Holding registers", client.read_holding_registers, register_values, MAX_REGS_PER_READ, args.skip_holding),
        ("Input registers", client.read_input_registers, register_values, MAX_REGS_PER_READ, args.skip_input),
    ]

    results = {}
    for label, read_fn, extract, max_chunk, skip in tables:
        if skip:
            continue
        log.info("Scanning %s...", label.lower())
        results[label] = scan_table(read_fn, extract, max_chunk, args.max_address, args.unit, args.delay, args.bisect)
    return results


def configure_logging():
    # Line-buffer stdout so printed tables interleave correctly with
    # timestamped log lines (logging flushes stderr after every line).
    sys.stdout.reconfigure(line_buffering=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    configure_logging()
    args = parse_args()
    has_write = any([args.write_coil, args.write_register, args.write_coils, args.write_registers])
    if args.write_only:
        args.skip_coils = args.skip_discrete = args.skip_holding = args.skip_input = True

    client = connect(args.host, args.port, args.timeout)
    log.info("Connected to %s:%s (unit=%s)", args.host, args.port, args.unit)

    results = {}
    device_info = None
    try:
        if args.scan_units:
            lo, hi = args.unit_range
            log.info("Scanning unit IDs %s-%s (timeout=%ss each, may take a while)...", lo, hi, args.timeout)
            print_unit_scan(scan_unit_ids(client, lo, hi))

        if has_write:
            run_writes(client, args.unit, args)

        if args.device_info:
            log.info("Reading slave identification (FC43)...")
            device_info = read_device_info(client, args.unit)

        results = scan_all_tables(client, args)
    finally:
        client.close()

    if device_info is not None:
        print_device_info(device_info)

    for label, values in results.items():
        print_table(label, values, show_hex=(label.endswith("registers")))

    total = sum(len(values) for values in results.values())
    log.info("Done. %s active address(es) total.", total)


if __name__ == "__main__":
    main()
