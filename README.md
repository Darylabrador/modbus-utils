# modbus.py — Modbus TCP Reconnaissance & Assessment Tool

A Python command-line tool for assessing Modbus TCP devices during **authorized security testing** (penetration tests, ICS/OT security audits, CTF/lab environments). It covers full address-space enumeration, slave identification, and write-access testing in a single script built on top of [pymodbus](https://github.com/pymodbus-dev/pymodbus).

## Legal & Ethical Use

This tool is intended **exclusively** for use against systems you own or are explicitly authorized to test (e.g. under a signed penetration test engagement, in a lab/CTF environment, or for defensive research on your own infrastructure).

Modbus has no built-in authentication: reads are generally harmless, but **write operations change the real state of the target device**. Unauthorized or careless use against industrial control systems can cause operational disruption or safety incidents. You are solely responsible for ensuring you have permission before running this tool, and especially before using any `--write-*` option.

## Features

| Capability | Function code(s) | Description |
|---|---|---|
| Coils | FC01 (read) / FC05, FC15 (write) | Read/write single-bit outputs |
| Discrete inputs | FC02 (read-only) | Read single-bit inputs |
| Holding registers | FC03 (read) / FC06, FC16 (write) | Read/write 16-bit registers |
| Input registers | FC04 (read-only) | Read 16-bit registers |
| Slave identification | FC43 (MEI 0x0E) | Vendor, product, version, etc. |
| Unit ID discovery | — | Brute-forces unit/slave IDs behind a gateway |

Key design points:

- **Full address-space scan** (0–65535) for all four Modbus data tables, in properly sized blocks (2000 bits / 125 registers per request, per the Modbus spec).
- **Bisection mode** (`--bisect`): a Modbus read request is accepted or rejected as a whole — if a single address in a block is invalid, the entire block read fails. A naive fixed-block scan can therefore miss isolated valid registers hidden inside a mostly-invalid range. Bisection recursively narrows down rejected blocks to find exactly which addresses are valid.
- **Write testing** with before/after read-back on every write, so you can immediately verify whether the device accepted an unauthenticated write and whether it reflects in the process.

## Installation

```bash
git clone <repository-url>
cd modbus_exploit
python3 -m venv venv
source venv/bin/activate      # or call ./venv/bin/python directly
pip install -r requirements.txt
```

## Usage

### Full scan (default)

```bash
./venv/bin/python modbus.py --host 192.168.1.10 --port 502 --unit 1
```

Reads the entire address range (0–65535) across all four data tables.

### Scan a reduced range

```bash
./venv/bin/python modbus.py --host 192.168.1.10 --max-address 200
```

### Bisection scan

```bash
./venv/bin/python modbus.py --host 192.168.1.10 \
    --skip-coils --skip-discrete --skip-input \
    --bisect --max-address 1000
```

Slower than a fixed-block scan, but exhaustive — recommended whenever a fixed-block scan reports zero results for a data table that you otherwise expect to be populated.

### Unit ID (slave ID) discovery

The unit ID identifies which slave should answer a request — relevant behind a Modbus TCP-to-serial gateway bridging multiple devices on one IP. `--scan-units` probes a range of IDs and reports every one that responds, including with a Modbus exception (which still proves the slave exists):

```bash
./venv/bin/python modbus.py --host 192.168.1.10 --scan-units --unit-range 0 247 \
    --skip-coils --skip-discrete --skip-holding --skip-input
```

Each non-responding ID waits for the full `--timeout` before moving to the next one. Lower `--timeout` (e.g. `--timeout 0.5`) to speed up wide scans.

### Slave identification (FC43)

```bash
./venv/bin/python modbus.py --host 192.168.1.10 --device-info --write-only
```

`--write-only` (or the relevant `--skip-*` flags) skips the full data-table scan.

### Write testing

Writes a value and reports the register/coil state before and after, so you can confirm whether the write was accepted:

```bash
# Single holding register
./venv/bin/python modbus.py --host 192.168.1.10 --write-register 0 99 --write-only

# Single coil
./venv/bin/python modbus.py --host 192.168.1.10 --write-coil 0 1 --write-only

# Multiple consecutive holding registers starting at address 0
./venv/bin/python modbus.py --host 192.168.1.10 --write-registers 0 99 88 --write-only

# Multiple consecutive coils starting at address 0
./venv/bin/python modbus.py --host 192.168.1.10 --write-coils 0 1 0 1 --write-only
```

> Always capture the original value before writing, and restore it afterwards when testing a shared or production system.

## Command-line reference

| Option | Description | Example |
|---|---|---|
| `--host` | Modbus slave IP address. **Required.** | `--host 192.168.1.10` |
| `--port` | Modbus TCP port. Default `502`. | `--port 5020` |
| `--unit` | Unit/slave ID to target for the scan and for write operations. Default `1`. | `--unit 3` |
| `--timeout` | Socket timeout in seconds for each request. Lower it to speed up scans against a responsive target, raise it on a slow/flaky link. Default `2.0`. | `--timeout 0.5` |
| `--delay` | Pause (seconds) inserted between requests, to avoid flooding a fragile or production device. Default `0` (no delay). | `--delay 0.05` |
| `--max-address` | Upper bound (exclusive) of the scanned address range. Reduce it for a quick first pass before scanning the full `0`–`65535` space. Default `65536`. | `--max-address 1000` |
| `--skip-coils` | Exclude coils (FC01) from the scan. | `--skip-coils` |
| `--skip-discrete` | Exclude discrete inputs (FC02) from the scan. | `--skip-discrete` |
| `--skip-holding` | Exclude holding registers (FC03) from the scan. | `--skip-holding` |
| `--skip-input` | Exclude input registers (FC04) from the scan. | `--skip-input` |
| `--bisect` | Recursively bisect rejected blocks to recover isolated valid addresses that a fixed-block scan would miss. Slower, more thorough; combine with `--skip-*` and a smaller `--max-address` to keep runtime reasonable. | `--bisect --skip-coils --skip-discrete --skip-input --max-address 1000` |
| `--device-info` | Query slave identification (vendor, product, version) via FC43. Combine with `--write-only` (or all four `--skip-*` flags) to skip the data-table scan. | `--device-info --write-only` |
| `--scan-units` | Brute-force unit/slave IDs to find which ones respond behind the target IP. Combine with the four `--skip-*` flags to avoid also running a full scan per discovered unit. | `--scan-units --skip-coils --skip-discrete --skip-holding --skip-input` |
| `--unit-range LOW HIGH` | Unit ID range probed by `--scan-units`. Default `0 247` (the full valid Modbus unit ID range). | `--unit-range 0 20` |
| `--write-coil ADDRESS VALUE` | Write a single coil via FC05. `VALUE` is `0` or `1`. | `--write-coil 3 1` |
| `--write-register ADDRESS VALUE` | Write a single holding register via FC06. `VALUE` is a 16-bit integer (`0`–`65535`). | `--write-register 0 99` |
| `--write-coils ADDRESS VAL [VAL ...]` | Write multiple consecutive coils via FC15, starting at `ADDRESS`. Each `VAL` is `0` or `1`. | `--write-coils 0 1 0 1` |
| `--write-registers ADDRESS VAL [VAL ...]` | Write multiple consecutive holding registers via FC16, starting at `ADDRESS`. | `--write-registers 0 99 88` |
| `--write-only` | Perform only the requested write(s) and/or `--device-info`/`--scan-units` action, skipping the full read scan. Use whenever you don't need the four-table scan in the same run. | `--write-register 0 99 --write-only` |

Run `./venv/bin/python modbus.py --help` for the full, up-to-date list.

## Notes

- A fixed-block scan can miss isolated valid registers when most of the address space is invalid — use `--bisect` for exhaustive detection, particularly on holding registers.
- Built on pymodbus 3.16+, which uses the `device_id` keyword (rather than the older `slave` keyword) to address a given unit ID.

## Requirements

- Python 3.9+
- [pymodbus](https://pypi.org/project/pymodbus/) (see `requirements.txt`)

## License

Add your preferred license here before distributing this tool.
