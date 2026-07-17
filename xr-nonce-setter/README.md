# XR Nonce Setter

A standalone iPhone XR (`iPhone11,8`, A12/n841ap) nonce setter using an
usbliter8-pwned DFU session.

The setter boots a nonce-patched iOS 14.4.2 iBSS, writes and reads back the
generator, reboots to recovery, and records the resulting A12-entangled
APNonce pair. The same iBSS also disables signature checks and unlocks NVRAM,
so it can be booted again as the final handoff into a custom futurerestore
session. Entering DFU changes the live APNonce, but the saved generator remains
set for the later untethered boot.

## Requirements

- Linux x86_64 or macOS
- Python 3 and PyUSB (`python3 -m pip install pyusb`)
- libusb and permission to access the connected USB device
- An iPhone XR in DFU mode, pwned using usbliter8

Do not run the script with `sudo`.

## Usage

Set a generator directly or use a matching SHSH2 blob:

```sh
./xr-nonce-setter.sh set 0x1111111111111111
./xr-nonce-setter.sh set /path/to/blob.shsh2
```

`set` is the project's only command. It automatically downloads the required
tools, prepares the patched iBSS when needed, sets and verifies the generator,
reboots to recovery, and records the resulting APNonce pair. The phone is left
in recovery by default; add `--boot-normal` to exit recovery afterward.

Records are saved under `nonce/iPhone11,8-ECID.json`. Keep this record with the
matching SHSH blobs. This utility sets the nonce pair; it does not bypass SEP,
baseband, or firmware-signing compatibility requirements.

## Supported device

Only the iPhone XR is accepted. The script validates `CPID 0x8020`, `BDID
0x0c`, and `PRODUCT iPhone11,8` before making changes.
