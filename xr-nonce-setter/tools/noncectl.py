#!/usr/bin/env python3
"""Small USB control helper for setting and verifying an A12 boot nonce.

The helper intentionally supports only the iPhone XR (iPhone11,8 / n841ap).
It talks to usbliter8 while the phone is in pwned DFU and to iBoot while the
phone is in recovery mode. Image preparation remains in xr-nonce-setter.sh.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

try:
    import usb.core as usb_core
    import usb.util as usb_util
except ModuleNotFoundError:  # Keep validation and unit tests usable without pyusb.
    usb_core = None
    usb_util = None


APPLE_VENDOR_ID = 0x05AC
DFU_PRODUCT_ID = 0x1227
RECOVERY_PRODUCT_IDS = tuple(range(0x1280, 0x1284))

IPHONE_XR_CPID = 0x8020
IPHONE_XR_BDID = 0x0C
IPHONE_XR_PRODUCT = "iPhone11,8"

GENERATOR_KEY = "com.apple.System.boot-nonce"
GENERATOR_PATTERN = re.compile(r"^0x[0-9a-fA-F]{16}$")
SERIAL_FIELD_PATTERN = re.compile(r"(?:^|\s)([A-Z]+):(?:\[([^\]]*)\]|(\S+))")

TRANSFER_SIZE = 0x800
USB_TIMEOUT_MS = 1_000

DFU_DNLOAD = 1
DFU_ABORT = 4
USBLITER8_BOOT = 8


class NonceCtlError(RuntimeError):
    """Expected user-facing failure."""


def normalize_generator(value: str) -> str:
    value = value.strip()
    if not GENERATOR_PATTERN.fullmatch(value):
        raise NonceCtlError(
            "generator must be 0x followed by exactly 16 hexadecimal digits"
        )
    return "0x" + value[2:].lower()


def generator_from_argument(value: str) -> str:
    candidate = Path(value).expanduser()
    if not candidate.is_file():
        return normalize_generator(value)

    try:
        with candidate.open("rb") as stream:
            ticket = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise NonceCtlError(f"unable to read SHSH blob {candidate}: {exc}") from exc

    generator = ticket.get("generator") if isinstance(ticket, dict) else None
    if isinstance(generator, bytes):
        generator = generator.decode("ascii", errors="strict")
    if not isinstance(generator, str):
        raise NonceCtlError(f"SHSH blob has no string generator: {candidate}")
    return normalize_generator(generator)


def apnonce_from_argument(value: str) -> str | None:
    candidate = Path(value).expanduser()
    if not candidate.is_file():
        return None
    try:
        with candidate.open("rb") as stream:
            ticket = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as exc:
        raise NonceCtlError(f"unable to read SHSH blob {candidate}: {exc}") from exc

    def find_apnonce(item: Any) -> Any:
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).lower() == "apnonce":
                    return child
            for child in item.values():
                found = find_apnonce(child)
                if found is not None:
                    return found
        elif isinstance(item, (list, tuple)):
            for child in item:
                found = find_apnonce(child)
                if found is not None:
                    return found
        return None

    apnonce = find_apnonce(ticket)
    if isinstance(apnonce, bytes):
        return apnonce.hex()
    if isinstance(apnonce, str):
        normalized = apnonce.strip().lower().removeprefix("0x")
        if re.fullmatch(r"[0-9a-f]{64}", normalized):
            return normalized
    return None


def parse_serial_fields(serial: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in SERIAL_FIELD_PATTERN.finditer(serial or ""):
        fields[match.group(1)] = match.group(2) or match.group(3) or ""
    return fields


def _hex_field(fields: dict[str, str], name: str) -> int:
    value = fields.get(name)
    if not value:
        raise NonceCtlError(f"device USB serial is missing {name}")
    try:
        return int(value, 16)
    except ValueError as exc:
        raise NonceCtlError(f"device USB serial contains invalid {name}: {value}") from exc


def assert_iphone_xr(fields: dict[str, str]) -> None:
    cpid = _hex_field(fields, "CPID")
    bdid = _hex_field(fields, "BDID")
    if (cpid, bdid) != (IPHONE_XR_CPID, IPHONE_XR_BDID):
        raise NonceCtlError(
            "this nonce path currently supports only iPhone XR "
            f"(expected CPID:8020 BDID:0C, got CPID:{cpid:04X} BDID:{bdid:02X})"
        )


def _require_pyusb() -> None:
    if usb_core is None:
        raise NonceCtlError(
            "pyusb is required; install it with: python3 -m pip install pyusb"
        )


def _iter_devices(product_ids: Iterable[int]) -> list[Any]:
    _require_pyusb()
    devices: list[Any] = []
    for product_id in product_ids:
        try:
            found = usb_core.find(
                find_all=True,
                idVendor=APPLE_VENDOR_ID,
                idProduct=product_id,
            )
        except Exception as exc:
            raise NonceCtlError(
                "unable to access the libusb backend; install libusb and check USB permissions"
            ) from exc
        if found is not None:
            devices.extend(list(found))
    return devices


def _serial_number(device: Any) -> str:
    try:
        return device.serial_number or ""
    except Exception as exc:  # PyUSB backends expose platform-specific errors.
        raise NonceCtlError(
            "unable to read the device USB serial; check USB permissions and cable access"
        ) from exc


def find_one_device(product_ids: Iterable[int], mode_name: str) -> tuple[Any, dict[str, str]]:
    devices = _iter_devices(product_ids)
    if not devices:
        raise NonceCtlError(f"no Apple device found in {mode_name} mode")
    if len(devices) > 1:
        raise NonceCtlError(
            f"multiple Apple devices found in {mode_name} mode; connect only the target iPhone XR"
        )

    device = devices[0]
    fields = parse_serial_fields(_serial_number(device))
    assert_iphone_xr(fields)
    return device, fields


def send_command(device: Any, command: str, *, request: int = 0) -> None:
    encoded = command.encode("ascii") + b"\0"
    if len(encoded) > 0x100:
        raise NonceCtlError("iBoot command is too long")
    try:
        device.ctrl_transfer(0x40, request, 0, 0, encoded, USB_TIMEOUT_MS)
    except Exception as exc:
        raise NonceCtlError(f"iBoot rejected command: {command}") from exc


def getenv(device: Any, name: str) -> str:
    send_command(device, f"getenv {name}")
    try:
        response = device.ctrl_transfer(0xC0, 0, 0, 0, 0xFF, USB_TIMEOUT_MS)
    except Exception as exc:
        raise NonceCtlError(f"unable to read iBoot variable: {name}") from exc
    raw = bytes(response).split(b"\0", 1)[0]
    return raw.decode("utf-8", errors="replace").strip()


def setenv(device: Any, name: str, value: str) -> None:
    send_command(device, f"setenv {name} {value}")


def saveenv(device: Any) -> None:
    send_command(device, "saveenv")


def set_and_verify_generator(device: Any, generator: str) -> tuple[str, str]:
    expected = normalize_generator(generator)
    before = getenv(device, GENERATOR_KEY)
    setenv(device, GENERATOR_KEY, expected)
    saveenv(device)
    after = getenv(device, GENERATOR_KEY)

    try:
        actual = normalize_generator(after)
    except NonceCtlError as exc:
        raise NonceCtlError(
            f"iBoot did not persist a valid generator (read back {after!r})"
        ) from exc
    if actual != expected:
        raise NonceCtlError(
            f"generator verification failed (expected {expected}, read back {actual})"
        )
    return before, actual


def find_irecovery() -> str:
    configured = os.environ.get("IRECOVERY")
    bundled = Path(__file__).resolve().parents[1] / "bin" / "irecovery"
    if configured:
        candidate = configured
    elif bundled.is_file() and os.access(bundled, os.X_OK):
        candidate = str(bundled)
    else:
        candidate = shutil.which("irecovery") or ""
    if not candidate:
        raise NonceCtlError("irecovery is required for recovery-mode nonce commands")
    return candidate


def run_irecovery(
    arguments: list[str],
    *,
    input_text: str | None = None,
    timeout: float = 15,
    allow_failure: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [find_irecovery(), *arguments],
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NonceCtlError(f"irecovery timed out while running: {' '.join(arguments)}") from exc
    except OSError as exc:
        raise NonceCtlError(f"unable to run irecovery: {exc}") from exc
    if result.returncode != 0 and not allow_failure:
        detail = (result.stderr or result.stdout).strip()
        raise NonceCtlError(detail or f"irecovery failed: {' '.join(arguments)}")
    return result


def parse_irecovery_query(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    return fields


def query_recovery_irecovery() -> dict[str, str]:
    result = run_irecovery(["-q"], timeout=5)
    fields = parse_irecovery_query(result.stdout)
    if fields.get("MODE") != "Recovery":
        raise NonceCtlError("iPhone XR is not in recovery mode")
    if fields.get("PRODUCT") != IPHONE_XR_PRODUCT:
        raise NonceCtlError(
            f"recovery device is not an iPhone XR (found {fields.get('PRODUCT') or 'unknown'})"
        )
    assert_iphone_xr(fields)
    return fields


def getenv_irecovery(name: str) -> str:
    command = f"getenv {name}"
    result = run_irecovery(
        ["-s"],
        input_text=f"{command}\n/exit\n",
        timeout=10,
    )
    output = (result.stdout + "\n" + result.stderr).replace("\r", "\n")
    lines = [line.strip() for line in output.splitlines() if line.strip()]

    if name == GENERATOR_KEY:
        for line in lines:
            if GENERATOR_PATTERN.fullmatch(line):
                return line
        return ""
    if name == "auto-boot":
        for line in lines:
            if line.lower() in ("true", "false", "0", "1"):
                return line.lower()
        return ""
    raise NonceCtlError(f"unsupported iBoot variable query: {name}")


def setenv_irecovery(name: str, value: str) -> None:
    run_irecovery(["-c", f"setenv {name} {value}"])


def saveenv_irecovery() -> None:
    run_irecovery(["-c", "saveenv"])


def set_and_verify_generator_irecovery(generator: str) -> tuple[str, str]:
    expected = normalize_generator(generator)
    before = getenv_irecovery(GENERATOR_KEY)
    setenv_irecovery(GENERATOR_KEY, expected)
    saveenv_irecovery()
    after = getenv_irecovery(GENERATOR_KEY)
    try:
        actual = normalize_generator(after)
    except NonceCtlError as exc:
        raise NonceCtlError(
            f"iBoot did not persist a valid generator (read back {after!r})"
        ) from exc
    if actual != expected:
        raise NonceCtlError(
            f"generator verification failed (expected {expected}, read back {actual})"
        )
    return before, actual


def try_query_recovery_irecovery() -> dict[str, str] | None:
    try:
        result = run_irecovery(["-q"], timeout=3, allow_failure=True)
    except NonceCtlError:
        # During a reboot libirecovery can briefly open a disappearing USB
        # device and block until its timeout. Treat that interval as absent.
        return None
    if result.returncode != 0:
        return None
    fields = parse_irecovery_query(result.stdout)
    if fields.get("MODE") != "Recovery" or fields.get("PRODUCT") != IPHONE_XR_PRODUCT:
        return None
    return fields


def wait_for_recovery_irecovery(timeout: float) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        fields = try_query_recovery_irecovery()
        if fields is not None:
            assert_iphone_xr(fields)
            return fields
        time.sleep(0.25)
    raise NonceCtlError(f"iPhone XR did not enter recovery within {timeout:g} seconds")


def wait_for_recovery_absence_irecovery(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if try_query_recovery_irecovery() is None:
            return
        time.sleep(0.1)
    raise NonceCtlError("iPhone XR did not disconnect after the reboot command")


def _dispose(device: Any) -> None:
    if usb_util is not None:
        try:
            usb_util.dispose_resources(device)
        except Exception:
            pass


def boot_raw_iboot(image: Path) -> dict[str, Any]:
    if not image.is_file():
        raise NonceCtlError(f"raw iBoot image does not exist: {image}")
    payload = image.read_bytes()
    if not payload:
        raise NonceCtlError(f"raw iBoot image is empty: {image}")

    device, fields = find_one_device((DFU_PRODUCT_ID,), "DFU")
    pwned_by = fields.get("PWND", "")
    if pwned_by.lower() != "usbliter8":
        raise NonceCtlError(
            "iPhone XR is not in usbliter8 pwned DFU mode "
            f"(PWND is {pwned_by or 'missing'})"
        )

    try:
        for offset in range(0, len(payload), TRANSFER_SIZE):
            chunk = payload[offset : offset + TRANSFER_SIZE]
            device.ctrl_transfer(0x21, DFU_DNLOAD, 0, 0, chunk, USB_TIMEOUT_MS)
            sent = offset + len(chunk)
            percent = sent * 100 // len(payload)
            print(
                f"\r[*] Uploading nonce iBSS: {percent:3d}% "
                f"({sent}/{len(payload)} bytes)",
                end="",
                flush=True,
                file=sys.stderr,
            )
        print(file=sys.stderr)
        device.ctrl_transfer(0x21, DFU_DNLOAD, 0, 0, None, USB_TIMEOUT_MS)
        try:
            device.ctrl_transfer(0x21, USBLITER8_BOOT, 0, 0, None, USB_TIMEOUT_MS)
            device.ctrl_transfer(0x21, DFU_ABORT, 0, 0, None, USB_TIMEOUT_MS)
        except Exception:
            # A successful raw boot commonly disconnects before the host sees a reply.
            pass
    except Exception as exc:
        raise NonceCtlError("failed while uploading the nonce iBSS") from exc
    finally:
        _dispose(device)

    return {
        "bytes_sent": len(payload),
        "cpid": fields.get("CPID"),
        "bdid": fields.get("BDID"),
        "pwned": pwned_by,
    }


def wait_for_recovery(timeout: float) -> tuple[Any, dict[str, str]]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return find_one_device(RECOVERY_PRODUCT_IDS, "recovery")
        except NonceCtlError as exc:
            last_error = exc
            time.sleep(0.25)
    raise NonceCtlError(f"iPhone XR did not enter recovery within {timeout:g} seconds") from last_error


def wait_for_absence(product_ids: Iterable[int], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _iter_devices(product_ids):
            return
        time.sleep(0.1)
    raise NonceCtlError("iPhone XR did not disconnect after the reboot command")


def recovery_info(device: Any, fields: dict[str, str]) -> dict[str, Any]:
    generator = getenv(device, GENERATOR_KEY)
    normalized: str | None
    try:
        normalized = normalize_generator(generator)
    except NonceCtlError:
        normalized = None

    return {
        "product": IPHONE_XR_PRODUCT,
        "model": "n841ap",
        "cpid": fields.get("CPID"),
        "bdid": fields.get("BDID"),
        "ecid": fields.get("ECID"),
        "generator": normalized,
        "apnonce": fields.get("NONC"),
        "sepnonce": fields.get("SNON"),
        "set": normalized is not None,
    }


def recovery_info_irecovery(fields: dict[str, str]) -> dict[str, Any]:
    generator = getenv_irecovery(GENERATOR_KEY)
    try:
        normalized: str | None = normalize_generator(generator)
    except NonceCtlError:
        normalized = None

    return {
        "product": IPHONE_XR_PRODUCT,
        "model": "n841ap",
        "cpid": fields.get("CPID"),
        "bdid": fields.get("BDID"),
        "ecid": fields.get("ECID"),
        "generator": normalized,
        "apnonce": fields.get("NONC"),
        "sepnonce": fields.get("SNON"),
        "set": normalized is not None,
    }


def write_record(path: Path, info: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(info)
    payload["recorded_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_record(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NonceCtlError(f"unable to read nonce record {path}: {exc}") from exc
    return payload if isinstance(payload, dict) else None


def command_set(args: argparse.Namespace) -> dict[str, Any]:
    generator = generator_from_argument(args.generator)

    boot_result = boot_raw_iboot(args.image)
    wait_for_recovery_irecovery(args.boot_wait)
    fields = query_recovery_irecovery()
    before, actual = set_and_verify_generator_irecovery(generator)
    setenv_irecovery("auto-boot", "false")
    saveenv_irecovery()
    auto_boot = getenv_irecovery("auto-boot").lower()
    if auto_boot not in ("false", "0"):
        raise NonceCtlError(
            f"failed to disable auto-boot before verification (read back {auto_boot!r})"
        )

    ecid = fields.get("ECID")
    run_irecovery(["-c", "reboot"], timeout=5, allow_failure=True)
    started = time.monotonic()
    wait_for_recovery_absence_irecovery(min(args.reboot_wait, 5.0))
    remaining = max(0.25, args.reboot_wait - (time.monotonic() - started))
    wait_for_recovery_irecovery(remaining)

    ecid_text = re.sub(r"^0[xX]", "", str(ecid or ""))
    clean_ecid = re.sub(r"[^0-9a-fA-F]", "", ecid_text)
    if not clean_ecid:
        raise NonceCtlError("recovery mode did not expose an ECID")
    record_name = f"{IPHONE_XR_PRODUCT}-{clean_ecid}.json"
    info_args = argparse.Namespace(
        associate=args.generator,
        expect=None,
        record=args.record_dir / record_name,
        allow_apnonce_mismatch=False,
    )
    info = command_info(info_args)
    if args.boot_normal:
        run_irecovery(["-n"])

    return {
        "product": IPHONE_XR_PRODUCT,
        "ecid": ecid,
        "before": before or None,
        "generator": actual,
        "verified": True,
        "apnonce": info["apnonce"],
        "record": info["record"],
        "bytes_sent": boot_result["bytes_sent"],
        "boot_normal": args.boot_normal,
    }


def command_info(args: argparse.Namespace) -> dict[str, Any]:
    fields = query_recovery_irecovery()
    info = recovery_info_irecovery(fields)
    if not info["apnonce"] or info["apnonce"] == "N/A":
        raise NonceCtlError("recovery did not expose an APNonce")

    info["apnonce"] = str(info["apnonce"]).lower()
    live_generator = info["generator"]
    record = read_record(args.record)
    expected_source = args.associate or args.expect
    allow_apnonce_mismatch = getattr(args, "allow_apnonce_mismatch", False) is True

    if expected_source:
        expected = generator_from_argument(expected_source)
        blob_apnonce = apnonce_from_argument(expected_source)
        if live_generator is not None and live_generator != expected:
            raise NonceCtlError(
                f"nonce is not set to the requested generator "
                f"(expected {expected}, found {live_generator})"
            )
        apnonce_matches_blob = blob_apnonce is None or info["apnonce"] == blob_apnonce
        if not apnonce_matches_blob and not allow_apnonce_mismatch:
            raise NonceCtlError(
                "recovery APNonce does not match the APNonce in the supplied SHSH blob"
            )
        if not apnonce_matches_blob and live_generator is None:
            raise NonceCtlError(
                "live APNonce differs from the blob and the saved generator is not readable"
            )

        verified_by = "live-generator"
        if blob_apnonce is not None and apnonce_matches_blob:
            verified_by = "shsh-apnonce"
        elif blob_apnonce is not None and allow_apnonce_mismatch:
            verified_by = "generator-with-pwned-nonce"
        elif live_generator is None and args.associate:
            verified_by = "post-reboot-pair"
        elif live_generator is None and record:
            record_generator = record.get("generator")
            record_apnonce = str(record.get("apnonce") or "").lower()
            if record_generator != expected or record_apnonce != info["apnonce"]:
                raise NonceCtlError(
                    "the live generator is no longer readable and the saved generator/APNonce "
                    "pair does not match"
                )
            verified_by = "saved-pair"
        elif live_generator is None:
            raise NonceCtlError(
                "the live generator is no longer readable; rerun set to create "
                "a verified generator/APNonce pair"
            )
        info["generator"] = expected
        info["set"] = True
        info["verified_by"] = verified_by
        if blob_apnonce is not None:
            info["blob_apnonce"] = blob_apnonce
            info["apnonce_matches_blob"] = apnonce_matches_blob
    elif not info["set"]:
        if record:
            record_generator = record.get("generator")
            record_apnonce = str(record.get("apnonce") or "").lower()
            try:
                record_generator = normalize_generator(str(record_generator))
            except NonceCtlError:
                record_generator = None
            if record_generator and record_apnonce == info["apnonce"]:
                info["generator"] = record_generator
                info["set"] = True
                info["verified_by"] = "saved-pair"
        if not info["set"]:
            raise NonceCtlError(
                "the generator is not readable in this recovery session and no matching "
                "saved generator/APNonce pair exists"
            )

    if args.record:
        write_record(args.record, info)
        info["record"] = str(args.record)
    return info


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="iPhone XR usbliter8 nonce control")
    subparsers = parser.add_subparsers(dest="command", required=True)

    set_parser = subparsers.add_parser("set", help="run the complete nonce-setting workflow")
    set_parser.add_argument("generator")
    set_parser.add_argument("--image", type=Path, required=True, help="raw patched iBSS")
    set_parser.add_argument("--record-dir", type=Path, required=True)
    set_parser.add_argument("--boot-wait", type=float, default=20, metavar="SECONDS")
    set_parser.add_argument("--reboot-wait", type=float, default=30, metavar="SECONDS")
    set_parser.add_argument("--boot-normal", action="store_true")
    set_parser.set_defaults(func=command_set, quiet=False)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
        if not args.quiet:
            print(json.dumps(result, sort_keys=True))
        return 0
    except (NonceCtlError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(
            "\n[!] Transfer interrupted. Re-enter DFU and re-pwn with usbliter8 before retrying.",
            file=sys.stderr,
        )
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
