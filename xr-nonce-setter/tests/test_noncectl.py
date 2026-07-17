import importlib.util
import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "tools" / "noncectl.py"
SPEC = importlib.util.spec_from_file_location("noncectl", MODULE_PATH)
noncectl = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(noncectl)


XR_SERIAL = (
    "CPID:8020 CPRV:11 CPFM:03 SCEP:01 BDID:0C "
    "ECID:0011223344556677 IBFL:3C NONC:AABBCCDD "
    "SNON:11223344 SRTG:[iBoot-test] PWND:[usbliter8]"
)


class FakeRecoveryDevice:
    def __init__(self, generator=""):
        self.serial_number = XR_SERIAL
        self.environment = {noncectl.GENERATOR_KEY: generator, "auto-boot": "true"}
        self.pending_get = None
        self.transfers = []

    def ctrl_transfer(self, request_type, request, value, index, data, timeout):
        self.transfers.append((request_type, request, value, index, data, timeout))
        if request_type == 0x40:
            command = bytes(data).rstrip(b"\0").decode("ascii")
            parts = command.split(" ", 2)
            if parts[0] == "getenv":
                self.pending_get = parts[1]
            elif parts[0] == "setenv":
                self.environment[parts[1]] = parts[2]
            return len(data)
        if request_type == 0xC0:
            return (self.environment.get(self.pending_get, "") + "\0").encode()
        return 0


class FakeDfuDevice:
    def __init__(self):
        self.serial_number = XR_SERIAL
        self.transfers = []

    def ctrl_transfer(self, request_type, request, value, index, data, timeout):
        self.transfers.append((request_type, request, value, index, data, timeout))
        if data is None:
            return 0
        return len(data)


class NonceCtlTests(unittest.TestCase):
    def test_set_is_the_only_cli_command(self):
        help_text = noncectl.build_parser().format_help()
        self.assertIn("{set}", help_text)
        for removed in ("prepare", "check", "handoff", "validate", "boot", "reboot", "info"):
            with self.subTest(command=removed):
                self.assertNotIn(f"    {removed} ", help_text)

    def test_set_command_runs_the_complete_workflow(self):
        with tempfile.TemporaryDirectory() as directory:
            args = noncectl.build_parser().parse_args(
                [
                    "set",
                    "0x1111111111111111",
                    "--image",
                    str(Path(directory) / "ibss.raw"),
                    "--record-dir",
                    directory,
                ]
            )
            fields = {
                "CPID": "0x8020",
                "BDID": "0x0c",
                "ECID": "0x0011223344556677",
                "PRODUCT": "iPhone11,8",
                "NONC": "aa" * 32,
            }
            with mock.patch.object(
                noncectl, "boot_raw_iboot", return_value={"bytes_sent": 123}
            ), mock.patch.object(
                noncectl, "wait_for_recovery_irecovery", return_value=fields
            ) as wait_for_recovery, mock.patch.object(
                noncectl, "query_recovery_irecovery", return_value=fields
            ), mock.patch.object(
                noncectl,
                "set_and_verify_generator_irecovery",
                return_value=("0x0000000000000000", "0x1111111111111111"),
            ), mock.patch.object(noncectl, "setenv_irecovery"), mock.patch.object(
                noncectl, "saveenv_irecovery"
            ), mock.patch.object(
                noncectl, "getenv_irecovery", return_value="false"
            ), mock.patch.object(
                noncectl, "wait_for_recovery_absence_irecovery"
            ), mock.patch.object(
                noncectl,
                "command_info",
                return_value={
                    "apnonce": "aa" * 32,
                    "record": str(Path(directory) / "pair.json"),
                },
            ), mock.patch.object(noncectl, "run_irecovery") as run_irecovery:
                result = noncectl.command_set(args)

        self.assertTrue(result["verified"])
        self.assertEqual(result["bytes_sent"], 123)
        self.assertEqual(wait_for_recovery.call_count, 2)
        run_irecovery.assert_called_once_with(
            ["-c", "reboot"], timeout=5, allow_failure=True
        )

    def test_normalize_generator(self):
        self.assertEqual(
            noncectl.normalize_generator("0xAABBCCDDEEFF0011"),
            "0xaabbccddeeff0011",
        )
        for invalid in ("1111111111111111", "0x1", "0xgggggggggggggggg"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(noncectl.NonceCtlError):
                    noncectl.normalize_generator(invalid)

    def test_extract_generator_from_shsh(self):
        with tempfile.TemporaryDirectory() as directory:
            blob = Path(directory) / "ticket.shsh2"
            with blob.open("wb") as stream:
                plistlib.dump(
                    {
                        "generator": "0x1234567890ABCDEF",
                        "ApNonce": bytes.fromhex("ab" * 32),
                    },
                    stream,
                )
            self.assertEqual(
                noncectl.generator_from_argument(str(blob)),
                "0x1234567890abcdef",
            )
            self.assertEqual(noncectl.apnonce_from_argument(str(blob)), "ab" * 32)

    def test_parse_and_validate_xr_serial(self):
        fields = noncectl.parse_serial_fields(XR_SERIAL)
        self.assertEqual(fields["PWND"], "usbliter8")
        self.assertEqual(fields["NONC"], "AABBCCDD")
        noncectl.assert_iphone_xr(fields)

        fields["BDID"] = "0A"
        with self.assertRaises(noncectl.NonceCtlError):
            noncectl.assert_iphone_xr(fields)

    def test_set_generator_is_read_back_exactly(self):
        device = FakeRecoveryDevice("0x0000000000000000")
        before, after = noncectl.set_and_verify_generator(
            device, "0x1111111111111111"
        )
        self.assertEqual(before, "0x0000000000000000")
        self.assertEqual(after, "0x1111111111111111")
        commands = [
            bytes(call[4]).rstrip(b"\0").decode("ascii")
            for call in device.transfers
            if call[0] == 0x40
        ]
        self.assertIn(
            "setenv com.apple.System.boot-nonce 0x1111111111111111", commands
        )
        self.assertIn("saveenv", commands)

    def test_recovery_info_has_entangled_pair(self):
        device = FakeRecoveryDevice("0x1111111111111111")
        fields = noncectl.parse_serial_fields(XR_SERIAL)
        info = noncectl.recovery_info(device, fields)
        self.assertTrue(info["set"])
        self.assertEqual(info["generator"], "0x1111111111111111")
        self.assertEqual(info["apnonce"], "AABBCCDD")

    def test_boot_uploads_in_usbliter8_chunks(self):
        device = FakeDfuDevice()
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "ibss.raw"
            image.write_bytes(b"A" * (noncectl.TRANSFER_SIZE + 3))
            with mock.patch.object(noncectl, "_iter_devices", return_value=[device]):
                result = noncectl.boot_raw_iboot(image)

        self.assertEqual(result["bytes_sent"], noncectl.TRANSFER_SIZE + 3)
        requests = [(call[0], call[1], call[4]) for call in device.transfers]
        downloads = [call for call in requests if call[1] == noncectl.DFU_DNLOAD]
        self.assertEqual(len(downloads), 3)  # two data chunks and the zero-length finish
        self.assertIn((0x21, noncectl.USBLITER8_BOOT, None), requests)
        self.assertIn((0x21, noncectl.DFU_ABORT, None), requests)

    def test_post_reboot_pair_can_be_recorded_and_checked(self):
        fields = noncectl.parse_irecovery_query(
            "\n".join(
                (
                    "CPID: 0x8020",
                    "BDID: 0x0c",
                    "ECID: 0x0011223344556677",
                    f"NONC: {'cd' * 32}",
                    "SNON: 11223344",
                    "MODE: Recovery",
                    "PRODUCT: iPhone11,8",
                )
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "pair.json"
            associate_args = mock.Mock(
                associate="0x1111111111111111", expect=None, record=record,
                allow_apnonce_mismatch=False,
            )
            with mock.patch.object(noncectl, "query_recovery_irecovery", return_value=fields), \
                 mock.patch.object(noncectl, "getenv_irecovery", return_value=""):
                info = noncectl.command_info(associate_args)
            self.assertEqual(info["verified_by"], "post-reboot-pair")
            self.assertTrue(info["set"])

            check_args = mock.Mock(
                associate=None, expect="0x1111111111111111", record=record,
                allow_apnonce_mismatch=False,
            )
            with mock.patch.object(noncectl, "query_recovery_irecovery", return_value=fields), \
                 mock.patch.object(noncectl, "getenv_irecovery", return_value=""):
                checked = noncectl.command_info(check_args)
            self.assertEqual(checked["verified_by"], "saved-pair")

    def test_pwndfu_nonce_mismatch_can_verify_generator_only(self):
        fields = noncectl.parse_irecovery_query(
            "\n".join(
                (
                    "CPID: 0x8020",
                    "BDID: 0x0c",
                    "ECID: 0x0011223344556677",
                    f"NONC: {'aa' * 32}",
                    "SNON: 11223344",
                    "MODE: Recovery",
                    "PRODUCT: iPhone11,8",
                )
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            blob = Path(directory) / "ticket.shsh2"
            with blob.open("wb") as stream:
                plistlib.dump(
                    {
                        "generator": "0x1111111111111111",
                        "ApNonce": bytes.fromhex("bb" * 32),
                    },
                    stream,
                )
            args = mock.Mock(
                associate=None,
                expect=str(blob),
                record=None,
                allow_apnonce_mismatch=True,
            )
            with mock.patch.object(noncectl, "query_recovery_irecovery", return_value=fields), \
                 mock.patch.object(
                     noncectl,
                     "getenv_irecovery",
                     return_value="0x1111111111111111",
                 ):
                info = noncectl.command_info(args)

        self.assertEqual(info["verified_by"], "generator-with-pwned-nonce")
        self.assertFalse(info["apnonce_matches_blob"])
        self.assertEqual(info["blob_apnonce"], "bb" * 32)


if __name__ == "__main__":
    unittest.main()
