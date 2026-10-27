import codecs
import csv
from datetime import timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from linux_log_triage.cli import export_view, main, serialize
from linux_log_triage.core import analyze, parse_offset
from contextlib import redirect_stdout, redirect_stderr


def ssh(stamp, message):
    return f"{stamp} lab sshd[42]: {message}\n"


FAILED = "Failed password for invalid user demo from 192.0.2.10 port 1234 ssh2"
SUCCESS = "Accepted publickey for demo from 192.0.2.10 port 1234 ssh2"


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, content, name="input.log"):
        path = self.root / name
        path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return path

    def test_all_rules_and_evidence(self):
        content = ssh("2026-01-01T12:00:00Z", FAILED)
        content += ssh("2026-01-01T12:00:01Z", "Invalid user ghost from 2001:db8::1 port 11")
        content += ssh("2026-01-01T12:00:02Z", SUCCESS)
        content += "2026-01-01T12:00:03Z lab sudo[4]: demo : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/id\n"
        content += "2026-01-01T12:00:04Z lab sudo: pam_unix(sudo:session): session opened for user root(uid=0) by demo(uid=1000)\n"
        content += "2026-01-01T12:00:05Z lab sudo: pam_unix(sudo:session): session closed for user root\n"
        result = analyze([self.write(content)])
        self.assertEqual(len(result["events"]), 6)
        self.assertEqual(result["unknown_user_events"], 2)
        self.assertEqual(result["summary"]["sudo_session"], 2)
        self.assertEqual(result["events"][0]["line"], 1)
        self.assertTrue(all(e["condition"] for e in result["events"]))

    def test_window_boundary_success_and_unsorted(self):
        content = "".join(ssh(f"2026-01-01T00:{minute}:00Z", message) for minute, message in
                          [("05", FAILED), ("00", FAILED), ("02", FAILED), ("06", SUCCESS)])
        result = analyze([self.write(content)], window_seconds=300, threshold=3)
        self.assertEqual(len(result["repetitions"]), 1)
        self.assertEqual(result["repetitions"][0]["lines"], [2, 3, 1])
        self.assertEqual(result["events"][-1]["rule"], "ssh_success")
        self.assertEqual(analyze([self.root / "input.log"], window_seconds=299)["repetitions"], [])

    def test_timezone_equivalence(self):
        content = ssh("2026-01-01T03:00:00+03:00", FAILED) + ssh("2026-01-01T00:00:00Z", FAILED)
        content += ssh("2025-12-31T19:00:00-0500", FAILED)
        result = analyze([self.write(content)], window_seconds=1)
        self.assertEqual(result["repetitions"][0]["count"], 3)
        self.assertEqual(result["events"][0]["timestamp"], "2026-01-01T00:00:00+00:00")

    def test_naive_iso_and_fractional(self):
        result = analyze([self.write(ssh("2026-01-01 03:00:00.123", FAILED))], tz=parse_offset("+03:00"))
        self.assertEqual(result["events"][0]["timestamp"], "2026-01-01T00:00:00.123000+00:00")

    def test_legacy_year_rollover(self):
        content = ssh("Dec 31 23:59:59", FAILED) + ssh("Jan  1 00:00:00", FAILED)
        result = analyze([self.write(content)], year=2025, threshold=2)
        self.assertEqual(result["events"][1]["timestamp"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(len(result["repetitions"]), 1)

    def test_missing_year_and_bad_dates(self):
        content = ssh("Feb 29 00:00:00", FAILED) + ssh("garbage", FAILED) + ssh("2026-99-01T00:00:00Z", FAILED)
        path = self.write(content)
        result = analyze([path])
        self.assertTrue(all(e["timestamp"] is None for e in result["events"]))
        self.assertEqual(result["repetitions"], [])
        self.assertIsNone(analyze([path], year=2025)["events"][0]["timestamp"])
        self.assertIsNotNone(analyze([path], year=2024)["events"][0]["timestamp"])

    def test_empty(self):
        result = analyze([self.write(b"")])
        self.assertEqual(result["events"], [])
        self.assertEqual(result["sources"][0]["lines"], 0)

    def test_damage_and_long_lines_are_skipped(self):
        data = b"\xff\xfeoops\x00\n"  # Explicit UTF-8 avoids interpreting BOM as UTF-16.
        data += b"x" * 65537 + b"\n"
        data += ssh("2026-01-01T00:00:00Z", FAILED).encode()
        result = analyze([self.write(data)], encoding="utf-8")
        self.assertEqual(len(result["events"]), 1)
        diagnostics = result["sources"][0]["diagnostics"]
        self.assertEqual(diagnostics["damaged_lines_skipped"], 1)
        self.assertEqual(diagnostics["oversized_lines_skipped"], 1)

    def test_utf16_and_utf8_bom(self):
        for encoding in ("utf-16", "utf-8-sig"):
            with self.subTest(encoding=encoding):
                result = analyze([self.write(ssh("2026-01-01T00:00:00Z", FAILED).encode(encoding))])
                self.assertEqual(len(result["events"]), 1)

    def test_explicit_legacy_encoding(self):
        content = ssh("2026-01-01T00:00:00Z", FAILED.replace("demo", "ученик"))
        result = analyze([self.write(content.encode("cp1251"))], encoding="cp1251")
        self.assertEqual(result["events"][0]["user"], "ученик")

    def test_invalid_ip_and_other_services(self):
        content = ssh("Jan 01 00:00:00", FAILED.replace("192.0.2.10", "999.1.1.1"))
        content += "Jan 01 00:00:00 lab other: " + FAILED + "\n"
        self.assertEqual(analyze([self.write(content)])["events"], [])

    def test_size_and_combined_limit(self):
        a = self.write(b"123456", "a.log")
        b = self.write(b"123456", "b.txt")
        for paths, limit in (([a], 5), ([a, b], 10)):
            with self.assertRaises(ValueError):
                analyze(paths, max_bytes=limit)

    def test_input_validation(self):
        path = self.write(b"", "bad.xml")
        with self.assertRaises(ValueError):
            analyze([path])
        path = self.write(b"")
        for options in ({"threshold": 1}, {"window_seconds": 0}, {"year": 0}, {"max_bytes": 0}, {"encoding": "no-such-codec"}):
            with self.subTest(options=options), self.assertRaises((ValueError, LookupError)):
                analyze([path], **options)
        with self.assertRaises(ValueError):
            analyze([path, path])

    def test_offsets(self):
        self.assertEqual(parse_offset("UTC"), timezone.utc)
        for value in ("Europe/Moscow", "+24:00", "+03:60"):
            with self.assertRaises(ValueError):
                parse_offset(value)

    def test_mask_all_exports_and_raw_override(self):
        path = self.write(ssh("2026-01-01T00:00:00Z", FAILED) * 3, "private-demo.log")
        report = analyze([path])
        masked = export_view(report, mask=True, include_raw=True)
        for fmt in ("json", "csv", "markdown"):
            content = serialize(masked, fmt)
            for secret in ("demo", "192.0.2.10", "private-demo", str(self.root)):
                self.assertNotIn(secret, content)
        self.assertIn("raw", report["events"][0])
        self.assertNotIn("raw", export_view(report)["events"][0])
        self.assertIn("raw", export_view(report, include_raw=True)["events"][0])

    def test_mask_sudo_free_text(self):
        path = self.write("2026-01-01T00:00:00Z lab sudo: alice : USER=root ; COMMAND=/bin/echo alice 192.0.2.10\n")
        content = serialize(export_view(analyze([path]), mask=True, include_raw=True), "json")
        for secret in ("alice", "root", "192.0.2.10", "/bin/echo"):
            self.assertNotIn(secret, content)

    def test_csv_formula_and_markdown_injection(self):
        content = ssh("2026-01-01T00:00:00Z", FAILED.replace("demo", "=1+1"))
        report = export_view(analyze([self.write(content)]))
        rows = list(csv.DictReader(io.StringIO(serialize(report, "csv"))))
        self.assertEqual(rows[-1]["user"], "'=1+1")
        report["events"][0]["user"] = "<script>|[link](evil)"
        md = serialize(report, "markdown")
        self.assertNotIn("<script>", md)
        self.assertNotIn("[link]", md)

    def test_files_are_independent(self):
        content = ssh("2026-01-01T00:00:00Z", FAILED) * 2
        result = analyze([self.write(content, "a.log"), self.write(content, "b.log")])
        self.assertEqual(result["repetitions"], [])

    def test_rule_user_command_action_grouping(self):
        content = ssh("2026-01-01T00:00:00Z", FAILED)
        content += ssh("2026-01-01T00:00:01Z", FAILED.replace("demo", "other"))
        content += ssh("2026-01-01T00:00:02Z", SUCCESS)
        self.assertEqual(analyze([self.write(content)], threshold=2)["repetitions"], [])
        content = "2026-01-01T00:00:00Z lab sudo: demo : USER=root ; COMMAND=/usr/bin/id\n"
        content += content.replace("/usr/bin/id", "/usr/bin/true")
        self.assertEqual(analyze([self.write(content)], threshold=2)["repetitions"], [])

    def test_disjoint_windows_bound_evidence(self):
        content = "".join(ssh(f"2026-01-01T00:0{i}:00Z", FAILED) for i in range(5))
        result = analyze([self.write(content)], window_seconds=120)
        self.assertEqual([e["lines"] for e in result["repetitions"]], [[1, 2, 3]])

    def test_sparse_prefix_does_not_hide_later_cluster(self):
        content = ssh("2026-01-01T00:00:00Z", FAILED)
        content += "".join(ssh(f"2026-01-01T00:10:0{i}Z", FAILED) for i in range(3))
        result = analyze([self.write(content)], window_seconds=5)
        self.assertEqual(result["repetitions"][0]["lines"], [2, 3, 4])

    def test_syslog_secure_and_journal_export(self):
        content = ssh("Oct 27 10:00:00", FAILED)
        for name in ("secure", "syslog", "auth.log"):
            with self.subTest(name=name):
                result = analyze([self.write(content, name)], year=2026)
                self.assertEqual(result["events"][0]["rule"], "ssh_failed")
        journal = "2026-10-27T10:00:00.123456+0300 training sshd[42]: " + FAILED
        result = analyze([self.write(journal, "journal.txt")])
        self.assertEqual(result["events"][0]["timestamp"], "2026-10-27T07:00:00.123456+00:00")

    def test_cli_exports_and_no_raw_terminal(self):
        path = self.write(ssh("2026-01-01T00:00:00Z", FAILED))
        before = path.read_bytes()
        for fmt in ("json", "csv", "markdown"):
            output = self.root / f"result.{fmt}"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = main([str(path), "--output", str(output), "--format", fmt, "--mask"])
            self.assertEqual(status, 0)
            self.assertIn("source-1:1", stdout.getvalue())
            self.assertNotIn(FAILED, stdout.getvalue())
            self.assertNotIn("192.0.2.10", output.read_text(encoding="utf-8"))
            if fmt == "json":
                json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(path.read_bytes(), before)

    def test_no_overwrite_and_errors(self):
        path = self.write(b"unchanged")
        target = self.root / "existing.json"
        target.write_bytes(b"keep")
        for args in ([str(path), "--output", str(path)], [str(path), "--output", str(target)],
                     [str(self.root / "missing.log")], [str(path), "--encoding", "invalid"],
                     [str(path), "--max-mib", "nan"]):
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 2)
        self.assertEqual(path.read_bytes(), b"unchanged")
        self.assertEqual(target.read_bytes(), b"keep")

    def test_module_entrypoint(self):
        result = subprocess.run([sys.executable, "-m", "linux_log_triage", "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--mask", result.stdout)


if __name__ == "__main__":
    unittest.main()
