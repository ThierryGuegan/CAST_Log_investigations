#!/usr/bin/env python3
"""Regression tests for analyze_logs.py. Run: python3 tests/run_tests.py (standard library only).

Every case here comes from a bug found in an audit or in real CAST logs; keep them passing
before shipping changes to the script.
"""
import atexit
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "analyze_logs.py"

_TMP_DIRS = []


def _mkdtemp():
    """Temporary folder removed when the test run ends (tests must not litter /tmp)."""
    d = tempfile.mkdtemp(prefix="cast-skill-test-")
    _TMP_DIRS.append(d)
    return d


atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _TMP_DIRS])


def run(files, *args):
    tmp = Path(_mkdtemp())
    for rel, content in files.items():
        p = tmp / "Input" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--input", str(tmp / "Input"),
                        "--output", str(tmp / "Output"), "--json"] + list(args),
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads((tmp / "Output" / "logs_analysis.json").read_text(encoding="utf-8"))
    report = (tmp / "Output" / "logs_analysis_report.md").read_text(encoding="utf-8")
    return data, report


def timing(data, name):
    return next(t for t in data["timeline"] if t["file"].endswith(name))


ENV_LOG = """2026-06-24 13:05:09.123 [INFO] Run analysis
2026-06-24 13:05:09 [INFO] CARL Version: 3.1.26-funcrel (Linux)
2026-06-24 13:05:09 [INFO] CAIP Version: CAST 8.4.10 (Build 2088)
2026-06-24 13:05:09 [INFO] LISA Folder: /usr/share/CAST/CASTMS/LISA/
2026-06-24 13:05:09 [INFO] LTSA Folder: /usr/share/CAST/CASTMS/LTSA/
2026-06-24 13:05:09 [INFO] Connection string: LIBPQ:10.17.25.159:2285,bidc001;user=cast;password=S3cret!
2026-06-24 13:21:44 [INFO] End

"""
ANALYZE_LOG = """2026-06-24 13:00:01 [INFO] start
2026-06-24 13:00:02 [INFO] 'com.castsoftware.angularjs.2.1.24-funcrel' extension is already downloaded
2026-06-24 13:00:02 [INFO] 'com.castsoftware.omg-ascqm-index.20260904.0.0-funcrel' extension is already downloaded
2026-06-24 13:00:02 [INFO] 'com.castsoftware.internal.platform.0.9.36' extension is already downloaded
2026-06-24 13:00:02 [INFO] 'com.castsoftware.webfilesdiscoverer.1.1.3' extension is already downloaded
2026-06-24 13:00:03 [INFO] Downloading extension com.castsoftware.sqlanalyzer version 3.7.24-funcrel
2026-06-24 13:00:03 [INFO] Extension com.castsoftware.jee 1.3.5-funcrel loaded
2026-06-24 13:00:03 [INFO] Installing extension 'com.castsoftware.camel' (version: 1.1.10-funcrel)
2026-06-24 13:00:03 [INFO] Extension com.castsoftware.springmvc is used, com.castsoftware.dummy version 9.9.9 too
2026-06-24 13:00:09 [INFO] Done
"""


class Environment(unittest.TestCase):
    def test_env_fields_and_password_redaction(self):
        data, report = run({"1-run.log": ENV_LOG})
        env = data["environment"]
        self.assertNotIn("S3cret", report)       # also not in quoted log lines (silent periods)
        self.assertEqual(env["CARL Version"], "3.1.26-funcrel (Linux)")
        self.assertEqual(env["CAIP Version"], "CAST 8.4.10 (Build 2088)")
        self.assertIn("password=****", env["Connection string"])
        self.assertNotIn("S3cret", env["Connection string"])
        self.assertIsNone(env["Knowledge Base Schema"])


class Extensions(unittest.TestCase):
    def test_versions_formats_and_hyphenated_names(self):
        data, _ = run({"0-analyze.log": ANALYZE_LOG})
        ext = data["extensions"]
        self.assertEqual(ext["com.castsoftware.angularjs"], "2.1.24-funcrel")
        self.assertEqual(ext["com.castsoftware.omg-ascqm-index"], "20260904.0.0-funcrel")
        self.assertEqual(ext["com.castsoftware.internal.platform"], "0.9.36")
        self.assertEqual(ext["com.castsoftware.webfilesdiscoverer"], "1.1.3")
        self.assertEqual(ext["com.castsoftware.sqlanalyzer"], "3.7.24-funcrel")
        self.assertEqual(ext["com.castsoftware.jee"], "1.3.5-funcrel")
        self.assertEqual(ext["com.castsoftware.camel"], "1.1.10-funcrel")

    def test_version_phrase_not_attached_to_wrong_extension(self):
        data, _ = run({"0-analyze.log": ANALYZE_LOG})
        # two extensions on one line: the "version 9.9.9" phrase must not go to springmvc
        self.assertEqual(data["extensions"]["com.castsoftware.springmvc"], "unknown")


class Timing(unittest.TestCase):
    def test_date_inside_message_is_not_a_start(self):
        data, _ = run({"p1.log": "Collected files\nRestoring backup made 2019-01-01 10:00:00 by admin\n"
                                 "2026-10-01 20:00:00 [INFO] start\n2026-10-01 20:10:00 [INFO] end\n"})
        t = timing(data, "p1.log")
        self.assertEqual(t["start"], "2026-10-01 20:00:00")
        self.assertEqual(t["duration"], "0d 0h 10m 0s")

    def test_edge_case_files(self):
        data, _ = run({
            "single.log": "2026-06-24 13:00:30 [INFO] only line",
            "blank_end.log": "2026-06-24 13:00:00 a\n2026-06-24 13:02:00 b\n\n\n",
            "crlf.log": b"2026-06-24 13:00:00 a\r\n2026-06-24 13:03:00 b\r\n",
            "utf16.log": "2026-06-24 13:08:00 start\nx\n2026-06-24 13:38:12 end\n".encode("utf-16"),
            "notime.log": "CAST-Profiler v1.9.8\nCollecting file list...\n",
        })
        self.assertEqual(timing(data, "single.log")["duration"], "0d 0h 0m 0s")
        self.assertEqual(timing(data, "blank_end.log")["duration"], "0d 0h 2m 0s")
        self.assertEqual(timing(data, "crlf.log")["duration"], "0d 0h 3m 0s")
        self.assertEqual(timing(data, "utf16.log")["duration"], "0d 0h 30m 12s")
        self.assertEqual(timing(data, "notime.log")["duration"], "N/A")
        self.assertEqual(data["total"]["start"], "2026-06-24 13:00:00")
        self.assertEqual(data["total"]["end"], "2026-06-24 13:38:12")


class Silence(unittest.TestCase):
    FILES = {
        "a.log": "2026-10-01 20:00:00 a1\n2026-10-01 21:00:00 a2\n",      # silent 20:00-21:00
        "b.log": "2026-10-01 20:30:00 b1\n2026-10-01 21:30:00 b2\n",      # overlaps partially
        "c.log": "2026-10-01 22:00:00 c1\n2026-10-01 22:05:00 c2\n",      # step after a pause
    }

    def test_partial_overlap_and_between_step_waits(self):
        data, _ = run(self.FILES, "--gap-minutes", "20")
        # lines at 20:00, 20:30, 21:00, 21:30, 22:00, 22:05 -> four 30-minute silences
        self.assertEqual(data["silent_seconds_total"], 4 * 1800)
        last = data["silent_periods"][-1]
        self.assertEqual((last["from"], last["to"]), ("2026-10-01 21:30:00", "2026-10-01 22:00:00"))
        self.assertTrue(last["before_file"].endswith("b.log"))
        self.assertTrue(last["after_file"].endswith("c.log"))

    def test_busy_log_cancels_silence_of_another(self):
        busy = "".join("2026-10-01 20:{:02d}:00 tick\n".format(m) for m in range(0, 60, 2))
        data, _ = run({"wait.log": "2026-10-01 20:00:00 w\n2026-10-01 21:00:00 w\n",
                       "busy.log": busy + "2026-10-01 21:00:00 tick\n"})
        self.assertEqual(data["silent_seconds_total"], 0)
        self.assertEqual(len(data["per_log_silent_stretches"]), 1)   # still shown per log


    def test_out_of_order_timestamps(self):
        lines = ["2026-10-01 20:00:00 start"]
        for _ in range(50):                  # threads interleave: 20:05 / 20:01 back and forth
            lines += ["2026-10-01 20:05:00 x", "2026-10-01 20:01:00 y"]
        lines.append("2026-10-01 20:20:00 end")
        data, _ = run({"mt.log": "\n".join(lines) + "\n"}, "--gap-minutes", "4")
        self.assertEqual([(g["from"], g["to"]) for g in data["per_log_silent_stretches"]],
                         [("2026-10-01 20:05:00", "2026-10-01 20:20:00"),
                          ("2026-10-01 20:00:00", "2026-10-01 20:05:00")])
        self.assertEqual(data["silent_seconds_total"], 20 * 60)
        self.assertEqual(timing(data, "mt.log")["end"], "2026-10-01 20:20:00")


class Redaction(unittest.TestCase):
    def test_redact(self):
        log = ENV_LOG + ("2026-06-24 13:22:00 [INFO] Reading /opt/cast/shared/upload/ACME/src/App.cs "
                         "and /usr/share/CAST/CASTMS/LISA/x.txt host db01.acme.internal "
                         "package Foo version 1.0.0.0\n2026-06-24 13:40:00 [INFO] ACME done\n")
        _, report = run({"1-run.log": log}, "--redact", "--redact-term", "ACME")
        self.assertNotIn("10.17.25.159", report)
        self.assertNotIn("db01.acme.internal", report)
        self.assertNotIn("ACME", report)
        self.assertIn("/usr/share/CAST/CASTMS/LISA/", report)       # CAST paths are kept
        self.assertIn("<path>/App.cs", report)                      # others keep the file name


class Round3(unittest.TestCase):
    def test_out_of_order_line_not_used_as_gap_edge(self):
        log = ("2026-10-01 20:00:00 start\n2026-10-01 20:01:00 latest before wait\n"
               "2026-10-01 20:00:30 late thread line\n2026-10-01 20:30:00 resumed\n")
        data, _ = run({"mt.log": log}, "--gap-minutes", "10")
        g = data["per_log_silent_stretches"][0]
        self.assertIn("latest before wait", g["before"])
        self.assertEqual(g["from"], "2026-10-01 20:01:00")

    def test_input_folder_shown_as_given(self):
        tmp = Path(_mkdtemp())
        (tmp / "Input").mkdir()
        (tmp / "Input" / "a.log").write_text("2026-10-01 20:00:00 x\n")
        r = subprocess.run([sys.executable, str(SCRIPT), "--input", "Input", "--output", "Output"],
                           cwd=str(tmp), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        head = (tmp / "Output" / "logs_analysis_report.md").read_text().split("---")[0]
        self.assertIn("`Input`", head)
        self.assertNotIn(str(tmp), head)                       # no machine-specific path

    def test_space_separated_credentials_in_quoted_lines(self):
        log = ("2026-10-01 17:27:02 [INFO] Running DMT command [java -jar dmt.jar --password baps -user cast]\n"
               "2026-10-01 20:52:46 [INFO] done\n")
        _, report = run({"p.log": log})
        self.assertIn("DMT command", report)                   # the line IS quoted (gap edge)
        self.assertNotIn("baps", report)


class Round4(unittest.TestCase):
    def test_clock_goes_back(self):
        lines = (["2026-10-25 01:50:00 start"] + ["2026-10-25 02:%02d:00 work" % m for m in range(0, 60, 5)] +
                 ["2026-10-25 02:%02d:00 work again" % m for m in range(0, 60, 5)] + ["2026-10-25 03:10:00 end"])
        data, _ = run({"dst.log": "\n".join(lines) + "\n"})
        self.assertEqual(timing(data, "dst.log")["duration"], "0d 2h 20m 0s")
        self.assertTrue(any("clock went back" in w for w in data["warnings"]))

    def test_clock_goes_forward_warning(self):
        data, _ = run({"spring.log": "2026-03-29 01:58:00 a\n2026-03-29 03:01:00 b\n"})
        self.assertTrue(any("daylight-saving" in w for w in data["warnings"]))

    def test_utf16_without_bom(self):
        data, _ = run({"u.log": "2026-10-01 20:00:00 a\n2026-10-01 20:30:00 b\n".encode("utf-16-le")})
        self.assertEqual(timing(data, "u.log")["duration"], "0d 0h 30m 0s")

    def test_real_shape_credentials_in_quoted_lines(self):
        log = ('2026-10-01 20:53:00 [INFO] connectPassword="CRYPTED:CAA9FB4"\n'
               "2026-10-01 21:30:00 [INFO] DB_PASSWORD=envpw -user castadm resumed\n")
        _, report = run({"c.log": log}, "--redact")
        for s in ["CAA9FB4", "envpw", "castadm"]:
            self.assertNotIn(s, report)
        self.assertIn("connectPassword", report)               # the line itself is still quoted


class Round5(unittest.TestCase):
    def test_stray_old_line_is_not_a_clock_change(self):
        lines = (["2026-10-01 20:%02d:00 w" % m for m in range(0, 30, 2)] + ["2026-10-01 19:00:00 replayed summary"] +
                 ["2026-10-01 20:%02d:00 w" % m for m in range(30, 60, 2)])
        data, _ = run({"s.log": "\n".join(lines) + "\n"})
        self.assertEqual(timing(data, "s.log")["duration"], "0d 0h 58m 0s")
        self.assertFalse(any("clock" in w for w in data["warnings"]))

    def test_stray_line_on_changeover_night_needs_confirmation(self):
        lines = (["2026-10-25 02:%02d:00 w" % m for m in range(30, 60, 2)] + ["2026-10-25 01:40:00 replay"] +
                 ["2026-10-25 03:%02d:00 w" % m for m in range(0, 10, 2)])
        data, _ = run({"s.log": "\n".join(lines) + "\n"})
        self.assertEqual(timing(data, "s.log")["duration"], "0d 0h 38m 0s")
        self.assertFalse(any("clock went back" in w for w in data["warnings"]))

    def test_clock_change_end_shown_on_log_clock(self):
        lines = (["2026-10-25 01:50:00 start"] + ["2026-10-25 02:%02d:00 w" % m for m in range(0, 60, 5)] * 2 +
                 ["2026-10-25 03:10:00 end"])
        data, report = run({"dst.log": "\n".join(lines) + "\n"})
        t = timing(data, "dst.log")
        self.assertEqual((t["end"], t["duration"]), ("2026-10-25 03:10:00", "0d 2h 20m 0s"))
        self.assertEqual(data["total"]["end"], "2026-10-25 03:10:00")
        self.assertNotIn("04:10", report)

    def test_long_dotted_line_with_redact(self):
        import time
        log = "2026-10-01 20:00:00 classpath " + "a." * 100000 + "\n2026-10-01 20:30:00 end\n"
        t = time.perf_counter()
        run({"cp.log": log}, "--redact")
        self.assertLess(time.perf_counter() - t, 20)

    def test_mask_mode(self):
        line = '2026-10-01 20:53:00 [INFO] connectPassword="CRYPTED:CAA9FB4" host db01.suez-eau.fr\n'
        r = subprocess.run([sys.executable, str(SCRIPT), "--mask"], input=line, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("CAA9FB4", r.stdout)
        self.assertIn("db01.suez-eau.fr", r.stdout)
        r = subprocess.run([sys.executable, str(SCRIPT), "--mask", "--redact"], input=line,
                           capture_output=True, text=True)
        self.assertNotIn("suez-eau", r.stdout)


def markdown_problems(md):
    """Stdlib-only check that a report renders as written: outside fenced blocks and code
    spans there must be no '<' (renderers drop it as an HTML tag) and no '__' (bold)."""
    problems, in_fence = [], None
    for n, line in enumerate(md.splitlines(), 1):
        f = re.match(r"^(`{3,})", line)
        if f:
            in_fence = None if in_fence and f.group(1).startswith(in_fence) else (in_fence or f.group(1))
            continue
        if in_fence:
            continue
        if line.count("`") % 2:
            problems.append((n, "unclosed code span", line))
        bare = re.sub(r"`[^`]*`", "", line)
        if "<" in bare.replace("\\<", "") or "__" in bare.replace("\\_", ""):
            problems.append((n, "markdown-active text", line))
    return problems


class Round6(unittest.TestCase):
    def test_report_renders_as_written(self):
        files = {"1-run.log": ENV_LOG, "0-analyze.log": ANALYZE_LOG,
                 "sub/*_Dataset__init__.log": "2026-10-01 20:00:00 a\n",
                 "q.log": "2026-10-01 20:00:00 [INFO] List<string> __init__ <<hidden value>>\n"
                          "2026-10-01 20:30:00 [INFO] password=S3cretPassw0rdThatIsLongEnoughToBeCutAtTheReportWidth"
                          "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"}
        for args in ((), ("--redact",)):
            _, report = run(files, *args)
            self.assertEqual(markdown_problems(report), [], args)

    def test_windows_console_encoding(self):
        tmp = Path(_mkdtemp())
        (tmp / "Input" / "完了").mkdir(parents=True)
        (tmp / "Input" / "完了" / "a.log").write_text("2026-10-01 20:00:00 [WARNING] ✓ x\n", encoding="utf-8")
        env = dict(os.environ, PYTHONIOENCODING="cp1252")
        r = subprocess.run([sys.executable, str(SCRIPT), "--input", "Input", "--output", "Out完了"],
                           cwd=str(tmp), capture_output=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr.decode("utf-8", "replace"))
        r = subprocess.run([sys.executable, str(SCRIPT), "--mask"], input="✓ 完了 password=x\n".encode("utf-8"),
                           capture_output=True, env=env)
        self.assertEqual((r.returncode, r.stdout.decode("utf-8")), (0, "✓ 完了 password=****\n"))


class Round7(unittest.TestCase):
    def test_output_same_as_input_is_refused(self):
        tmp = Path(_mkdtemp())
        (tmp / "Input").mkdir()
        (tmp / "Input" / "a.log").write_text("2026-10-01 20:00:00 x\n")
        r = subprocess.run([sys.executable, str(SCRIPT), "--input", "Input", "--output", "Input"],
                           cwd=str(tmp), capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("must be a different folder", r.stderr)


class Round9(unittest.TestCase):
    def test_windows_1252_log_in_report(self):
        log = ("2026-10-01 20:00:00 [INFO] Démarrage de l'analyse\n"
               "2026-10-01 20:30:00 [INFO] Terminé\n").encode("cp1252")
        data, report = run({"fr.log": log})
        self.assertNotIn("\ufffd", report)
        self.assertIn("Terminé", report)                       # quoted at the silent period's edge
        self.assertEqual(timing(data, "fr.log")["duration"], "0d 0h 30m 0s")

    def test_mask_mode_windows_1252(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--mask"], input="Terminé password=x\n".encode("cp1252"),
                           capture_output=True)
        self.assertEqual((r.returncode, r.stdout.decode("utf-8")), (0, "Terminé password=****\n"))


class Round10(unittest.TestCase):
    def test_concatenated_logs_keep_their_timestamps(self):
        log = "\ufeff2026-10-01 20:00:00 a\n".encode() + "\ufeff2026-10-01 20:45:00 b\n".encode()
        data, _ = run({"cat.log": log})
        self.assertEqual(timing(data, "cat.log")["duration"], "0d 0h 45m 0s")


class RealRuns(unittest.TestCase):
    def test_silence_tables_are_capped_on_long_runs(self):
        lines = ["2026-04-14 %02d:%02d:00 x" % (h, m) for h in range(0, 24) for m in (0, 10, 20)]   # 10-min gaps
        data, report = run({"long.log": "\n".join(lines) + "\n"}, "--top-silences", "5")
        self.assertEqual(len(data["silent_periods"]), len(lines) - 1)                # JSON: every period
        sec = report.split("## Silent Periods")[1].split("###")[0]
        self.assertEqual(sec.count("\n| 2026"), 5)
        self.assertIn("silent periods; the 5 longest are shown", sec)
        self.assertIn("full list is in logs_analysis.json", sec)
        total = sum(g["seconds"] for g in data["silent_periods"])
        self.assertEqual(total, data["silent_seconds_total"])                        # total counts all

    def test_no_spring_warning_in_april(self):
        data, _ = run({"sql.log": "2026-04-19 01:16:15 a\n2026-04-19 02:17:00 b\n"})       # a Sunday in April
        self.assertFalse(any("daylight-saving" in w for w in data["warnings"]))

    def test_empty_step_log_is_reported_as_empty(self):
        data, _ = run({"19-externallink-for-technology-html5.log": "", "a.log": "2026-10-01 20:00:00 x\n"})
        self.assertTrue(any(w.startswith("Empty log file") and "19-externallink" in w for w in data["warnings"]))
        self.assertFalse(any(w.startswith("No line starting") for w in data["warnings"]))


class RunStatus(unittest.TestCase):
    def _status(self, files):
        data, report = run(files)
        return data["run_status"], report.split("## Run Status")[1].split("\n---\n")[0]

    def test_completed(self):
        st, sec = self._status({"1-cast-ms-runanalysis-1.log": "2026-01-01 10:00:00 [INFO] go\n"
                                                              "2026-01-01 10:30:00 [INFO] Return value: 0\n"})
        self.assertEqual(st["status"], "Completed")
        self.assertIn("**Completed**", sec)

    def test_failed(self):
        st, sec = self._status({"1-cast-ms-runanalysis-1.log": "2026-01-01 10:00:00 [INFO] go\n"
                                                              "2026-01-01 10:30:00 [INFO] Return value: 3\n"})
        self.assertEqual((st["status"], st["return_value"]), ("Failed", 3))
        self.assertIn("Failed", sec)

    def test_did_not_finish_names_the_last_tasks(self):
        st, sec = self._status({
            "0-analyze.log": "2026-01-01 10:00:00 starting Task Run SQL Analyzer \"db\"\n"
                             "starting Task Run J2EE Analyzer \"unit_1\"\nstarting Task Clean dependency dataset\n",
            "1-cast-ms-runanalysis-1.log": "2026-01-01 10:00:00 [INFO] go\n2026-01-01 10:20:00 [INFO] still going\n"})
        self.assertEqual(st["status"], "Did not finish")
        self.assertEqual(st["last_tasks"], ['Run J2EE Analyzer "unit_1"', "Clean dependency dataset"])
        self.assertIn("Did not finish", sec)
        self.assertIn("2026-01-01 10:20:00", sec)

    def test_failed_snapshot_fails_the_run(self):
        files = {"analyze/0-analyze.log": "2026-01-01 10:00:00 a\n2026-01-01 10:30:00 Return value: 0\n",
                 "analyze/1-cast-ms-runanalysis-1.log": "2026-01-01 10:00:00 go\n2026-01-01 10:30:00 Return value: 0\n",
                 "snapshot/0-snapshot.log": "2026-01-01 10:31:00 s\n2026-01-01 10:40:00 Return value: 1\n",
                 "exclude_files/0-exclude-files.log": "2026-01-01 09:59:00 e\n"}
        st, sec = self._status(files)
        self.assertEqual((st["status"], st["failed_phases"]), ("Failed", ["snapshot"]))
        self.assertIn("phase `snapshot` returned 1", sec)
        results = {ph["phase"]: ph["result"] for ph in st["phases"]}
        self.assertEqual(results, {"exclude-files": "not logged", "analyze": "OK", "snapshot": "Failed"})
        self.assertEqual([ph["phase"] for ph in st["phases"]], ["exclude-files", "analyze", "snapshot"])  # by start

    def test_unfinished_analysis_row_is_flagged(self):
        files = {"0-analyze.log": "2026-01-01 10:00:00 starting Task Run X\n",
                 "1-cast-ms-runanalysis-1.log": "2026-01-01 10:00:00 go\n"}
        st, sec = self._status(files)
        self.assertEqual(st["status"], "Did not finish")
        self.assertIn("no return value** (did not finish)", sec)

    def test_phase_without_timestamps_is_ordered_by_its_folder(self):
        files = {"deliver/0-deliver.log": "INF: 2026-09-26 00:50:46: d\r\nINF: 2026-09-26 00:51:18: Return value: 0\r\n",
                 "accept/0-accept.log": "Using arguments:\r\n\tacceptDelivery\r\nReturn value: 0\r\n",
                 "accept/1-acceptdelivery.log": "INF: 2026-09-26 00:51:25: a\r\n",
                 "analyze/0-analyze.log": "INF: 2026-09-26 00:59:46: x\r\nINF: 2026-09-26 01:30:00: Return value: 0\r\n",
                 "analyze/1-cast-ms-runanalysis-1.log": "INF: 2026-09-26 00:59:49: go\r\nINF: 2026-09-26 01:29:00: Return value: 0\r\n"}
        st, _ = self._status(files)
        self.assertEqual([ph["phase"] for ph in st["phases"]], ["deliver", "accept", "analyze"])

    def test_execution_summary(self):
        base = {"analyze/0-analyze.log": "INF: 2026-09-26 00:59:46: x\r\nINF: 2026-09-26 01:30:00: Return value: 0\r\n",
                "analyze/1-cast-ms-runanalysis-1.log": "INF: 2026-09-26 00:59:49: go\r\nINF: 2026-09-26 01:29:00: Return value: 0\r\n"}
        ok = dict(base, **{"analyze/15-execution-summary.log": "Status: Execution succeeded\r\n\r\nStart: Sat Sep 26 01:00:11 CEST 2026\r\n"})
        st, sec = self._status(ok)
        self.assertEqual((st["status"], st["summary"]["status"]), ("Completed", "Execution succeeded"))
        self.assertIn("CAST execution summary: `Execution succeeded`", sec)
        bad = dict(base, **{"analyze/15-execution-summary.log": "Status: Execution failed\r\n"})
        st, sec = self._status(bad)
        self.assertEqual(st["status"], "Failed")
        self.assertIn("the execution summary says `Execution failed`", sec)

    def test_unknown_without_run_analysis_log(self):
        st, _ = self._status({"a.log": "2026-01-01 10:00:00 x\n"})
        self.assertEqual(st["status"], "Unknown")


class Cast83Formats(unittest.TestCase):
    TRAIL = "\t0 ; 0\t0\t\t0\t[Module name]\t0\t0\t\t"

    def test_orchestration_timestamps(self):
        log = "INF: 2026-09-26 00:59:46: Running analysis\r\nUsing arguments:\r\nINF: 2026-09-26 01:29:46: Return value: 0\r\n"
        data, _ = run({"analyze/1-cast-ms-runanalysis-1.log": log})
        self.assertEqual(timing(data, "runanalysis-1.log")["duration"], "0d 0h 30m 0s")
        self.assertEqual(data["run_status"]["status"], "Completed")

    def test_environment_without_carl(self):
        data, _ = run({"analyze/0-analyze.log": "INF: 2026-09-26 00:59:46: x\r\n   -connectionProfile: acme_mngt on CastStorageService _ dbsrv:5432\r\n",
                       "analyze/10-metrics.log": " 2026-09-30 09:29:02.705439\tInformation\tMODULMSG ; Job execution\tCAIP Version: CAST 8.3.50 ( Build 10723 )" + self.TRAIL + "\n"})
        env = data["environment"]
        self.assertEqual(env["CAIP Version"], "CAST 8.3.50 ( Build 10723 )")          # stops at the tab
        self.assertEqual(env["Connection string"], "acme_mngt on CastStorageService _ dbsrv:5432")
        self.assertIsNone(env["CARL Version"])
        self.assertTrue(data["environment_source"].endswith("10-metrics.log"))

    def test_explicit_connection_string_wins(self):
        data, _ = run({"0-analyze.log": "2026-01-01 10:00:00 -connectionProfile: p on CastStorageService _ h:1\n",
                       "9-x.log": "2026-01-01 10:00:00 [INFO] CARL Version: 3.2.6\n2026-01-01 10:00:00 [INFO] Connection string: LIBPQ:h:2285,postgres\n"})
        self.assertEqual(data["environment"]["Connection string"], "LIBPQ:h:2285,postgres")

    def test_extensions_from_plugin_paths_and_install_list(self):
        E = r"E:\\Prog\\Cast\\Programdata\\CAST\\CAST\\Extensions"
        files = {"analyze/0-analyze.log": "INF: 2026-09-26 00:59:46: starting Task Run extensions before analysis\r\n",
                 "analyze/3-ua.log": f" 2026-09-26 01:15:42.878491\tInformation\tMODULMSG ; Job execution\t[com.castsoftware.php] Plugin Directory: {E}\\com.castsoftware.php.1.6.2-funcrel\\x" + self.TRAIL + "\n"
                                     f" 2026-09-26 01:15:43.000000\tInformation\tMODULMSG ; Job execution\tload {E}\\com.castsoftware.nodejs.2.11.0-funcrel\\a.py" + self.TRAIL + "\n",
                 "install_extensions/2-servman.log": "extensions file dump :\r\n\r\ncom.castsoftware.sqlanalyzer=3.8.3-funcrel\r\n"
                                                     "com.castsoftware.nodejs ( 1.0.0.0   - UpToDate )\r\n"
                                                     "com.castsoftware.internal.platform.ADG ( 1.0.0   - UpToDate )\r\n"}
        data, _ = run(files)
        self.assertEqual(data["extensions"], {"com.castsoftware.nodejs": "2.11.0-funcrel",          # not 1.0.0.0
                                              "com.castsoftware.php": "1.6.2-funcrel",
                                              "com.castsoftware.sqlanalyzer": "3.8.3-funcrel"})  # no components

    def test_extension_names_from_log_tags(self):
        t = self.TRAIL
        files = {"analyze/0-analyze.log": "INF: 2026-09-19 01:04:43: starting Task Run extensions before analysis\r\n",
                 "analyze/3-ua.log": " 2026-09-19 01:15:42.878491\tInformation\tMODULMSG ; Job execution\t[com.castsoftware.php] Analyzing x" + t + "\n"
                                     " 2026-09-19 01:15:43.000000\tWarning\tMODULMSG ; Job execution\t[com.castsoftware.sqlanalyzer] y" + t + "\n"
                                     " 2026-09-19 01:15:44.000000\tInformation\tMODULMSG ; Job execution\tload E:\\CAST\\Extensions\\com.castsoftware.php.3.1.2-funcrel\\a.py" + t + "\n"}
        data, _ = run(files)
        self.assertEqual(data["extensions"], {"com.castsoftware.php": "3.1.2-funcrel", "com.castsoftware.sqlanalyzer": "unknown"})

    def test_redaction_happens_before_truncation(self):
        line = "INF: 2026-09-26 01:00:00: " + "x" * 85 + " connect castlin02.lan.itr.acme:5432\r\n"
        _, report = run({"a.log": line + "INF: 2026-09-26 02:00:00: next\r\n"}, "--redact")
        self.assertNotIn("castlin02", report)


# >>> shared-redaction tests: keep identical in both skills' tests/run_tests.py
import hashlib as _hashlib
import importlib.util as _ilu

SHARED_BLOCK_SHA = "7568b60f3fc4204d"   # update in BOTH skills when the shared block changes
REDACTION_SAMPLE = (r"-password Hunter2 --password baps --pwd=x1 Authorization: Bearer eyJabc.def "
                    r"password=S3c; Unexpected token: '}' api_key=K9 host db01.suez-eau.fr "
                    r"unc \\fileserver01\share\ACME\App.cs Connection string: LIBPQ:pgprod-bidc01:5432,castdb "
                    r"Server=sql01;Database=x jdbc:postgresql://dbhost:5432/cast https://doc.castsoftware.com/x "
                    r"System.IO version 1.0.0.0 at 10.1.2.3 /usr/share/CAST/Extensions/x.py "
                    r"/opt/cast/upload/BAPS/A.cs C:\Users\jdoe\src\B.cs "
                    # round 4: quoted / JSON / XML / env-style / camelCase / YAML / CAST-encrypted
                    r"password=\"my secret\" '\"password\": \"jsonpw\"' <password>xmlpw</password> "
                    r"DB_PASSWORD=envpw PGPASSWORD=pgpw CAST_TOKEN=tok7 secret_key: yamlpw "
                    r"connectPassword=\"CRYPTED:CAA9FB4\" pwd=ab;cd -user castadm User ID=sqluser "
                    # must stay readable (all seen in real CAST logs)
                    r"[mscorlib]System.Security.Cryptography.PasswordDeriveBytes.+ctor(x) "
                    r"System.IdentityModel.Tokens.Jwt.JwtPayload Token(Token.Generic,'Uri',1,2) "
                    r"closing dn-sendcredentials Culture=neutral, PublicKeyToken=b77a5c561934e089")
MUST_GO = ["Hunter2", "baps", "x1", "eyJabc", "S3c", "K9", "suez-eau", "fileserver01", "ACME",
           "pgprod-bidc01", "sql01", "dbhost", "10.1.2.3", "/opt/cast", "jdoe",
           "my secret", "jsonpw", "xmlpw", "envpw", "pgpw", "tok7", "yamlpw", "CAA9FB4", ";cd",
           "castadm", "sqluser"]
MUST_STAY = ["Unexpected token: '}'", "doc.castsoftware.com", "System.IO", "version 1.0.0.0",
             "/usr/share/CAST/Extensions/x.py", "<path>/A.cs", "<path>\\B.cs", "<path>\\App.cs",
             "PasswordDeriveBytes.+ctor(x)", "Tokens.Jwt.JwtPayload", "Token(Token.Generic,'Uri',1,2)",
             "dn-sendcredentials", "PublicKeyToken=b77a5c561934e089"]


def _load_script():
    spec = _ilu.spec_from_file_location("skill_script", str(SCRIPT))
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SharedRedaction(unittest.TestCase):
    def test_block_unchanged(self):
        src = SCRIPT.read_text(encoding="utf-8")
        block = src[src.index("# >>> shared-redaction"):src.index("# <<< shared-redaction")]
        self.assertEqual(_hashlib.sha256(block.encode("utf-8")).hexdigest()[:16], SHARED_BLOCK_SHA,
                         "shared redaction block changed: apply the same edit to the other skill's "
                         "script, then update SHARED_BLOCK_SHA in both test files")

    def test_masking_cases(self):
        m = _load_script()
        out = m.redact_text(m.mask_secrets(REDACTION_SAMPLE), ["ACME"], True)
        for s in MUST_GO:
            self.assertNotIn(s, out)
        for s in MUST_STAY:
            self.assertIn(s, out)
        secrets_only = m.mask_secrets(REDACTION_SAMPLE)          # without --redact
        for s in ["Hunter2", "baps", "eyJabc", "S3c", "K9", "my secret", "jsonpw", "xmlpw", "envpw",
                  "pgpw", "tok7", "yamlpw", "CAA9FB4", ";cd"]:
            self.assertNotIn(s, secrets_only)
        self.assertIn("suez-eau.fr", secrets_only)               # hosts only masked with --redact
        self.assertIn("castadm", secrets_only)                   # user names only with --redact

    def test_terms_never_mangle_placeholders(self):
        m = _load_script()
        out = m.redact_text("/opt/x/y/A.cs at 10.0.0.1 for ACME", ["path", "ip", "host", "ACME"], True)
        self.assertEqual(out, "<path>/A.cs at <ip> for <redacted>")

    def test_code_is_not_a_secret(self):
        m = _load_script()
        for code in ["password = self.connection_password", "token = parser.next_token()",
                     'cnx = connect(host, password=get_secret("db"))', "x = read(password_file)"]:
            self.assertEqual(m.mask_secrets(code), code)
        self.assertEqual(m.mask_secrets('conn = connect(password="Hunter2")'), 'conn = connect(password="****")')

    def test_map_strings_keeps_counters(self):
        import collections
        m = _load_script()
        self.assertEqual(dict(m.map_strings(collections.Counter({"a.log": 3}), str.upper)), {"A.LOG": 3})

    def test_long_lines_stay_linear(self):
        import time
        m = _load_script()
        for unit in ("a.", "a-", "-a", "a/", "a:"):
            t = time.perf_counter()
            m.redact_text(m.mask_secrets(unit * 100000 + " password=x"), ["ACME"], True)
            self.assertLess(time.perf_counter() - t, 3.0, "quadratic pattern on %r" % unit)

    def test_passwords_shaped_like_code_are_masked(self):
        m = _load_script()
        for line, secret in [("-password Pass(word)1", "word)1"), ("pwd=Tr0ub4dor(3)", "4dor"),
                             ("password=P@ss(1)", "ss(1"), ("password=Summer.Rain", "Rain"),
                             ("--password Admin.Secure", "Secure"), ("connectPassword=Winter.Is.Coming", "Coming")]:
            self.assertNotIn(secret, m.mask_secrets(line), line)

    def test_masking_is_idempotent_and_keeps_report_syntax(self):
        m = _load_script()
        once = m.mask_secrets("| x | `pwd=S3cret!` | y |")
        self.assertEqual(once, "| x | `pwd=****` | y |")                  # backtick and pipe kept
        self.assertEqual(m.mask_secrets(once), once)
        cut = "| `password=***` |"                                          # cut at the report width
        self.assertEqual(m.mask_secrets(cut), cut)

    def test_windows_1252_and_mixed_files(self):
        m = _load_script()
        p = Path(_mkdtemp()) / "mixed.log"
        p.write_bytes("Démarrage réussi\n".encode("utf-8") + "Fichier non trouvé\r\n".encode("cp1252")
                      + "Terminé ✓\n".encode("utf-8"))
        self.assertEqual(list(m.read_lines(p)), ["Démarrage réussi", "Fichier non trouvé", "Terminé ✓"])
        b = "\ufeffÉlément\n".encode("utf-8")
        q = Path(_mkdtemp()) / "bom.log"
        q.write_bytes(b)
        self.assertEqual(list(m.read_lines(q)), ["Élément"])
        self.assertEqual(m.decode_text("Terminé".encode("cp1252")), "Terminé")

    def test_oem_code_page_and_byte_order_marks(self):
        m = _load_script()
        for enc, text in [("cp850", "Terminé avec succès"), ("cp850", "Échec : fichier non trouvé"),
                          ("cp1252", "Étape 1 – terminée… à l’heure"), ("cp1252", "l’analyse – done…"),
                          ("cp1252", "Fichier non trouvé"), ("utf-8", "Terminé ✓")]:
            self.assertEqual(m.decode_line(text.encode(enc)), text, enc)
        p = Path(_mkdtemp()) / "cat.log"                    # two logs concatenated on Windows
        p.write_bytes("\ufeffa\n".encode() + "\ufeffb\n".encode())
        self.assertEqual(list(m.read_lines(p)), ["a", "b"])

    def test_windows_paths_with_forward_slashes(self):
        m = _load_script()
        self.assertEqual(m.redact_text("c:/cast-node/common-data/upload/ACME/main/App.java", ["ACME"], True),
                         "<path>/App.java")
        cast = "C:/ProgramData/CAST/CAST/Extensions/com.castsoftware.jee.2.0.19-funcrel/x.py"
        self.assertEqual(m.redact_text(cast, [], True), cast)

    def test_private_hosts_with_ports(self):
        m = _load_script()
        cases = {"acme_mngt on CastStorageService _ dbsrv02.lan.itr.acme:5432": "acme_mngt on CastStorageService _ <host>:5432",
                 "-CONNECT_LOCAL('PostgreSQL','//dbsrv02.lan.itr.acme:5432/postgres')": "-CONNECT_LOCAL('PostgreSQL','//<host>:5432/postgres')",
                 "jdbc:postgresql://dbsrv02.lan.itr.acme:5432/db": "jdbc:postgresql://<host>:5432/db",
                 "connect to dbsrv02.lan.itr.acme:5432 failed": "connect to <host>:5432 failed"}
        for src, want in cases.items():
            self.assertEqual(m.redact_text(src, [], True), want)
        for keep in ("analyser.py:492", "formsreport_symbols/__init__.py:1713", "com.acme.billing.Foo:12"):
            self.assertEqual(m.redact_text(keep, [], True), keep)
# <<< shared-redaction tests


if __name__ == "__main__":
    unittest.main(verbosity=2)
