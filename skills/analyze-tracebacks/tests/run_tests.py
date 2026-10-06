#!/usr/bin/env python3
"""Regression tests for analyze_tracebacks.py. Run: python3 tests/run_tests.py (standard library only).

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

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "analyze_tracebacks.py"

_TMP_DIRS = []


def _mkdtemp():
    """Temporary folder removed when the test run ends (tests must not litter /tmp)."""
    d = tempfile.mkdtemp(prefix="cast-skill-test-")
    _TMP_DIRS.append(d)
    return d


atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _TMP_DIRS])
E = "/usr/share/CAST/Extensions"
W = r"C:\ProgramData\CAST\CAST\Extensions"


def run(files, *args, out=None):
    tmp = Path(_mkdtemp())
    out = out or tmp / "Output"
    for rel, content in files.items():
        p = tmp / "Input" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--input", str(tmp / "Input"), "--output", str(out)]
                       + list(args), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads((out / "tracebacks.json").read_text(encoding="utf-8"))
    report = (out / "tracebacks_report.md").read_text(encoding="utf-8")
    return data, report, out


def group(data, label_start):
    return next(g for g in data["groups"] if g["label"].startswith(label_start))


def forms_tb(i):
    return f"""2026-06-24 13:10:{i:02d} [TRACEBACK] Extension com.castsoftware.formsreport has encountered an issue :
During start_file on File(/src/app/Test{i}_Dataset.xml)
Traceback (most recent call last):
  File "/usr/share/CAST/Python/Lib/site-packages/cast/analysers/internal/plugin.py", line 125, in call_extensions2
    plugin._call_extension2(className, methodName, parameter)
  File "{E}/com.castsoftware.formsreport.1.0.4-funcrel/analyser.py", line 492, in first_pass
    module_name = rdf_xml_module.attributes['name'].text
KeyError: 'name'
2026-06-24 13:10:{i:02d} [INFO] continuing
"""


def sql_tb(ln):
    return f"""2026-06-24 13:08:00 [TRACEBACK] [com.castsoftware.sqlanalyzer] SQL-002: Parsing issue between line {ln} and line {ln+7} : Traceback (most recent call last):
  File "{E}/com.castsoftware.sqlanalyzer.3.7.24-funcrel/sqlscript_parser/__init__.py", line 6311, in create_type_header
    or object_of.type_header_is_wrapped):
AttributeError: 'Synonym' object has no attribute 'type_header_is_wrapped'
"""


CHAINED = f"""2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport] Traceback (most recent call last):
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport]   File "{E}/com.castsoftware.formsreport.1.0.4-funcrel/util.py", line 10, in load
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport]     data = cache[key]
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport] KeyError: 'k1'
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport]
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport] During handling of the above exception, another exception occurred:
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport]
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport] Traceback (most recent call last):
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport]   File "{E}/com.castsoftware.formsreport.1.0.4-funcrel/util.py", line 14, in load
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport]     raise RuntimeError("cache miss for " + key)
2026-06-24 13:12:00 [INFO] [com.castsoftware.formsreport] RuntimeError: cache miss for k1
2026-06-24 13:12:01 [INFO] next
"""


class Counting(unittest.TestCase):
    def test_formats_counts_grouping(self):
        log = "".join(forms_tb(i) for i in range(5)) + CHAINED + \
            "2026-06-24 13:13:00 [TRACEBACK] [com.castsoftware.formsreport] FORMSREPORT-009: header only\n" + \
            "2026-06-24 13:14:00 [INFO] end\n"
        data, report, _ = run({"forms.log": log, "sql.log": "".join(sql_tb(n) for n in (1401, 1502, 1603))})
        self.assertEqual(sum(data["per_file"].values()), 9)            # 5 + 1 chained + 3; not doubled
        self.assertEqual(sum(g["count"] for g in data["groups"]), 9)
        k = group(data, "KeyError: 'name'")
        self.assertEqual((k["count"], k["block"], k["error_code"]), (5, "start_file", ""))
        self.assertEqual(k["extension"], "com.castsoftware.formsreport.1.0.4-funcrel")
        s = group(data, "AttributeError: 'Synonym'")
        self.assertEqual((s["count"], s["error_code"]), (3, "SQL-002"))   # line numbers normalized
        r = group(data, "RuntimeError")
        self.assertEqual(r["chain"], ["KeyError: 'k1'"])
        self.assertEqual(sum(data["stray_headers"].values()), 1)
        self.assertEqual(report.count("TRIGGER_TODO"), 3)

    def test_bare_word_traceback_does_not_swallow_next_header(self):
        log = """2026-07-01 09:00:06 [INFO] Traceback logging enabled for jee
2026-07-01 09:00:07 [TRACEBACK] Extension com.castsoftware.jee has encountered an issue :
Traceback (most recent call last):
  File "/x/Python/Lib/site-packages/cast/analysers/internal/plugin.py", line 85, in _broadcast
    plugin._call_broadcast(broadcasterName, eventName, parameter)
cast.analysers.InternalError: broadcast failed
2026-07-01 09:30:00 [INFO] end
"""
        data, _, _ = run({"jee.log": log})
        self.assertEqual(len(data["groups"]), 1)
        self.assertEqual(data["groups"][0]["extension"], "com.castsoftware.jee (version unknown)")

    def test_windows_crlf_stdlib_frame_and_truncation(self):
        win = f"""2026-07-01 09:00:05 [TRACEBACK] [com.castsoftware.jee] JEE-014: Issue while reading descriptor
Traceback (most recent call last):
  File "{W}\\com.castsoftware.jee.1.3.5-funcrel\\analyser\\descriptor.py", line 88, in read
    root = ET.parse(path)
  File "C:\\Program Files\\CAST\\8.4\\ThirdParty\\Python\\Lib\\xml\\etree\\ElementTree.py", line 1218, in parse
    tree.parse(source, parser)
xml.etree.ElementTree.ParseError: not well-formed (invalid token): line 3, column 7
2026-07-01 09:30:00 [INFO] end
""".replace("\n", "\r\n").encode()
        trunc = f"""2026-07-01 10:00:01 [TRACEBACK] [com.castsoftware.jee] JEE-014: Issue
Traceback (most recent call last):
  File "{E}/com.castsoftware.jee.1.3.5-funcrel/analyser/descriptor.py", line 88, in read
    root = ET.parse(path)
"""
        data, _, _ = run({"a/jee.log": win, "b/jee.log": trunc})
        p = group(data, "xml.etree.ElementTree.ParseError")
        self.assertTrue(p["source"].endswith("ElementTree.py:1218"))
        self.assertTrue(p["extension_source"].endswith("descriptor.py:88"))
        self.assertEqual(p["error_code"], "JEE-014")
        self.assertEqual(group(data, "UnknownError")["count"], 1)
        self.assertEqual(len(data["per_file"]), 2)                       # same name, two folders

    def test_real_cast_format_and_hyphenated_extension(self):
        log = f"""2026-10-01 20:54:27.965 [INFO] [com.castsoftware.dotnetweb] mvc application found
2026-10-01 20:54:27.966 [INFO] [com.castsoftware.dotnetweb] Traceback (most recent call last):
  File "{E}/com.castsoftware.omg-ascqm-index.20260904.0.0-funcrel/analyser_dotnet.py", line 791, in decode_config
    for routes in element.elements[0].elements:
AttributeError: 'NoneType' object has no attribute 'elements'
2026-10-01 20:54:27.966 [INFO] [com.castsoftware.dotnetweb] start type Type(X)
"""
        data, _, _ = run({"x.log": log})
        g = data["groups"][0]
        self.assertEqual(g["extension"], "com.castsoftware.omg-ascqm-index.20260904.0.0-funcrel")
        self.assertEqual(g["raised_code"], "for routes in element.elements[0].elements:")


class Attribution(unittest.TestCase):
    def test_interleaved_threads(self):
        x = f"{E}/com.castsoftware.camel.1.1.10-funcrel"
        log = f"""2026-10-01 20:00:00 [INFO] [111] [TRACEBACK] [com.castsoftware.camel] CAMEL-001: x Traceback (most recent call last):
2026-10-01 20:00:00 [INFO] [222] [TRACEBACK] [com.castsoftware.camel] CAMEL-002: y Traceback (most recent call last):
  File "{x}/a.py", line 1, in fa
    a()
KeyError: 'a'
ValueError: b
2026-10-01 20:00:01 [INFO] [1] next
"""
        data, report, _ = run({"t.log": log})
        self.assertEqual(sum(data["per_file"].values()), 2)
        codes = sorted(g["error_code"] for g in data["groups"])
        self.assertEqual(codes, ["CAMEL-001", "CAMEL-002"])
        self.assertTrue(all(g["interleaved_count"] == 1 for g in data["groups"]))
        self.assertIn("interleaved", report)

    def test_thread_ids_route_prefixed_lines(self):
        x = f"{E}/com.castsoftware.camel.1.1.10-funcrel"
        log = f"""2026-10-01 20:00:00 [INFO] [1] Traceback (most recent call last):
2026-10-01 20:00:00 [INFO] [2] Traceback (most recent call last):
2026-10-01 20:00:00 [INFO] [1]   File "{x}/one.py", line 1, in f1
2026-10-01 20:00:00 [INFO] [2]   File "{x}/two.py", line 2, in f2
2026-10-01 20:00:00 [INFO] [2] TypeError: two
2026-10-01 20:00:00 [INFO] [1] KeyError: 'one'
2026-10-01 20:00:01 [INFO] [1] next
"""
        data, _, _ = run({"t.log": log})
        self.assertEqual(group(data, "KeyError")["short_source"], "one.py:1")
        self.assertEqual(group(data, "TypeError")["short_source"], "two.py:2")

    def test_no_false_error_code(self):
        log = f"""2026-10-01 20:00:00 [TRACEBACK] Extension com.castsoftware.camel has encountered an issue reading ISO-8859: bad byte
Traceback (most recent call last):
  File "{E}/com.castsoftware.camel.1.1.10-funcrel/c.py", line 3, in fc
    c()
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe9
"""
        data, _, _ = run({"t.log": log})
        self.assertEqual(data["groups"][0]["error_code"], "")

    def test_foreign_line_is_not_raising_code(self):
        log = f"""2026-10-01 20:00:00 [INFO] [com.castsoftware.camel] Traceback (most recent call last):
  File "{E}/com.castsoftware.camel.1.1.10-funcrel/d.py", line 4, in fd
2026-10-01 20:00:00 [INFO] [com.castsoftware.jee] start type Type(Foo)
    d()
TypeError: bad
"""
        data, _, _ = run({"t.log": log})
        self.assertEqual(data["groups"][0]["raised_code"], "d()")


class Warnings(unittest.TestCase):
    def test_grouping(self):
        lines = []
        for pkg, ver in [("Amr.Bus", "2.0.1"), ("Amr.Bus.RabbitMQ", "2.0.1"), ("FakeItEasy", "7.3.1"),
                         ("RemoteReadingSystem.Contracts.Metering", "1.0.0.0")]:
            lines.append("2026-10-01 20:54:00 [WARNING] DOTNET.0142:No ressource found for nuget package "
                         f"{pkg} version {ver}. The corresponding package reference of project /opt/x/A.csproj")
        for name in ("Amr", "RabbitConnector", "System.Runtime"):
            lines.append(f"2026-10-01 20:54:01 [WARNING] DOTNET.0150:No definition found for the name '{name}'. "
                         "Therefore no link will be drawn to that object.")
        lines.append("2026-10-01 20:54:02 [ERROR] Something broke")
        lines.append("2026-10-01 20:54:03 [INFO] [1] normal line")
        data, report, _ = run({"w.log": "\n".join(lines) + "\n"})
        pr = data["problems"]
        self.assertEqual(pr["totals"], {"WARNING": 7, "ERROR": 1})
        by_code = {g["code"]: g for g in pr["groups"] if g["code"]}
        self.assertEqual(by_code["DOTNET.0142"]["count"], 4)            # one pattern, not per package
        self.assertIn("FakeItEasy", by_code["DOTNET.0142"]["values"])
        self.assertEqual(by_code["DOTNET.0150"]["count"], 3)
        self.assertIn("Warnings and Errors Without a Traceback", report)


class TriggersAndRedaction(unittest.TestCase):
    def test_triggers_survive_reruns_and_render_only(self):
        files = {"sql.log": sql_tb(1401)}
        _, report, out = run(files)
        self.assertIn("TRIGGER_TODO", report)
        tpath = out / "triggers.json"
        t = json.loads(tpath.read_text())
        for k in t:
            t[k]["trigger"] = "Synonym passed where a type is expected."
        tpath.write_text(json.dumps(t))
        r = subprocess.run([sys.executable, str(SCRIPT), "--render-only", "--output", str(out)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Synonym passed", (out / "tracebacks_report.md").read_text())
        _, report2, _ = run(files, out=out)                            # full re-parse keeps it too
        self.assertIn("Synonym passed", report2)
        self.assertNotIn("TRIGGER_TODO", report2)

    def test_secrets_always_masked_and_redact(self):
        log = forms_tb(1).replace("continuing", "conn password=Hunter2; host db01.acme.internal") + \
            "2026-06-24 13:10:05 [WARNING] ACME upload /opt/cast/shared/upload/ACME/src/App.cs failed\n"
        _, report, _ = run({"f.log": log})
        self.assertNotIn("Hunter2", report)                             # even without --redact
        _, red, _ = run({"f.log": log}, "--redact", "--redact-term", "ACME")
        self.assertNotIn("ACME", red)
        self.assertNotIn("/opt/cast/shared", red)
        self.assertIn(f"{E}/com.castsoftware.formsreport.1.0.4-funcrel/analyser.py", red)  # CAST path kept


class Round3(unittest.TestCase):
    def test_custom_exception_class_at_exception_position(self):
        x = f"{E}/com.castsoftware.camel.1.1.10-funcrel"
        log = f"""2026-10-01 20:00:00 [INFO] [com.castsoftware.camel] Traceback (most recent call last):
  File "{x}/a.py", line 1, in fa
    raise Abort("stop")
cast.application.Abort: stop
2026-10-01 20:00:01 [INFO] [com.castsoftware.camel] Traceback (most recent call last):
  File "{x}/b.py", line 2, in fb
    b()
KeyError: 'b'
2026-10-01 20:00:02 [INFO] [com.castsoftware.camel] next
"""
        data, _, _ = run({"x.log": log})
        a = group(data, "cast.application.Abort")
        k = group(data, "KeyError")
        self.assertEqual((a["short_source"], k["short_source"]), ("a.py:1", "b.py:2"))
        self.assertEqual(a["interleaved_count"] + k["interleaved_count"], 0)

    def test_ordinary_log_line_is_not_an_exception(self):
        x = f"{E}/com.castsoftware.camel.1.1.10-funcrel"
        log = f"""2026-10-01 20:00:00 [INFO] [com.castsoftware.camel] Traceback (most recent call last):
2026-10-01 20:00:00 [INFO] [com.castsoftware.camel]   File "{x}/a.py", line 1, in fa
2026-10-01 20:00:00 [INFO] [com.castsoftware.camel]     a()
2026-10-01 20:00:00 [INFO] [com.castsoftware.jee] Done
2026-10-01 20:00:00 [INFO] [com.castsoftware.camel] ValueError: real one
"""
        data, _, _ = run({"x.log": log})
        self.assertEqual(data["groups"][0]["label"], "ValueError: real one")

    def test_triggers_file_redacted_and_render_only_after_redaction(self):
        files = {"z.log": f"""2026-10-01 20:00:00 [TRACEBACK] [com.castsoftware.camel] CAMEL-001: x Traceback (most recent call last):
  File "{E}/com.castsoftware.camel.1.1.10-funcrel/a.py", line 1, in fa
    a()
KeyError: 'ACME_TABLE'
2026-10-01 20:00:01 [INFO] next
"""}
        _, _, out = run(files, "--redact-term", "ACME")
        tpath = out / "triggers.json"
        self.assertNotIn("ACME", (out / "triggers.shared.json").read_text())   # shareable copy
        t = json.loads(tpath.read_text())
        for k in t:
            t[k]["trigger"] = "Table name not in the schema."
        tpath.write_text(json.dumps(t))
        r = subprocess.run([sys.executable, str(SCRIPT), "--render-only", "--output", str(out),
                            "--redact-term", "ACME"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = (out / "tracebacks_report.md").read_text()
        self.assertIn("Table name not in the schema.", rep)
        self.assertNotIn("ACME", rep)

    def test_legacy_triggers_file_is_migrated(self):
        files = {"s.log": sql_tb(1401)}
        data, _, out = run(files)
        sig = data["groups"][0]["signature"]
        (out / "triggers.json").write_text(json.dumps({sig: {"label": "x", "trigger": "Old explanation."}}))
        _, report, _ = run(files, out=out)
        self.assertIn("Old explanation.", report)


class Round4(unittest.TestCase):
    def test_redacted_render_never_destroys_working_triggers(self):
        files = {"z.log": sql_tb(1401)}
        _, _, out = run(files)
        tpath = out / "triggers.json"
        t = json.loads(tpath.read_text())
        for k in t:
            t[k]["trigger"] = "ACME synonym used as a type."
        tpath.write_text(json.dumps(t))
        r = subprocess.run([sys.executable, str(SCRIPT), "--render-only", "--output", str(out),
                            "--redact-term", "ACME"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ACME synonym", tpath.read_text())                       # working file intact
        self.assertNotIn("ACME", (out / "triggers.shared.json").read_text())
        self.assertNotIn("ACME", (out / "tracebacks_report.md").read_text())
        _, report, _ = run(files, out=out)                                     # unredacted again
        self.assertIn("ACME synonym used as a type.", report)

    def test_fence_survives_backticks_inside_example(self):
        log = f"""2026-10-01 20:00:00 [TRACEBACK] [com.castsoftware.camel] CAMEL-001: x
```stray fence-looking line between header and traceback
Traceback (most recent call last):
  File "{E}/com.castsoftware.camel.1.1.10-funcrel/a.py", line 1, in fa
    a()
ValueError: bad
2026-10-01 20:00:01 [INFO] next
"""
        _, report, _ = run({"f.log": log})
        sec = report[report.index("**Full Traceback**"):report.index("## Summary Table")]
        self.assertIn("```stray", sec)
        self.assertTrue(any(l.startswith("````text") for l in sec.splitlines()))

    def test_utf16_without_bom(self):
        log = forms_tb(1)
        data, _, _ = run({"u.log": log.encode("utf-16-le")})
        self.assertEqual(sum(data["per_file"].values()), 1)

    def test_real_shape_credentials_never_in_outputs(self):
        log = forms_tb(1).replace("continuing", 'connectPassword="CRYPTED:CAA9FB4" DB_PASSWORD=envpw') + \
            '2026-06-24 13:10:05 [WARNING] [com.castsoftware.sqlanalyzer] password : sqlpw1 "password": "jsonpw"\n'
        _, report, out = run({"c.log": log})
        everything = report + (out / "tracebacks.json").read_text() + (out / "triggers.json").read_text()
        for s in ["CAA9FB4", "envpw", "sqlpw1", "jsonpw"]:
            self.assertNotIn(s, everything)

    def test_json_stays_valid_after_redaction(self):
        win = f"""2026-07-01 09:00:05 [TRACEBACK] [com.castsoftware.jee] JEE-014: Issue reading C:\\Users\\jdoe\\app.xml password="p w"
Traceback (most recent call last):
  File "{W}\\com.castsoftware.jee.1.3.5-funcrel\\analyser\\descriptor.py", line 88, in read
    root = ET.parse(path)
ValueError: bad \\"password\\": \\"escpw\\" at \\\\srv01\\share\\x.xml
2026-07-01 09:30:00 [INFO] end
"""
        data, report, out = run({"w.log": win}, "--redact")          # run() parses tracebacks.json
        raw = (out / "tracebacks.json").read_text()
        for s in ["jdoe", "escpw", "srv01", "p w"]:
            self.assertNotIn(s, raw + report)
        self.assertIn("com.castsoftware.jee.1.3.5-funcrel", data["groups"][0]["extension"])


class Round5(unittest.TestCase):
    def test_source_lines_are_not_mangled(self):
        x = f"{E}/com.castsoftware.camel.1.1.10-funcrel"
        log = f"""2026-10-01 20:00:00 [INFO] [com.castsoftware.camel] Traceback (most recent call last):
  File "{x}/a.py", line 1, in fa
    token = parser.next_token()
KeyError: 'x'
2026-10-01 20:00:01 [INFO] [com.castsoftware.camel] Traceback (most recent call last):
  File "{x}/b.py", line 2, in fb
    conn = connect(password="Hunter2")
ValueError: bad
2026-10-01 20:00:02 [INFO] [com.castsoftware.camel] next
"""
        data, report, _ = run({"x.log": log})
        self.assertEqual(group(data, "KeyError")["raised_code"], "token = parser.next_token()")
        self.assertEqual(group(data, "ValueError")["raised_code"], 'conn = connect(password="****")')
        self.assertNotIn("Hunter2", report)

    def test_long_dotted_line_with_redact(self):
        import time
        log = "2026-10-01 20:00:00 [WARNING] classpath " + "a." * 100000 + "\n"
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
        x = f"{E}/com.castsoftware.formsreport.1.0.4-funcrel/formsreport_symbols/__init__.py"
        log = f"""2026-10-01 20:00:00 [TRACEBACK] [com.castsoftware.formsreport] FORMSREPORT-001: x Traceback (most recent call last):
  File "{x}", line 1713, in save_links
    create_link('callLink', a)
KeyError: '__name__' in List<string>
2026-10-01 20:00:01 [WARNING] DOTNET.0142:No ressource found for nuget package Amr.Bus version 2.0.1. The corresponding package reference of project /opt/x/A.csproj
2026-10-01 20:00:02 [WARNING] value <<hidden value>> for *_Dataset*.xml
"""
        for args in ((), ("--redact",)):
            _, report, _ = run({"sub/*_x__init__.log": log}, *args)
            self.assertEqual(markdown_problems(report), [], args)
            self.assertIn("__init__.py", report)                        # literal, inside code

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
    def _sql(self, keys):
        return "".join(f"""2026-10-01 20:00:00 [TRACEBACK] [com.castsoftware.sqlanalyzer] SQL-002: x Traceback (most recent call last):
  File "{E}/com.castsoftware.sqlanalyzer.3.7.24-funcrel/sqlscript_parser/__init__.py", line 6311, in create_type_header
    or object_of.type_header_is_wrapped):
KeyError: '{k}'
""" for k in keys) + "2026-10-01 20:00:01 [INFO] next\n"

    def test_invalid_triggers_file_is_never_overwritten(self):
        files = {"s.log": self._sql(["name"])}
        _, _, out = run(files)
        tpath = out / "triggers.json"
        t = json.loads(tpath.read_text())
        for k in t:
            t[k]["trigger"] = "Hours of careful analysis."
        broken = json.dumps(t, indent=2).rstrip().rstrip("}").rstrip() + ",\n}"     # trailing comma
        tpath.write_text(broken)
        report_before = (out / "tracebacks_report.md").read_text()
        r = subprocess.run([sys.executable, str(SCRIPT), "--input", str(out.parent / "Input"),
                            "--output", str(out)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not valid JSON", r.stderr)
        self.assertEqual(tpath.read_text(), broken)                          # untouched
        self.assertEqual((out / "tracebacks_report.md").read_text(), report_before)

    def test_backup_kept_before_every_write(self):
        files = {"s.log": self._sql(["name"])}
        _, _, out = run(files)
        tpath = out / "triggers.json"
        t = json.loads(tpath.read_text())
        for k in t:
            t[k]["trigger"] = "First version."
        tpath.write_text(json.dumps(t))
        run(files, out=out)
        self.assertIn("First version.", (out / "triggers.json.bak").read_text())

    def test_one_bug_with_many_names_is_one_group(self):
        data, report, out = run({"s.log": self._sql(["TABLE_%04d_COL" % i for i in range(300)])})
        self.assertEqual(len(data["groups"]), 1)
        g = data["groups"][0]
        self.assertEqual((g["count"], g["variant_count"]), (300, 300))
        self.assertLessEqual(len(g["message_variants"]), 20)
        self.assertIn("KeyError: '…'", report)
        self.assertLess(len(report.splitlines()), 120)

    def test_different_sites_or_types_never_merge(self):
        a = self._sql(["x"])
        b = a.replace("line 6311", "line 999").replace("KeyError", "IndexError")
        data, _, _ = run({"a.log": a, "b.log": b})
        self.assertEqual(len(data["groups"]), 2)

    def test_triggers_from_the_previous_grouping_are_migrated(self):
        import hashlib
        files = {"s.log": self._sql(["name"])}
        data, _, out = run(files)
        g = data["groups"][0]
        site = g["extension_source"] or g["source"]
        old_sig = "KeyError|'name'|" + site                                   # previous release's grouping
        old_id = hashlib.sha256(old_sig.encode()).hexdigest()[:16]
        (out / "triggers.json").write_text(json.dumps({old_id: {"label": "x", "trigger": "Kept explanation."}}))
        _, report, _ = run(files, out=out)
        self.assertIn("Kept explanation.", report)

    def test_report_caps_full_sections(self):
        logs = {}
        for i in range(8):
            logs["s%d.log" % i] = self._sql(["k"]).replace("line 6311", "line %d" % (100 + i))
        data, report, _ = run(logs, "--top-errors", "3")
        self.assertEqual(len(data["groups"]), 8)
        self.assertEqual(report.count("\n### "), 3)
        self.assertIn("8 error groups", report)
        self.assertEqual(report.split("## Summary Table")[1].count("\n| "), 9)  # header + 8 rows

    def test_several_runs_in_one_folder_are_flagged(self):
        files = {"run1/analyze/0-analyze.log": "2026-10-01 20:00:00 x\n", "run1/analyze/4.log": self._sql(["a"]),
                 "run2/analyze/0-analyze.log": "2026-10-02 20:00:00 x\n", "run2/analyze/4.log": self._sql(["a"])}
        data, report, _ = run(files)
        self.assertEqual(len(data["runs"]), 2)
        self.assertIn("2 runs in one folder", report)

    def test_render_only_with_json_from_an_older_release(self):
        _, _, out = run({"s.log": self._sql(["name"])})
        d = json.loads((out / "tracebacks.json").read_text())
        for k in ("problems", "runs"):
            d.pop(k)
        for g in d["groups"]:
            g.pop("variant_count")
        (out / "tracebacks.json").write_text(json.dumps(d))
        r = subprocess.run([sys.executable, str(SCRIPT), "--render-only", "--output", str(out)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_output_same_as_input_is_refused(self):
        tmp = Path(_mkdtemp())
        (tmp / "Input").mkdir()
        (tmp / "Input" / "a.log").write_text(self._sql(["a"]))
        r = subprocess.run([sys.executable, str(SCRIPT), "--input", "Input", "--output", "Input"],
                           cwd=str(tmp), capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("must be a different folder", r.stderr)


class Round8(unittest.TestCase):
    def _jee(self, names):
        return "".join(f"""2026-10-01 20:00:00 [TRACEBACK] [com.castsoftware.jee] JEE-014: x Traceback (most recent call last):
  File "{E}/com.castsoftware.jee.2.0.19-funcrel/resolver.py", line 210, in resolve
    raise LookupError("Symbol not found: " + name)
LookupError: Symbol not found: {n}
""" for n in names) + "2026-10-01 20:00:01 [INFO] next\n"

    def _id(self, sig):
        import hashlib
        return hashlib.sha256(sig.encode()).hexdigest()[:16]

    def test_unquoted_dotted_names_are_one_group(self):
        names = ["com.acme.%s.%sService" % (a, b) for a in ("billing", "ledger", "meter")
                 for b in ("Invoice", "Account", "Tariff", "Reading")]
        data, report, _ = run({"j.log": self._jee(names)})
        self.assertEqual(len(data["groups"]), 1)
        self.assertEqual(data["groups"][0]["variant_count"], 12)
        self.assertIn("Symbol not found: <name>", report)

    def test_uploaded_triggers_are_only_read(self):
        files = {"j.log": self._jee(["com.acme.A"])}
        data, _, out = run(files)
        sid = data["groups"][0]["signature_id"]
        upload = Path(_mkdtemp()) / "triggers.json"
        upload.write_text(json.dumps({sid: {"label": "x", "trigger": "From the previous session."}}))
        before = upload.read_bytes()
        out2 = Path(_mkdtemp()) / "Output"
        r = subprocess.run([sys.executable, str(SCRIPT), "--input", str(out.parent / "Input"),
                            "--output", str(out2), "--triggers", str(upload)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(upload.read_bytes(), before)                          # never written
        self.assertFalse(any(p.name != "triggers.json" for p in upload.parent.iterdir()))  # no .bak/.tmp
        self.assertIn("From the previous session.", (out2 / "triggers.json").read_text())
        self.assertIn("From the previous session.", (out2 / "tracebacks_report.md").read_text())
        r = subprocess.run([sys.executable, str(SCRIPT), "--input", str(out.parent / "Input"),
                            "--output", str(out2), "--triggers", str(upload) + ".missing"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not found", r.stderr)

    def test_triggers_from_the_quoted_only_pattern_are_migrated(self):
        files = {"j.log": self._jee(["com.acme.billing.InvoiceService"])}
        data, _, out = run(files)
        g = data["groups"][0]
        site = g["extension_source"] or g["source"]
        v1 = self._id("LookupError|Symbol not found: com.acme.billing.InvoiceService|" + site)
        (out / "triggers.json").write_text(json.dumps({v1: {"label": "x", "trigger": "Written last release."}}))
        _, report, _ = run(files, out=out)
        self.assertIn("Written last release.", report)

    def test_different_earlier_explanations_are_all_kept(self):
        tb = lambda k: f"""2026-10-01 20:00:00 [TRACEBACK] [com.castsoftware.sqlanalyzer] SQL-002: x Traceback (most recent call last):
  File "{E}/com.castsoftware.sqlanalyzer.3.7.24-funcrel/p.py", line 9, in f
    a()
KeyError: '{k}'
"""
        files = {"a.log": tb("name") + tb("id") + "2026-10-01 20:00:01 [INFO] next\n"}
        data, _, out = run(files)
        g = data["groups"][0]
        site = g["extension_source"] or g["source"]
        old = {self._id("KeyError|'name'|" + site): {"label": "KeyError: 'name'", "trigger": "Explanation A."},
               self._id("KeyError|'id'|" + site): {"label": "KeyError: 'id'", "trigger": "Explanation B."}}
        (out / "triggers.json").write_text(json.dumps(old))
        _, report, _ = run(files, out=out)
        self.assertIn("Explanation A.", report)
        self.assertIn("Explanation B.", report)

    def test_negative_caps_are_refused(self):
        for flag in ("--top-errors", "--top-warnings"):
            r = subprocess.run([sys.executable, str(SCRIPT), flag, "-1"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
            self.assertIn("must be 0 or more", r.stderr)


class Round9(unittest.TestCase):
    def test_windows_1252_log_in_report(self):
        E1 = r"C:\ProgramData\CAST\CAST\Extensions\com.castsoftware.jee.2.0.19-funcrel"
        log = f"""2026-10-01 20:00:01 [WARNING] Fichier non trouvé : App.java
2026-10-01 20:00:02 [TRACEBACK] [com.castsoftware.jee] JEE-014: Échec Traceback (most recent call last):
  File "{E1}\\resolver.py", line 210, in resolve
    raise LookupError("Élément introuvable")
LookupError: Élément introuvable : facturé
2026-10-01 20:30:00 [INFO] Terminé
"""
        data, report, _ = run({"fr.log": log.encode("cp1252")})
        self.assertNotIn("\ufffd", report)
        self.assertEqual(data["groups"][0]["label"], "LookupError: Élément introuvable : facturé")
        self.assertIn("Fichier non trouvé", report)

    def test_superseded_trigger_entries_are_dropped_safely(self):
        import hashlib
        hid = lambda sig: hashlib.sha256(sig.encode()).hexdigest()[:16]
        tb = lambda k: f"""2026-10-01 20:00:00 [TRACEBACK] [com.castsoftware.sqlanalyzer] SQL-002: x Traceback (most recent call last):
  File "{E}/com.castsoftware.sqlanalyzer.3.7.24-funcrel/p.py", line 9, in f
    a()
KeyError: '{k}'
"""
        files = {"a.log": tb("name") + tb("id") + "2026-10-01 20:00:01 [INFO] next\n"}
        data, _, out = run(files)
        g = data["groups"][0]
        site = g["extension_source"] or g["source"]
        same, other, unrelated = hid("KeyError|'name'|" + site), hid("KeyError|'id'|" + site), "0123456789abcdef"
        (out / "triggers.json").write_text(json.dumps({
            g["signature_id"]: {"label": "x", "trigger": "Current explanation."},
            same: {"label": "KeyError: 'name'", "trigger": "Current explanation."},     # redundant
            other: {"label": "KeyError: 'id'", "trigger": "A different explanation."},  # adds something
            unrelated: {"label": "another app", "trigger": "Keep me."}}))
        run(files, out=out)
        t = json.loads((out / "triggers.json").read_text())
        self.assertNotIn(same, t)
        self.assertIn(other, t)
        self.assertIn(unrelated, t)
        self.assertEqual(t[g["signature_id"]]["trigger"], "Current explanation.")

    def test_mask_mode_windows_1252(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--mask"], input="Terminé password=x\n".encode("cp1252"),
                           capture_output=True)
        self.assertEqual((r.returncode, r.stdout.decode("utf-8")), (0, "Terminé password=****\n"))


class RealRuns(unittest.TestCase):
    """Message shapes from real CAST runs (Java, .NET, SQL, Forms); names rewritten."""

    def _patterns(self, lines):
        log = "".join("2026-04-20 12:42:%02d.000 [WARNING] %s\n" % (i % 60, l) for i, l in enumerate(lines))
        data, _, _ = run({"w.log": log})
        return data["problems"]["groups"]

    def test_java_codes_and_method_names(self):
        g = self._patterns(["JAVA068: Duplicate method declaration : get%s(): C:\\src\\A%d.java" % (n, i)
                            for i, n in enumerate(["Code", "Key", "Value", "Owner", "State"])])
        self.assertEqual(len(g), 1)
        self.assertEqual((g[0]["code"], g[0]["count"]), ("JAVA068", 5))

    def test_java_signatures_in_single_quotes(self):
        g = self._patterns(["JAVA124:Cannot resolve 'Nullable' as annotation type in formal parameter "
                            "'com.acme.Svc.%s(List, int)#p' from formal parameter 'com.acme.Svc.%s(List, int)#p': "
                            "/src/Svc.java" % (n, n) for n in ("countA", "mapB", "loadC")])
        self.assertEqual(len(g), 1)

    def test_security_code_with_dash(self):
        g = self._patterns(["SECJAVA.004 - Missing import 12/src/a/B.java com.acme.X",
                            "SECJAVA.004 - Missing import 3/src/c/D.java com.acme.Y"])
        self.assertEqual((len(g), g[0]["code"]), (1, "SECJAVA.004"))

    def test_byte_dumps_and_double_quotes(self):
        g = self._patterns(["The UTF-8 sequence starting at offset %d was invalid (all invalid bytes have been "
                            "replaced by '?'); dump starting at the 1st invalid UTF-8 byte follows: %s(\"%s\")."
                            % (o, d, t) for o, d, t in [(10, "\\xc3,\\xa9", "ré au"),
                                                        (99, "\\xa0,\\x20,\\xc3", "té g"),
                                                        (7, "\\xbf", "le rev")]])
        self.assertEqual(len(g), 1)

    def test_english_words_and_french_apostrophes_kept(self):
        m = _load_script()
        self.assertIn("as type or variable in", m.warning_template(
            "JAVA124:Cannot resolve 'X' as type or variable in method 'a.B.c()' from method 'a.B.c()'")[1])
        self.assertEqual(m.warning_template("Impossible de trouver l'élément 'Foo' dans l'analyse")[1],
                         "Impossible de trouver l'élément '…' dans l'analyse")

    def test_rare_errors_and_failures_are_shown_beyond_the_top(self):
        words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliett",
                 "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango",
                 "uniform", "victor", "whiskey", "xray", "yankee", "zulu", "amber", "basalt", "cobalt", "dune",
                 "ember", "fjord", "garnet", "harbor", "indigo", "jasper", "kelp", "lagoon", "marble", "nickel"]
        lines = ["WARNING common %s situation noted" % words[i % 40] for i in range(2000)]   # 40 frequent patterns
        lines += ["ERROR Failed to run the augmented discoverer",
                  "WARNING UA Plugin : Plugin operation failed. Please check log for details.",
                  "WARNING harmless rare note"]
        log = "".join("2026-09-26 07:01:%02d [%s] %s\n" % (i % 60, l.split(" ", 1)[0], l.split(" ", 1)[1])
                      for i, l in enumerate(lines))
        _, report, _ = run({"w.log": log}, "--top-warnings", "30")
        sec = report.split("beyond the top 30** (rare")[1].split("tracebacks.json")[0]
        self.assertIn("Failed to run the augmented discoverer", sec)
        self.assertIn("Plugin operation failed", sec)
        self.assertNotIn("harmless rare note", sec)

    def test_lowercase_nuget_ids_stay_in_their_group(self):
        g = self._patterns(["DOTNET.0142:No ressource found for nuget package %s version 1.2.3. The corresponding "
                            "package reference of project /src/A.csproj will be ignored" % n
                            for n in ("Amr.Bus", "NLog.Extensions.Logging", "xunit", "moq")])
        self.assertEqual(len(g), 1)
        self.assertIn("package or type", self._patterns(["JAVA124:Cannot resolve 'X' as package or type in "
                                                         "package 'a' from package 'b': /src/A.java"])[0]["template"])

    def test_lowercase_exception_class(self):
        log = f"""2026-04-22 01:00:00 [INFO] [com.castsoftware.automaticlinksvalidator] Traceback (most recent call last):
  File "{E}/com.castsoftware.automaticlinksvalidator.1.0.0/main.py", line 5, in probability_delete
    re.search(pattern, text)
re.error: bad escape \\c at position 43
2026-04-22 01:00:01 [INFO] next
"""
        data, _, _ = run({"x.log": log})
        self.assertEqual(data["groups"][0]["exc_type"], "re.error")


class NestedLevels(unittest.TestCase):
    def test_level_inside_an_info_wrapper_counts(self):
        log = ("2026-05-28 15:22:00 [INFO] [81976] [ERROR] cannot parse file /x/a.xml\n"
               "2026-05-28 15:22:01 [ERROR] cannot parse file /x/b.xml\n"
               "2026-05-28 15:22:02 [WARNING] [INFO] odd order, still a warning\n"
               "2026-05-28 15:22:03 [INFO] [81976] plain info\n"
               "2026-04-22 00:38:21 [INFO] ERROR: INVALID LINK POSITIONS : 4267\n"      # INFO statistic
               "2026-04-22 00:38:22 ERROR bare level as the first level\n")
        data, _, _ = run({"n.log": log})
        self.assertEqual(data["problems"]["totals"], {"ERROR": 3, "WARNING": 1})


class Cast83Formats(unittest.TestCase):
    """CAST 8.3.50 layouts (tab-separated analyzer logs, "INF:" orchestration logs); names rewritten."""
    TRAIL = "\t0 ; 0\t0\t\t0\t[Module name]\t0\t0\t\t"

    def test_tab_format_levels_and_messages(self):
        t = self.TRAIL
        log = (" 2026-09-30 11:50:18.734869\tInformation\tMODULMSG ; Job execution\t[com.castsoftware.java.service] ok" + t + "\n"
               " 2026-09-30 11:50:18.969245\tWarning\tMODULMSG ; Job execution\t[com.castsoftware.java.service] Method call not found at position (65, 37, 65, 106)" + t + "\n"
               " 2026-09-30 11:50:19.100000\tWarning\tMODULMSG ; Job execution\tDuplicate object of type 'X' has been detected : 'a.B'" + t + "\n"
               " 2026-09-30 11:50:19.200000\tError\tMODULMSG ; Job execution\tSomething failed" + t + "\n")
        data, _, _ = run({"a.log": log})
        self.assertEqual(data["problems"]["totals"], {"WARNING": 2, "ERROR": 1})
        g = {x["template"]: x for x in data["problems"]["groups"]}
        self.assertIn("Method call not found at position (N, N, N, N)", g)              # trailing columns dropped
        self.assertEqual(g["Method call not found at position (N, N, N, N)"]["source"], "com.castsoftware.java.service")

    def test_tab_format_traceback(self):
        W = r"E:\\Prog\\Cast\\Programdata\\CAST\\CAST\\Extensions\\com.castsoftware.java.service.1.0.5-funcrel"
        log = (" 2026-09-30 11:50:19.000474\tWarning\tMODULMSG ; Job execution\t[com.castsoftware.java.service] Traceback (most recent call last):\r\n"
               f'  File "{W}\\service.py", line 556, in rest_template\r\n'
               "    log.info('%s calling %s' % (caller.get_fullname(), method_call.get_resolution().get_fullname()))\r\n"
               "AttributeError: 'NoneType' object has no attribute 'get_resolution'\r\n"
               + self.TRAIL + "\r\n"
               " 2026-09-30 11:50:19.100000\tInformation\tMODULMSG ; Job execution\tnext" + self.TRAIL + "\r\n")
        data, _, _ = run({"j.log": log})
        self.assertEqual(sum(data["per_file"].values()), 1)
        g = data["groups"][0]
        self.assertEqual((g["extension"], g["short_source"]), ("com.castsoftware.java.service.1.0.5-funcrel", "service.py:556"))

    def test_lines_with_control_characters(self):
        log = (" 2026-09-30 13:47:00,039 \x07\tINFO\x07\tMODULMSG ; Body\x07\tAugmented-discoverer 0.2.1\r\n"
               " 2026-09-30 13:47:01,039 \x07\tWARNING\x07\tMODULMSG ; Body\x07\tSomething odd\r\n"
               " 2026-09-30 13:47:02,039 \x07\tERROR\x07\tMODULMSG ; Body\x07\tBroken thing\r\n")
        data, _, _ = run({"0-analyze.log": log})
        self.assertEqual(data["problems"]["totals"], {"WARNING": 1, "ERROR": 1})
        self.assertIn("Broken thing", [g["template"] for g in data["problems"]["groups"]])

    def test_warning_table_names_the_log(self):
        t = self.TRAIL
        logs = {"analyze/4-run-metrics-calculation-for-main.log":
                " 2026-09-26 11:21:47.202924\tWarning\tMODULMSG ; Job execution\t[MAv2] Cannot find type of string" + t + "\n" * 1,
                "analyze/11-run-j2ee.log": " 2026-09-26 11:21:48.000000\tWarning\tMODULMSG ; Job execution\t[MAv2] Cannot find type of string" + t + "\n"}
        logs["analyze/4-run-metrics-calculation-for-main.log"] *= 3
        _, report, _ = run(logs)
        row = [l for l in report.splitlines() if "Cannot find type of string" in l and l.startswith("| 1 |")][0]
        self.assertIn("`4-run-metrics-calculation-for-main.log` +1", row)

    def test_orchestration_levels_with_and_without_timestamp(self):
        log = ("INF: 2026-09-26 00:59:46: Running analysis\r\n"
               "WRN: 2026-09-26 01:00:00: \tMissing translation for id CONNECTION_MANAGER_JDBC_CONNECTED\r\n"
               "WRN: Aborting the installation of Package 'Base_X', version '1.0.0.1'\r\n"
               "ERR: 2026-09-26 01:00:01: No file found for application 1234\r\n")
        data, _, _ = run({"0-analyze.log": log})
        self.assertEqual(data["problems"]["totals"], {"WARNING": 2, "ERROR": 1})


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
