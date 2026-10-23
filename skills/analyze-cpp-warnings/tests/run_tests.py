#!/usr/bin/env python3
"""Regression tests for analyze_cpp_warnings.py. Run: python3 tests/run_tests.py (standard library only).

Fixtures use invented folder, header and identifier names only. Every case documents a behaviour
found on a real 1.6 GB C++ log (4.1 million warnings from missing headers and unknown macros).
"""
import atexit
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "analyze_cpp_warnings.py"

_TMP_DIRS = []


def _mkdtemp():
    """Temporary folder removed when the test run ends (tests must not litter /tmp)."""
    d = tempfile.mkdtemp(prefix="cast-skill-test-")
    _TMP_DIRS.append(d)
    return d


atexit.register(lambda: [shutil.rmtree(d, ignore_errors=True) for d in _TMP_DIRS])

ROOT = "/data/app1/src"


def ts(i):
    return "2026-03-01 10:{:02d}:{:02d}.{:03d}".format(i // 60 % 60, i % 60, 100 + i % 900)


def build_log(units=3, total=None, finish=True, extra=()):
    """A small C++ analyzer log: `units` source files parsed; every file includes the generated
    header gen/topics.h, which cannot find an SDK header and uses SDK macros."""
    total = total or units
    lines = ["{} [INFO] +root path:{}".format(ts(0), ROOT),
             "{} [INFO] include path: '/usr/share/CAST/Extensions/com.castsoftware.cpp.3.0.1-funcrel/EnvProf/CPP/STL' "
             "(from STL for Unix), unsaved".format(ts(0)),
             "{} [INFO] Running analysis 'Main-CFileProject_1'.".format(ts(1)),
             "{} [INFO] Compiling source files ({} items)...".format(ts(1), total)]
    t = 2
    for k in range(1, units + 1):
        src = "{}/modA/src/file{}.c".format(ROOT, k)
        gen = "{}/modA/gen/topics.h".format(ROOT)
        lines.append("{} [INFO] Parsing file ({}/{}) {}...".format(ts(t), k, total, src))
        for h, line in (("rtisdk/core.h", 14), ("stdio.h", 3), ("pthread.h", 4), ("sys/neutrino.h", 5)):
            lines.append("{} [WARNING] Preprocessor cannot find file '{}'. (file {}, line {})".format(
                ts(t), h, gen if h.startswith("rtisdk") else src, line))
        for col, tok in ((30, "RTI_BOOL"), (31, "RTI_BOOL"), (32, "RTI_UINT32")):
            lines.append("{} [WARNING] [Parser] {}: Ignored token '{}'. [file '{}'({},{})]\t{}".format(
                ts(t), tok, tok, gen, 40 + col, col, gen))
            lines.append("{} [WARNING] [Parser] Variable name expected. [file '{}'({},{})]\t{}".format(
                ts(t), gen, 40 + col, col, gen))
        lines.append("{} [WARNING] [Parser] char:     char: variable already has type EXPORT_MACRO. "
                     "[file '{}'(42,32)]\t{}".format(ts(t), gen, gen))
        lines.append("{} [WARNING] [Configuration] SDK_name_t: Unknown identifier 'SDK_name_t' is probably an unknown "
                     "compilation directive. [file '{}'(52,30)]\t{}".format(ts(t), gen, gen))
        lines.append("{} [INFO] Preprocessor has found several possibilities for common.h. Chose closest : "
                     "{}/moda/include/common.h\t{}/modb/src/user.h".format(ts(t), ROOT.lower(), ROOT))
        lines.append("{} [INFO] Skipping illegal redefinition of typedef Int8. [file '{}/modA/inc/types.h'(10,1)]"
                     "\t{}/modA/inc/types.h".format(ts(t), ROOT, ROOT))
        t += 5
    lines += list(extra)
    return "\n".join(lines) + "\n"


def run(files, *args, out=None, expect=0):
    tmp = Path(_mkdtemp())
    out = out or tmp / "Output"
    for rel, content in files.items():
        p = tmp / "Input" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    (tmp / "Input").mkdir(exist_ok=True)
    r = subprocess.run([sys.executable, str(SCRIPT), "--input", str(tmp / "Input"), "--output", str(out)]
                       + list(args), capture_output=True, text=True)
    assert r.returncode == expect, (r.returncode, r.stdout, r.stderr)
    if expect:
        return None, None, out, r
    data = json.loads((out / "cpp_warnings.json").read_text(encoding="utf-8"))
    report = (out / "cpp_warnings_report.md").read_text(encoding="utf-8")
    return data, report, out, r


def finding(data, fid):
    return next((f for f in data["findings"] if f["id"] == fid), None)


def _load_script():
    import importlib.util
    spec = importlib.util.spec_from_file_location("skill_script", str(SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Counting(unittest.TestCase):
    def test_levels_tags_and_totals(self):
        data, _, _, _ = run({"4-cpp.log": build_log(3)})
        t = data["totals"]
        self.assertEqual(t["warnings"], 3 * (4 + 6 + 2))
        self.assertEqual(t["by_tag"]["WARNING:Parser"], 3 * 7)
        self.assertEqual(t["by_tag"]["WARNING:Configuration"], 3)
        self.assertEqual(t["by_tag"]["WARNING:Preprocessor"], 12)
        self.assertEqual(data["cpp_logs"], 1)

    def test_missing_headers_are_classified(self):
        data, _, _, _ = run({"4-cpp.log": build_log(3)})
        rows = {r["header"]: r for r in data["missing_headers"]["rows"]}
        self.assertEqual(rows["rtisdk/core.h"]["count"], 3)
        self.assertEqual(rows["stdio.h"]["category"], "system")
        self.assertEqual(rows["sys/neutrino.h"]["category"], "platform")
        self.assertEqual(rows["sys/neutrino.h"]["label"], "QNX Neutrino SDP")
        self.assertEqual(rows["rtisdk/core.h"]["category"], "other")

    def test_unknown_identifiers_by_kind(self):
        data, _, _, _ = run({"4-cpp.log": build_log(3)})
        toks = {t["token"]: t for t in data["unknown_identifiers"]["rows"]}
        self.assertEqual(toks["RTI_BOOL"]["ignored"], 6)
        self.assertEqual(toks["RTI_UINT32"]["ignored"], 3)
        self.assertEqual(toks["EXPORT_MACRO"]["decorator"], 3)
        self.assertEqual(toks["SDK_name_t"]["unknown_directive"], 3)
        self.assertEqual(toks["RTI_BOOL"]["family"], "RTI")

    def test_header_reparsed_for_every_source_file(self):
        """A header is parsed again for each file that includes it: the report says in how many."""
        data, _, _, _ = run({"4-cpp.log": build_log(3)})
        gen = next(r for r in data["files"]["rows"] if r["file"].endswith("gen/topics.h"))
        self.assertEqual(gen["source_files"], 3)
        self.assertEqual(data["source_files"]["parsed"], 3)

    def test_ambiguous_includes_and_cross_folder_choice(self):
        data, _, _, _ = run({"4-cpp.log": build_log(2)})
        row = data["ambiguous_includes"]["rows"][0]
        self.assertEqual((row["header"], row["count"], row["chosen_module"]), ("common.h", 2, "moda"))
        self.assertEqual(row["other_module_count"], 2)          # included from modB, chosen in modA

    def test_typedef_redefinitions(self):
        data, _, _, _ = run({"4-cpp.log": build_log(2)})
        self.assertEqual(data["typedef_redefinitions"]["count"], 2)
        self.assertEqual(data["typedef_redefinitions"]["rows"][0]["typedef"], "Int8")

    def test_environment(self):
        data, _, _, _ = run({"4-cpp.log": build_log(1)})
        env = data["environment"]
        self.assertEqual(env["cpp_extension"], ["3.0.1-funcrel"])
        self.assertEqual(env["analysis_units"], ["Main-CFileProject_1"])
        self.assertEqual(env["root_path"], ROOT)

    def test_error_lines_are_listed(self):
        log = build_log(1, extra=["{} [ERROR] Cannot open database 'x1' (code 12)".format(ts(50))])
        data, report, _, _ = run({"a.log": log})
        self.assertEqual(data["totals"]["errors"], 1)
        self.assertIsNotNone(finding(data, "errors"))
        self.assertIn("Cannot open database", report)


class SeveralLogs(unittest.TestCase):
    """Audit: unit indexes were per log but used against one shared list, so a second C/C++ log
    was counted against the first one's source files, and a duration spanned the gap between logs."""

    def test_second_log_is_not_counted_against_the_first(self):
        second = build_log(1).replace("2026-03-01 10:", "2026-03-02 11:")
        data, _, _, _ = run({"a.log": build_log(3), "b.log": second})
        self.assertEqual(data["source_files"]["parsed"], 4)
        by_warn = sorted(u["warnings"] for u in data["source_files"]["most_warnings"])
        self.assertEqual(by_warn, [12, 12, 12, 12])                        # not 24 on the first file
        gen = next(r for r in data["files"]["rows"] if r["file"].endswith("gen/topics.h"))
        self.assertEqual(gen["source_files"], 4)

    def test_duration_never_spans_two_logs(self):
        second = build_log(1).replace("2026-03-01 10:", "2026-03-02 11:")
        data, _, _, _ = run({"a.log": build_log(3), "b.log": second})
        self.assertLess(max(u["seconds"] for u in data["source_files"]["slowest"]), 60)

    def test_warning_before_the_first_source_file_belongs_to_none(self):
        early = "2026-03-01 10:00:00.100 [WARNING] Preprocessor cannot find file 'stdio.h'. (file /s/early.h, line 1)\n"
        data, _, _, _ = run({"a.log": early + build_log(1)})
        row = next(r for r in data["files"]["rows"] if r["file"] == "/s/early.h")
        self.assertEqual((row["warnings"], row["source_files"]), (1, 0))


class Findings(unittest.TestCase):
    def test_root_causes_found(self):
        data, report, _, _ = run({"4-cpp.log": build_log(3)})
        ids = [f["id"] for f in data["findings"]]
        for want in ("missing-other-headers", "missing-system-headers", "unknown-identifiers", "concentrated",
                     "ambiguous-includes", "typedef-redefinitions"):
            self.assertIn(want, ids)
        sysf = finding(data, "missing-system-headers")
        self.assertIn("QNX", sysf["recommendation"])
        self.assertIn("## Verdict", report)
        self.assertIn("### 1.", report)

    def test_known_sdk_is_named(self):
        log = build_log(1, extra=["{} [WARNING] Preprocessor cannot find file 'rti_me_c.h'. (file {}/a.h, line 1)".format(
            ts(60), ROOT), "{} [WARNING] Preprocessor cannot find file 'reda/reda_sequence_decl.h'. (file {}/a.h, "
                          "line 2)".format(ts(60), ROOT)])
        data, _, _, _ = run({"a.log": log})
        f = finding(data, "missing-sdk-headers")
        self.assertIn("RTI Connext DDS", f["title"])
        self.assertIn("RTI", f["evidence"][1])                  # linked to the RTI_ identifiers

    def test_unfinished_run_is_stated_first(self):
        data, report, _, r = run({"4-cpp.log": build_log(3, total=10)})
        f = finding(data, "run-incomplete")
        self.assertIn("3 of 10", f["evidence"][0])
        self.assertFalse(data["logs"][0]["all_files_reached"])
        self.assertLess(report.index("did not finish"), report.index("## Findings"))
        self.assertIn("did not finish", r.stderr)

    def test_finished_run_has_no_incomplete_finding(self):
        data, report, _, r = run({"4-cpp.log": build_log(3)})
        self.assertIsNone(finding(data, "run-incomplete"))
        self.assertTrue(data["logs"][0]["all_files_reached"])
        self.assertNotIn("did not finish", report)

    def test_classify_header(self):
        m = _load_script()
        for name, want in (("stdio.h", "system"), ("pthread.h", "system"), ("sys/types.h", "system"),
                           ("alloca.h", "system"), ("vector", "system"), ("sys/neutrino.h", "platform"),
                           ("hw/inout.h", "platform"), ("windows.h", "platform"), ("rti_me_c.h", "sdk"),
                           ("reda/reda_sequence_decl.h", "sdk"), ("boost/shared_ptr.hpp", "sdk"),
                           ("my_project.h", "other"), ("io.h", "other")):
            self.assertEqual(m.classify_header(name)[0], want, name)
        self.assertEqual(m.classify_header("SYS\\Neutrino.H")[0], "platform")      # case and separators

    def test_token_family(self):
        m = _load_script()
        self.assertEqual(m.token_family("RTI_BOOL"), "RTI")
        self.assertEqual(m.token_family("NDDSUSERDllExport"), "")
        self.assertEqual(m.token_family("lower_case"), "")


class Refusals(unittest.TestCase):
    def test_missing_input_folder(self):
        tmp = Path(_mkdtemp())
        r = subprocess.run([sys.executable, str(SCRIPT), "--input", str(tmp / "nope"), "--output", str(tmp / "o")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertFalse((tmp / "o").exists())

    def test_output_must_not_be_input_or_contain_it(self):
        tmp = Path(_mkdtemp())
        (tmp / "Input").mkdir()
        (tmp / "Input" / "a.log").write_text(build_log(1), encoding="utf-8")
        for out in (tmp / "Input", tmp):
            r = subprocess.run([sys.executable, str(SCRIPT), "--input", str(tmp / "Input"), "--output", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 2)
        self.assertFalse((tmp / "cpp_warnings_report.md").exists())

    def test_no_cpp_log_writes_nothing(self):
        plain = "2026-03-01 10:00:00 [INFO] Starting\n2026-03-01 10:00:01 [WARNING] Something odd\n"
        _, _, out, r = run({"a.log": plain}, expect=2)
        self.assertIn("No C/C++ analyzer log", r.stderr)
        self.assertFalse(out.exists())

    def test_no_logs(self):
        _, _, out, r = run({"readme.txt": "x"}, expect=2)
        self.assertFalse(out.exists())

    def test_non_cpp_logs_are_ignored_among_cpp_ones(self):
        data, _, _, _ = run({"a.log": build_log(1), "b.log": "2026-03-01 10:00:00 [WARNING] unrelated\n"})
        self.assertEqual((data["logs_scanned"], data["cpp_logs"]), (2, 1))
        self.assertEqual([l["file"] for l in data["logs"]], ["a.log"])


class Formats(unittest.TestCase):
    def test_utf16_log(self):
        data, _, _, _ = run({"a.log": build_log(2).encode("utf-16")})
        self.assertEqual(data["missing_headers"]["distinct"], 4)
        data, _, _, _ = run({"a.log": build_log(2).replace("\n", "\r\n").encode("utf-16-le")})   # no BOM
        self.assertEqual(data["missing_headers"]["distinct"], 4)

    def test_crlf_and_tab_separated_83_layout(self):
        tab = ("2026-03-01 10:00:01.000100\tWarning\tCPP ; Preprocessor\tPreprocessor cannot find file 'stdio.h'. "
               "(file /s/a.c, line 3)\t0 ; 0\n"
               "2026-03-01 10:00:01.000200\tInformation\tCPP ; Preprocessor\tParsing file (1/1) /s/a.c...\t0 ; 0\n")
        data, _, _, _ = run({"a.log": tab})
        self.assertEqual(data["missing_headers"]["rows"][0]["header"], "stdio.h")
        self.assertEqual(data["logs"][0]["files_total"], 1)

    def test_unprefixed_lines_are_ignored(self):
        data, _, _, _ = run({"a.log": build_log(1) + "continuation line without a timestamp\n"})
        self.assertEqual(data["totals"]["errors"], 0)


class TimingAndPatterns(unittest.TestCase):
    def test_duration_and_slowest_source_file(self):
        data, _, _, _ = run({"a.log": build_log(3)})
        self.assertEqual(data["logs"][0]["first"], "2026-03-01 10:00:00")
        self.assertGreater(data["logs"][0]["duration_s"], 0)
        self.assertEqual(len(data["source_files"]["slowest"]), 3)

    def test_patterns_group_by_template(self):
        data, _, _, _ = run({"a.log": build_log(3)})
        pats = {p["pattern"]: p for p in data["patterns"]}
        self.assertEqual(pats["[Parser] <id>: Ignored token '…'."]["count"], 9)
        self.assertEqual(pats["[Parser] Variable name expected."]["count"], 9)

    def test_json_and_report_are_the_only_outputs(self):
        _, _, out, _ = run({"a.log": build_log(1)})
        self.assertEqual(sorted(p.name for p in out.iterdir()), ["cpp_warnings.json", "cpp_warnings_report.md"])


class DocumentedMessages(unittest.TestCase):
    """The messages listed in the CAST documentation (C and Cpp Analyzer 3.0, Log messages) are recognised,
    with the impact and the resolution the documentation gives."""

    SAMPLES = {   # invented names; the wording follows the documented messages
        "user-cancel": "Analysis canceled on user request.",
        "runtime-exception": "Run-time exception occurred, analysis canceled: out of memory",
        "send-preprocessed": "Please take a copy of the file '/data/a/pre.i' and send it to CAST, to help analyze the issue.",
        "unknown-exception": "Unknown exception occurred, analysis canceled.",
        "fatal-error": "Fatal error: something broke",
        "analysis-canceled": "Analysis canceled.",
        "invalid-positions": "Invalid positions (start, end) found for object Foo when computing CRC: 1, 2",
        "parser-error": "Parser error \\",
        "unexisting-paths": "Some unexisting paths where found in the configuration.",
        "invalid-include-path": "Invalid include path /opt/x/include, declared in environment profile 'ProfA'",
        "unknown-directive": "[Configuration] MY_EXPORT: Unknown identifier 'MY_EXPORT' is probably an unknown compilation directive.",
        "unable-open": "Unable to open file 'q.h' and to compute CRC. Reason: denied",
        "missing-header": "Preprocessor cannot find file 'q.h'. (file /data/a/b.c, line 3)",
        "selected-and-included": "Following file(s) is/are selected for analysis, while being also included by other analyzed file(s). "
                                 "Maybe you want to consider removing that/these file(s) from the selection: a.c",
        "pch-position": "Trying to include a precompiled header from another place than the start of the compiled file "
                        "(file 'a.c', line 9). This can cause strange behavior. PCH usage deactivated.",
        "empty-variable": "Empty variable name encountered (is that a C++ file?)",
        "several-objects": "Several definitions found for Foo. Two objects will be created: 1, 2",
        "several-symbol": "Several definitions found for symbol _Z3foov: 1, 2",
        "multiple-definitions": "Multiple definitions found for 'Foo'. A link will be traced towards each of these definitions: 1, 2",
        "unresolved-identifier": "Unresolved identifier Foo",
        "called-undeclared": "Function foo() is called without having been declared.",
        "no-parent": "No parent class nor namespace found for method bar. Object will be saved under its parent file only.",
        "now-a-type": "Unknown identifier MY_T is now considered as a type.",
        "system-functions": "Unable to access list of system functions implied in diags (strcpy, gets...).",
        "recursive-flag": "Flag 'recursive' has been set for include path '/opt/x'. This flag is generally of no use.",
        "no-executable-code": "File a.h has no executable code.",
        "parser-misc": "[Parser] XYZ: Ignored token 'XYZ'.",
    }

    def test_every_documented_message_is_recognised(self):
        m = _load_script()
        self.assertEqual(sorted(self.SAMPLES), sorted(e[0] for e in m.KNOWN_MESSAGES))      # none left untested
        for want, text in self.SAMPLES.items():
            got = m.match_known(m.message_template(text))
            self.assertEqual(got[0] if got else None, want, text)

    def test_messages_the_documentation_does_not_list_are_not_claimed(self):
        m = _load_script()
        for text in ("Preprocessor has found several possibilities for common.h. Chose closest : /x/common.h",
                     "Skipping illegal redefinition of typedef Int8.", "Parsing file (1/3) /data/a/b.c...",
                     "Compiling source files (3 items)..."):
            self.assertIsNone(m.match_known(m.message_template(text)), text)

    def test_ordinary_log_lists_documented_messages(self):
        data, report, _, _ = run({"a.log": build_log(3)})
        rows = {r["id"]: r for r in data["known_messages"]["rows"]}
        self.assertEqual(rows["missing-header"]["count"], 12)                      # 4 per source file, 3 files
        self.assertEqual(rows["missing-header"]["doc_level"], "Warning")
        self.assertEqual(rows["missing-header"]["levels"], ["WARNING"])
        self.assertIn("unknown-directive", rows)
        self.assertIn("parser-misc", rows)
        self.assertNotIn("several possibilities", " ".join(r["id"] for r in rows.values()))
        self.assertTrue(all(p["known"] in rows or p["known"] == "" for p in data["patterns"]))
        self.assertEqual(sum(p["count"] for p in data["patterns"] if p["known"]) + rows["missing-header"]["count"],
                         data["known_messages"]["documented_lines"])            # missing headers are not patterns
        self.assertIsNone(finding(data, "analysis-stopped"))
        self.assertIn("## Documented log messages", report)
        self.assertIn("An included file is missing", report)
        self.assertIn("Add the file or correct the include path.", report)
        self.assertNotIn("the analysis ended**", report)

    def test_a_message_saying_the_analysis_ended_is_stated_first(self):
        extra = ["{} [ERROR] Analysis canceled on user request.".format(ts(70)),
                 "{} [ERROR] Run-time exception occurred, analysis canceled: out of memory".format(ts(71)),
                 "{} [ERROR] Unable to open file 'q.h' and to compute CRC. Reason: denied".format(ts(72))]
        data, report, _, _ = run({"a.log": build_log(2, extra=extra)})
        f = finding(data, "analysis-stopped")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(len(f["evidence"]), 2)
        self.assertIn("Restart the analysis.", f["recommendation"])
        self.assertIn("Contact CAST Support.", f["recommendation"])
        e = finding(data, "documented-errors")
        self.assertEqual(len(e["evidence"]), 1)                                    # the documented-as-error message logged as ERROR
        self.assertIn("Unable to open a file", e["evidence"][0])
        self.assertIn("ERROR", e["evidence"][0])
        self.assertLess(report.index("the analysis ended**"), report.index("## Findings"))
        self.assertIn("### Analysis stops prematurely", report)
        self.assertIn("### Configuration problems", report)

    def test_error_documented_but_logged_as_warning_is_not_a_finding(self):
        data, report, _, _ = run({"a.log": build_log(2)})            # the ordinary [Configuration] ... unknown compilation directive
        self.assertIn("unknown-directive", [r["id"] for r in data["known_messages"]["rows"]])
        self.assertIsNone(finding(data, "documented-errors"))        # warnings in every C/C++ run are not "errors"
        self.assertIn("A macro or an include file is not defined", report)

    def test_documented_messages_are_masked_like_everything_else(self):
        extra = ["{} [ERROR] Fatal error: cannot reach connectPassword=\"hunter2secret\" connect to dbsrv02.lan.corp.acme:5432 failed".format(ts(70))]
        data, report, out, _ = run({"a.log": build_log(1, extra=extra)}, "--redact")
        blob = json.dumps(data) + report
        self.assertNotIn("hunter2secret", blob)
        self.assertNotIn("dbsrv02", blob)
        self.assertIsNotNone(finding(data, "analysis-stopped"))


class Masking(unittest.TestCase):
    SECRET = "Zx9Qv7pw"

    def test_credentials_are_masked_everywhere(self):
        lines = ["{} [ERROR] Connection failed: connectPassword=\"{}\" user=x".format(ts(70 + i), self.SECRET)
                 for i in range(3)]                                       # repeated: also goes through the memo
        lines.append("{} [WARNING] [Parser] Ignored token 'x'. Token: -password {}".format(ts(80), self.SECRET))
        data, report, out, _ = run({"a.log": build_log(1, extra=lines)})
        for f in out.iterdir():
            self.assertNotIn(self.SECRET, f.read_text(encoding="utf-8"), f.name)

    def test_memo_gives_the_same_result_as_mask_line(self):
        m = _load_script()
        cache = {}
        body = "[ERROR] connect -password {} done".format(self.SECRET)
        for i, stamp in enumerate(("2026-03-01 10:00:00.100", "2026-03-01 10:00:01.200", "2026-03-01 10:00:02.300")):
            line = stamp + " " + body
            self.assertEqual(m.masked_line(line, cache), m.mask_line(line))
        self.assertEqual(len(cache), 1)
        self.assertNotIn(self.SECRET, m.masked_line("2026-03-01 10:00:09.900 " + body, cache))
        short = "2026-03-01 10:00:00 [INFO] password=" + self.SECRET   # no milliseconds: no memo, still masked
        self.assertNotIn(self.SECRET, m.masked_line(short, cache))
        self.assertEqual(len(cache), 1)
        plain = "2026-03-01 10:00:00.100 [INFO] nothing to mask here"
        m.masked_line(plain, cache)
        key = plain[m.TS_LEN:]
        self.assertIs(cache[key], next(k for k in cache if k == key))      # one string stored, not two

    def test_redact_masks_paths_and_keeps_json_valid(self):
        data, report, out, _ = run({"a.log": build_log(2)}, "--redact", "--redact-term", "app1")
        text = report + (out / "cpp_warnings.json").read_text(encoding="utf-8")
        self.assertNotIn("/data/app1", text)
        self.assertNotIn("app1", text)
        self.assertIn("<path>", text)
        json.loads((out / "cpp_warnings.json").read_text(encoding="utf-8"))
        self.assertIn("topics.h", report)                                   # file names are kept

    def test_mask_option_on_stdin(self):
        r = subprocess.run([sys.executable, str(SCRIPT), "--mask"], input=("pwd=" + self.SECRET + "\n").encode(),
                           capture_output=True)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn(self.SECRET, r.stdout.decode())


# >>> shared-redaction tests: keep identical in both skills' tests/run_tests.py
import hashlib as _hashlib
import importlib.util as _ilu

SHARED_BLOCK_SHA = "7568b60f3fc4204d"   # update in BOTH skills when the shared block changes
REDACTION_SAMPLE = (r"-password Hunter2 --password tiger7 --pwd=x1 Authorization: Bearer eyJabc.def "
                    r"password=S3c; Unexpected token: '}' api_key=K9 host db01.example-corp.fr "
                    r"unc \\fileserver01\share\ACME\App.cs Connection string: LIBPQ:pgprod-db01:5432,castdb "
                    r"Server=sql01;Database=x jdbc:postgresql://dbhost:5432/cast https://doc.castsoftware.com/x "
                    r"System.IO version 1.0.0.0 at 10.1.2.3 /usr/share/CAST/Extensions/x.py "
                    r"/opt/cast/upload/APP1/A.cs C:\Users\jdoe\src\B.cs "
                    # round 4: quoted / JSON / XML / env-style / camelCase / YAML / CAST-encrypted
                    r"password=\"my secret\" '\"password\": \"jsonpw\"' <password>xmlpw</password> "
                    r"DB_PASSWORD=envpw PGPASSWORD=pgpw CAST_TOKEN=tok7 secret_key: yamlpw "
                    r"connectPassword=\"CRYPTED:CAA9FB4\" pwd=ab;cd -user castadm User ID=sqluser "
                    # must stay readable (all seen in real CAST logs)
                    r"[mscorlib]System.Security.Cryptography.PasswordDeriveBytes.+ctor(x) "
                    r"System.IdentityModel.Tokens.Jwt.JwtPayload Token(Token.Generic,'Uri',1,2) "
                    r"closing dn-sendcredentials Culture=neutral, PublicKeyToken=b77a5c561934e089")
MUST_GO = ["Hunter2", "tiger7", "x1", "eyJabc", "S3c", "K9", "example-corp", "fileserver01", "ACME",
           "pgprod-db01", "sql01", "dbhost", "10.1.2.3", "/opt/cast", "jdoe",
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
        for s in ["Hunter2", "tiger7", "eyJabc", "S3c", "K9", "my secret", "jsonpw", "xmlpw", "envpw",
                  "pgpw", "tok7", "yamlpw", "CAA9FB4", ";cd"]:
            self.assertNotIn(s, secrets_only)
        self.assertIn("example-corp.fr", secrets_only)               # hosts only masked with --redact
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
        cases = {"acme_mngt on CastStorageService _ dbsrv02.lan.corp.acme:5432": "acme_mngt on CastStorageService _ <host>:5432",
                 "-CONNECT_LOCAL('PostgreSQL','//dbsrv02.lan.corp.acme:5432/postgres')": "-CONNECT_LOCAL('PostgreSQL','//<host>:5432/postgres')",
                 "jdbc:postgresql://dbsrv02.lan.corp.acme:5432/db": "jdbc:postgresql://<host>:5432/db",
                 "connect to dbsrv02.lan.corp.acme:5432 failed": "connect to <host>:5432 failed"}
        for src, want in cases.items():
            self.assertEqual(m.redact_text(src, [], True), want)
        for keep in ("analyser.py:492", "formsreport_symbols/__init__.py:1713", "com.acme.billing.Foo:12"):
            self.assertEqual(m.redact_text(keep, [], True), keep)
# <<< shared-redaction tests



if __name__ == "__main__":
    unittest.main(verbosity=2)
