#!/usr/bin/env python3
"""Tests for the CAST run inspector server. Run: python3 tests/run_tests.py (standard library only).

The server runs in this process on a free port and is driven over real HTTP.
"""
import atexit
import io
import os
import json
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
import server  # noqa: E402

TMP = tempfile.mkdtemp(prefix="cast-gui-test-")
atexit.register(lambda: shutil.rmtree(TMP, ignore_errors=True))
SRV = server.make_server(0, Path(TMP) / "workspace")
threading.Thread(target=SRV.serve_forever, daemon=True).start()
BASE = "http://127.0.0.1:{}".format(SRV.server_address[1])
E = "/usr/share/CAST/Extensions/com.castsoftware.sqlanalyzer.3.7.24-funcrel"


def req(method, path, body=None, headers=None, raw=False):
    h = {"X-CAST-GUI": "1"} if method != "GET" else {}
    h.update(headers or {})
    data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
    if data is not None and not isinstance(body, bytes):
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r) as resp:
            out = resp.read()
            return resp.status, (out if raw else json.loads(out.decode()) if out[:1] in (b"{", b"[") else out)
    except urllib.error.HTTPError as e:
        out = e.read()
        try:
            return e.code, json.loads(out.decode())
        except ValueError:
            return e.code, out


def zip_bytes(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


ANALYZE = ("2026-10-01 20:00:00 [INFO] start\n2026-10-01 20:00:01 [INFO] starting Task Run SQL\n"
           "2026-10-01 20:30:00 [INFO] Return value: 0\n")
RUNANALYSIS = ("2026-10-01 20:00:02 [INFO] CARL Version: 3.2.6\n2026-10-01 20:00:02 [INFO] Connection string: "
               "LIBPQ:dbsrv02.lan.corp.acme:5432,db;password=S3cret!\n2026-10-01 20:29:00 [INFO] Return value: 0\n")
SQL = ("2026-10-01 20:05:00 [TRACEBACK] [com.castsoftware.sqlanalyzer] SQL-002: x Traceback (most recent call last):\n"
       '  File "{}/p.py", line 9, in f\n    a()\nKeyError: \'ACME_TABLE\'\n'
       "2026-10-01 20:05:01 [WARNING] Something odd in ACME\n").format(E)
SNAPSHOT = "2026-10-01 20:31:00 [INFO] snap\n2026-10-01 20:40:00 [INFO] Return value: 0\n"


def phase_zip_archive():
    """CAST 8.3 style: one zip per phase, with identically named files in two phases."""
    analyze = zip_bytes({"0-analyze.log": ANALYZE, "1-cast-ms-runanalysis-1.log": RUNANALYSIS, "4-sql.log": SQL,
                         "2-run-extensions.log": "2026-10-01 20:01:00 [INFO] a\n"})
    snapshot = zip_bytes({"0-snapshot.log": SNAPSHOT, "2-run-extensions.log": "2026-10-01 20:32:00 [INFO] b\n"})
    return zip_bytes({"analyze_logs(1).zip": analyze, "snapshot_logs.zip": snapshot})


def upload(data, name="run.zip", run_name=None):
    h = {"X-Filename": name}
    if run_name:
        h["X-Run-Name"] = run_name
    return req("POST", "/api/upload", data, h)


def analyse(run_id, **opts):
    code, _ = req("POST", "/api/runs/{}/analyse".format(run_id), opts)
    assert code == 202, code
    for _ in range(200):
        code, meta = req("GET", "/api/runs/{}".format(run_id))
        if meta["job"]["state"] in ("done", "failed"):
            return meta
        time.sleep(0.1)
    raise AssertionError("analysis did not finish")


class Archives(unittest.TestCase):
    def test_one_zip_per_phase_goes_into_phase_folders(self):
        code, body = upload(phase_zip_archive(), run_name="phases")
        self.assertEqual(code, 200, body)
        self.assertEqual(body["logs"], 6)
        inp = Path(body["run"]["input"])
        self.assertTrue((inp / "analyze" / "2-run-extensions.log").is_file())
        self.assertTrue((inp / "snapshot" / "2-run-extensions.log").is_file())   # not overwritten
        self.assertEqual(body["runs_found"], ["analyze/0-analyze.log"])

    def test_path_traversal_is_refused(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../evil.log", "x")
        code, body = upload(buf.getvalue())
        self.assertEqual(code, 400)
        self.assertIn("outside its folder", body["error"])
        self.assertFalse((Path(TMP) / "evil.log").exists())

    def test_symlink_entry_is_refused(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("link.log")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
        code, body = upload(buf.getvalue())
        self.assertEqual(code, 400)
        self.assertIn("symbolic link", body["error"])

    def test_not_a_zip_and_no_logs(self):
        self.assertEqual(upload(b"plain text")[0], 400)
        code, body = upload(zip_bytes({"readme.txt": "x"}))
        self.assertEqual((code, body["error"]), (400, "The archive contains no .log file."))

    def test_phase_folder_names(self):
        self.assertEqual(server.phase_folder_name("analyze_logs(1).zip"), "analyze")
        self.assertEqual(server.phase_folder_name("snapshot_indicator_logs.zip"), "snapshot_indicator")
        self.assertEqual(server.phase_folder_name("other.zip"), "other")


class Workflow(unittest.TestCase):
    def test_analyse_results_explain_export(self):
        _, body = upload(phase_zip_archive(), run_name="workflow")
        rid = body["run"]["id"]
        meta = analyse(rid)
        self.assertEqual(meta["job"]["state"], "done", meta["job"])
        code, res = req("GET", "/api/runs/{}/results".format(rid))
        self.assertEqual(res["logs_analysis"]["run_status"]["status"], "Completed")
        self.assertEqual([p["phase"] for p in res["logs_analysis"]["run_status"]["phases"]], ["analyze", "snapshot"])
        self.assertEqual(len(res["tracebacks"]["groups"]), 1)
        self.assertNotIn("S3cret", json.dumps(res))                               # credentials always masked
        sig = res["tracebacks"]["groups"][0]["signature_id"]
        code, saved = req("PUT", "/api/runs/{}/triggers".format(rid), {sig: "Table missing from the schema."})
        self.assertEqual((code, saved["todo"]), (200, 0))
        code, md = req("GET", "/api/runs/{}/file/tracebacks_report.md".format(rid), raw=True)
        self.assertIn(b"Table missing from the schema.", md)
        code, data = req("GET", "/api/runs/{}/export".format(rid), raw=True)
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        self.assertIn("{}/triggers.json".format(rid), names)
        code, body = req("GET", "/api/runs/{}/export?shared=1".format(rid))
        self.assertEqual(code, 409)                                               # not masked: no share pack

    def test_redacted_run_share_pack(self):
        _, body = upload(phase_zip_archive(), run_name="masked")
        rid = body["run"]["id"]
        analyse(rid, redact=True, redact_terms="acme")
        code, data = req("GET", "/api/runs/{}/export?shared=1".format(rid), raw=True)
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = [n.split("/")[-1] for n in zf.namelist()]
        self.assertNotIn("triggers.json", names)                                  # internal file never shared
        self.assertIn("triggers.shared.json", names)
        everything = b"".join(zf.read(n) for n in zf.namelist()).decode("utf-8", "replace").lower()
        self.assertNotIn("acme", everything)
        self.assertNotIn("dbsrv02", everything)

    def test_imported_explanations_are_used(self):
        _, body = upload(phase_zip_archive(), run_name="first")
        first = body["run"]["id"]
        analyse(first)
        _, res = req("GET", "/api/runs/{}/results".format(first))
        sig = res["tracebacks"]["groups"][0]["signature_id"]
        _, body = upload(phase_zip_archive(), run_name="second")
        second = body["run"]["id"]
        code, imp = req("POST", "/api/runs/{}/import-triggers".format(second), {sig: {"label": "x", "trigger": "Known cause."}})
        self.assertEqual(imp["imported"], 1)
        analyse(second)
        _, res = req("GET", "/api/runs/{}/results".format(second))
        self.assertEqual(res["triggers"][sig]["trigger"], "Known cause.")

    def test_folder_input_and_delete(self):
        folder = Path(TMP) / "logs_folder"
        folder.mkdir(exist_ok=True)
        (folder / "0-analyze.log").write_text(ANALYZE)
        (folder / "1-cast-ms-runanalysis-1.log").write_text(RUNANALYSIS)
        code, body = req("POST", "/api/folder", {"path": str(folder), "name": "from folder"})
        self.assertEqual(code, 200, body)
        rid = body["run"]["id"]
        analyse(rid)
        code, _ = req("DELETE", "/api/runs/{}".format(rid))
        self.assertEqual(code, 200)
        self.assertTrue((folder / "0-analyze.log").is_file())                     # original logs untouched
        self.assertEqual(req("GET", "/api/runs/{}".format(rid))[0], 404)


class AuditFixes(unittest.TestCase):
    def test_decompression_bomb_is_refused_before_extraction(self):
        bomb = zip_bytes({"0-analyze.log": "2026-10-01 20:00:00 x\n", "big.log": b"\0" * (20 * 1024 * 1024)})
        target = Path(TMP) / "bomb"
        with self.assertRaises(server.ExtractLimit):
            fd = Path(TMP) / "bomb.zip"; fd.write_bytes(bomb)
            server.extract_archive(fd, target, max_bytes=5 * 1024 * 1024)
        self.assertFalse((target / "big.log").exists())                        # nothing written
        nested = zip_bytes({"phase_logs.zip": bomb})                              # nested zips count too
        fd = Path(TMP) / "nested.zip"; fd.write_bytes(nested)
        with self.assertRaises(server.ExtractLimit):
            server.extract_archive(fd, Path(TMP) / "nested", max_bytes=5 * 1024 * 1024)
        old, SRV.max_extract = SRV.max_extract, 5 * 1024 * 1024                 # and through the server
        try:
            code, body = upload(bomb)
            self.assertEqual(code, 400)
            self.assertIn("extraction limit", body["error"])
        finally:
            SRV.max_extract = old

    def test_no_deletion_while_running_and_no_resurrection(self):
        folder = Path(TMP) / "slow"
        folder.mkdir(exist_ok=True)
        (folder / "0-analyze.log").write_text("".join("2026-10-01 20:%02d:00 [WARNING] w %d\n" % (i % 60, i) for i in range(150000)))
        code, body = req("POST", "/api/folder", {"path": str(folder)})
        rid = body["run"]["id"]
        req("POST", "/api/runs/{}/analyse".format(rid), {})
        code, body = req("DELETE", "/api/runs/{}".format(rid))
        self.assertEqual(code, 409)
        self.assertIn("being analysed", body["error"])
        for _ in range(300):
            if req("GET", "/api/runs/{}".format(rid))[1]["job"]["state"] != "running":
                break
            time.sleep(0.1)
        self.assertEqual(req("DELETE", "/api/runs/{}".format(rid))[0], 200)
        time.sleep(0.5)
        self.assertEqual(req("GET", "/api/runs/{}".format(rid))[0], 404)
        self.assertNotIn(rid, [r["id"] for r in req("GET", "/api/runs")[1]])

    def test_analyse_again_with_masking_keeps_explanations(self):
        _, body = upload(phase_zip_archive(), run_name="again")
        rid = body["run"]["id"]
        analyse(rid)
        _, res = req("GET", "/api/runs/{}/results".format(rid))
        sig = res["tracebacks"]["groups"][0]["signature_id"]
        req("PUT", "/api/runs/{}/triggers".format(rid), {sig: "Written before masking."})
        self.assertEqual(req("GET", "/api/runs/{}/export?shared=1".format(rid))[0], 409)
        analyse(rid, redact=True, redact_terms="acme")                              # no new upload
        code, data = req("GET", "/api/runs/{}/export?shared=1".format(rid), raw=True)
        self.assertEqual(code, 200)
        _, res = req("GET", "/api/runs/{}/results".format(rid))
        self.assertEqual(res["triggers"][sig]["trigger"], "Written before masking.")
        analyse(rid)                                                                 # unmasked again:
        out = Path(res["meta"]["input"]).parent / "Output"
        self.assertFalse((out / "triggers.shared.json").exists())                  # no stale masked copy

    def test_quoted_windows_path(self):
        folder = Path(TMP) / "quoted logs"
        folder.mkdir(exist_ok=True)
        (folder / "0-analyze.log").write_text(ANALYZE)
        code, body = req("POST", "/api/folder", {"path": '"{}"'.format(folder)})
        self.assertEqual(code, 200, body)


class CleanRuns(unittest.TestCase):
    """Cleaning old runs, and the Windows 'access denied' crash while saving meta.json."""

    def make_run(self, name, days_old, state="done"):
        ws = SRV.ws
        meta = ws.new_run(name)
        meta["created"] = (datetime.now() - timedelta(days=days_old)).isoformat(timespec="seconds")
        meta["job"] = {"state": state}
        ws.save_meta(meta["id"], meta)
        (ws.root / meta["id"] / "Input").mkdir(exist_ok=True)
        return meta["id"]

    def test_clean_deletes_only_old_runs_that_are_not_running(self):
        old, new = self.make_run("cl-old", 40), self.make_run("cl-new", 1)
        busy = self.make_run("cl-busy", 90, state="running")
        code, body = req("POST", "/api/runs/clean", {"older_than_days": 30, "dry_run": True})
        self.assertEqual(code, 200, body)
        self.assertEqual([m["id"] for m in body["matched"]], [old])
        self.assertEqual(body["deleted"], [])
        self.assertTrue((SRV.ws.root / old).is_dir())                              # preview deletes nothing
        code, body = req("POST", "/api/runs/clean", {"older_than_days": 30})
        self.assertEqual(body["deleted"], [old])
        self.assertFalse((SRV.ws.root / old).exists())
        self.assertTrue((SRV.ws.root / new).is_dir())
        self.assertTrue((SRV.ws.root / busy).is_dir())                             # being analysed: skipped
        for rid in (new, busy):
            SRV.ws.delete(rid, force=True)

    def test_clean_zero_days_and_bad_values(self):
        rid = self.make_run("cl-zero", 0)
        self.assertEqual(req("POST", "/api/runs/clean", {"older_than_days": "abc"})[0], 400)
        self.assertEqual(req("POST", "/api/runs/clean", {"older_than_days": -1})[0], 400)
        self.assertEqual(req("POST", "/api/runs/clean", {})[0], 400)
        _, body = req("POST", "/api/runs/clean", {"older_than_days": 0})
        self.assertIn(rid, body["deleted"])

    def test_clean_needs_the_gui_header(self):
        r = urllib.request.Request(BASE + "/api/runs/clean", data=b'{"older_than_days": 0}', method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        self.assertEqual(cm.exception.code, 403)

    def test_save_meta_retries_when_windows_denies_access(self):
        rid = self.make_run("cl-retry", 0)
        real, calls = os.replace, []

        def flaky(src, dst):
            calls.append(1)
            if len(calls) < 3:
                raise PermissionError(5, "Access is denied")
            return real(src, dst)
        os.replace = flaky
        try:
            meta = SRV.ws.meta(rid)
            meta["name"] = "renamed"
            SRV.ws.save_meta(rid, meta)
        finally:
            os.replace = real
        self.assertEqual(SRV.ws.meta(rid)["name"], "renamed")
        self.assertEqual(len(calls), 3)
        SRV.ws.delete(rid, force=True)

    def test_analysis_thread_crash_does_not_leave_run_running(self):
        rid = self.make_run("cl-crash", 0, state="new")
        real = server.subprocess.run

        def boom(*a, **k):
            raise OSError("cannot start")
        server.subprocess.run = boom
        try:
            SRV.ws.analyse(rid, {})
            for _ in range(100):
                if SRV.ws.meta(rid)["job"]["state"] != "running":
                    break
                time.sleep(0.05)
        finally:
            server.subprocess.run = real
        job = SRV.ws.meta(rid)["job"]
        self.assertEqual(job["state"], "failed")
        self.assertIn("cannot start", job["steps"][-1]["stderr"])
        SRV.ws.delete(rid)

    def test_run_left_running_by_a_stopped_server_is_closed_at_startup(self):
        rid = self.make_run("cl-stale", 0, state="running")
        server.Workspace(SRV.ws.root, (SRV.ws.logs_script, SRV.ws.tb_script))      # what a restart does
        job = SRV.ws.meta(rid)["job"]
        self.assertEqual(job["state"], "failed")
        self.assertEqual(job["steps"][-1]["step"], "Interrupted")
        SRV.ws.delete(rid)                                                        # now deletable without force


class MultiArchive(unittest.TestCase):
    """Several zips (one per phase) added to one run, each in its own folder."""

    def phase_zip(self, tag):
        return zip_bytes({"0-analyze.log": ANALYZE, "2-{}.log".format(tag): "x\n"})

    def test_second_archive_is_added_beside_the_first_never_merged(self):
        code, first = req("POST", "/api/upload", self.phase_zip("a"), {"X-Filename": "analyze_logs.zip", "X-Multi": "1", "X-Run-Name": "multi"})
        self.assertEqual(code, 200, first)
        rid = first["run"]["id"]
        code, second = req("POST", "/api/upload", self.phase_zip("b"), {"X-Filename": "snapshot_logs.zip", "X-Add-To": rid})
        self.assertEqual(code, 200, second)
        self.assertEqual(second["run"]["id"], rid)
        self.assertEqual(second["runs_found"], ["snapshot/0-analyze.log"])
        inp = Path(first["run"]["input"])
        self.assertTrue((inp / "analyze" / "0-analyze.log").is_file())
        self.assertTrue((inp / "snapshot" / "0-analyze.log").is_file())              # same file name, not overwritten
        code, third = req("POST", "/api/upload", self.phase_zip("c"), {"X-Filename": "snapshot_logs.zip", "X-Add-To": rid})
        self.assertTrue((inp / "snapshot_2" / "2-c.log").is_file())                  # same archive name: own folder
        SRV.ws.delete(rid)

    def test_cannot_add_to_a_missing_analysed_or_folder_run(self):
        self.assertEqual(req("POST", "/api/upload", self.phase_zip("a"), {"X-Add-To": "nope-20200101-000000"})[0], 404)
        _, up = req("POST", "/api/upload", self.phase_zip("a"), {"X-Filename": "one.zip", "X-Multi": "1"})
        rid = up["run"]["id"]
        analyse(rid)
        code, body = req("POST", "/api/upload", self.phase_zip("b"), {"X-Filename": "two.zip", "X-Add-To": rid})
        self.assertEqual(code, 409, body)
        SRV.ws.delete(rid)
        folder = Path(TMP) / "multi_folder"
        folder.mkdir(exist_ok=True)
        (folder / "0-analyze.log").write_text(ANALYZE)
        _, fr = req("POST", "/api/folder", {"path": str(folder)})
        code, body = req("POST", "/api/upload", self.phase_zip("b"), {"X-Filename": "two.zip", "X-Add-To": fr["run"]["id"]})
        self.assertEqual(code, 409, body)
        SRV.ws.delete(fr["run"]["id"])

    def test_a_bad_added_archive_leaves_the_run_intact(self):
        _, up = req("POST", "/api/upload", self.phase_zip("a"), {"X-Filename": "good.zip", "X-Multi": "1"})
        rid = up["run"]["id"]
        code, _ = req("POST", "/api/upload", zip_bytes({"readme.txt": "x"}), {"X-Filename": "nologs.zip", "X-Add-To": rid})
        self.assertEqual(code, 400)
        inp = Path(up["run"]["input"])
        self.assertTrue((inp / "good" / "0-analyze.log").is_file())
        self.assertFalse((inp / "nologs").exists())                                  # nothing left from the refused one
        SRV.ws.delete(rid)

    def test_single_archive_still_extracts_straight_into_input(self):
        _, up = req("POST", "/api/upload", self.phase_zip("a"), {"X-Filename": "plain.zip"})
        self.assertTrue((Path(up["run"]["input"]) / "0-analyze.log").is_file())
        self.assertEqual(up["runs_found"], ["0-analyze.log"])
        SRV.ws.delete(up["run"]["id"])

    def test_known_folder_is_exposed_to_warn_about_duplicates(self):
        folder = Path(TMP) / "dup_folder"
        folder.mkdir(exist_ok=True)
        (folder / "0-analyze.log").write_text(ANALYZE)
        _, chk = req("POST", "/api/folder/check", {"path": str(folder)})
        _, fr = req("POST", "/api/folder", {"path": str(folder)})
        _, runs = req("GET", "/api/runs")
        mine = [r for r in runs if r["id"] == fr["run"]["id"]][0]
        self.assertEqual(mine["input"], chk["path"])                                 # same string: the page compares them
        zipped = req("POST", "/api/upload", self.phase_zip("a"), {"X-Filename": "z.zip"})[1]["run"]["id"]
        self.assertIsNone([r for r in req("GET", "/api/runs")[1] if r["id"] == zipped][0]["input"])
        SRV.ws.delete(fr["run"]["id"])
        SRV.ws.delete(zipped)


class AddRunChecks(unittest.TestCase):
    def test_folder_check_previews_without_creating_a_run(self):
        folder = Path(TMP) / "check_folder"
        folder.mkdir(exist_ok=True)
        (folder / "0-analyze.log").write_text(ANALYZE)
        (folder / "1-cast-ms-runanalysis-1.log").write_text(RUNANALYSIS)
        before = len(req("GET", "/api/runs")[1])
        code, body = req("POST", "/api/folder/check", {"path": '"{}"'.format(folder)})   # quotes from "Copy as path"
        self.assertEqual(code, 200, body)
        self.assertEqual((body["logs"], body["runs_found"], body["name"]), (2, ["0-analyze.log"], "check_folder"))
        self.assertEqual(body["bytes"], sum(p.stat().st_size for p in folder.iterdir()))
        self.assertEqual(len(req("GET", "/api/runs")[1]), before)

    def test_limits_are_published_for_the_page(self):
        code, body = req("GET", "/api/limits")
        self.assertEqual(code, 200)
        self.assertEqual(body, {"max_upload": SRV.max_upload, "max_extract": SRV.max_extract})

    def test_folder_check_errors_and_header(self):
        empty = Path(TMP) / "check_empty"
        empty.mkdir(exist_ok=True)
        self.assertEqual(req("POST", "/api/folder/check", {"path": str(empty)})[0], 400)
        self.assertEqual(req("POST", "/api/folder/check", {"path": str(Path(TMP) / "nope")})[0], 400)
        r = urllib.request.Request(BASE + "/api/folder/check", data=b'{"path": "x"}', method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        self.assertEqual(cm.exception.code, 403)


class CppSkill(unittest.TestCase):
    """analyze-cpp-warnings is the third analysis step; it only shows up for C/C++ analyzer logs."""

    @staticmethod
    def cpp_log(units=2, total=None):
        total = total or units
        lines = ["2026-03-01 10:00:00.100 [INFO] +root path:/data/acme/src",
                 "2026-03-01 10:00:01.100 [INFO] Compiling source files ({} items)...".format(total)]
        for k in range(1, units + 1):
            lines.append("2026-03-01 10:00:{:02d}.100 [INFO] Parsing file ({}/{}) /data/acme/src/m/f{}.c...".format(k + 1, k, total, k))
            lines.append("2026-03-01 10:00:{:02d}.200 [WARNING] Preprocessor cannot find file 'stdio.h'. "
                         "(file /data/acme/src/m/gen.h, line 3)".format(k + 1))
            lines.append("2026-03-01 10:00:{:02d}.300 [WARNING] [Parser] SDK_BOOL: Ignored token 'SDK_BOOL'. "
                         "[file '/data/acme/src/m/gen.h'(5,7)]\t/data/acme/src/m/gen.h".format(k + 1))
        return "\n".join(lines) + "\n"

    def test_cpp_run_gets_results_files_and_export(self):
        _, body = upload(zip_bytes({"analyze/4-cpp.log": self.cpp_log(2, total=5)}), run_name="cpp-run")
        rid = body["run"]["id"]
        meta = analyse(rid)
        self.assertEqual(meta["job"]["state"], "done", meta["job"])
        self.assertEqual([s["step"] for s in meta["job"]["steps"]],
                         ["Timing and environment", "Errors and warnings", "C/C++ warnings"])
        self.assertFalse(meta["job"]["steps"][-1].get("skipped"))
        code, res = req("GET", "/api/runs/{}/results".format(rid))
        cw = res["cpp_warnings"]
        self.assertEqual(cw["totals"]["warnings"], 4)
        self.assertFalse(cw["logs"][0]["all_files_reached"])                       # 2 of 5: shown as unfinished
        self.assertIn("missing-system-headers", [f["id"] for f in cw["findings"]])
        known = {r["id"]: r for r in cw["known_messages"]["rows"]}                 # documented messages, shown by the C/C++ tab
        self.assertEqual(known["missing-header"]["count"], 2)
        self.assertEqual(known["parser-misc"]["doc_level"], "Warning")
        code, md = req("GET", "/api/runs/{}/file/cpp_warnings_report.md".format(rid), raw=True)
        self.assertEqual(code, 200)
        self.assertIn(b"did not finish", md)
        code, data = req("GET", "/api/runs/{}/export".format(rid), raw=True)
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        for n in ("cpp_warnings_report.md", "cpp_warnings.json"):
            self.assertIn("{}/{}".format(rid, n), names)

    def test_run_without_cpp_logs_skips_the_step_and_does_not_fail(self):
        _, body = upload(phase_zip_archive(), run_name="no-cpp")
        rid = body["run"]["id"]
        out = SRV.ws.run_dir(rid) / "Output"
        out.mkdir(exist_ok=True)
        (out / "cpp_warnings.json").write_text("{}", encoding="utf-8")          # left by an earlier analysis
        meta = analyse(rid)
        self.assertEqual(meta["job"]["state"], "done", meta["job"])
        step = meta["job"]["steps"][-1]
        self.assertEqual((step["step"], step["exit"], step.get("skipped")), ("C/C++ warnings", 0, True))
        code, res = req("GET", "/api/runs/{}/results".format(rid))
        self.assertIsNone(res["cpp_warnings"])
        self.assertFalse((out / "cpp_warnings.json").exists())
        code, data = req("GET", "/api/runs/{}/export".format(rid), raw=True)
        self.assertFalse([n for n in zipfile.ZipFile(io.BytesIO(data)).namelist() if "cpp_warnings" in n])

    def test_masking_options_reach_the_cpp_step(self):
        _, body = upload(zip_bytes({"4-cpp.log": self.cpp_log(1)}), run_name="cpp-masked")
        rid = body["run"]["id"]
        meta = analyse(rid, redact=True, redact_terms=["acme"])
        self.assertEqual(meta["job"]["state"], "done", meta["job"])
        out = SRV.ws.run_dir(rid) / "Output"
        text = (out / "cpp_warnings.json").read_text(encoding="utf-8") + (out / "cpp_warnings_report.md").read_text(encoding="utf-8")
        self.assertNotIn("acme", text.lower())
        self.assertIn("gen.h", text)

    def test_older_skills_folder_without_the_cpp_skill_still_works(self):
        skills = Path(TMP) / "old-skills"
        for name in ("analyze-logs", "analyze-tracebacks"):
            shutil.copytree(str(HERE / "skills" / name), str(skills / name), ignore=shutil.ignore_patterns("tests", "__pycache__"))
        scripts = server.find_scripts(skills)
        self.assertIsNone(scripts[2])
        ws = server.Workspace(Path(TMP) / "ws-old", scripts)
        self.assertIsNone(ws.cpp_script)
        self.assertEqual(server.find_scripts(None)[2].name, "analyze_cpp_warnings.py")


class GuiPage(unittest.TestCase):
    def test_every_function_the_page_calls_is_defined(self):
        """A refactor once deleted uploadZip(), which silently broke every zip upload."""
        with urllib.request.urlopen(BASE + "/") as resp:
            page = resp.read().decode()
        script = page.split("<script>")[1]
        defined = set(re.findall(r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)", script))
        defined |= set(re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=", script))
        called = set(re.findall(r"(?<![.\w])(upload\w*|start\w*|show\w*|tab\w*|load\w*|open\w*|render\w*|read\w*|remember\w*|clean\w*)\(", script))
        self.assertEqual(sorted(c for c in called if c not in defined), [])
        self.assertIn("function tabCpp", script)                                  # the C/C++ tab exists
        self.assertIn("known_messages", script)                                   # ...the documented messages of the C/C++ tab
        self.assertIn("function cppCompare", script)                              # ...and its part of Compare runs
        self.assertIn("${cppCompare(A, B)}", script)                              # which tabCompare actually calls


class Security(unittest.TestCase):
    def test_writes_need_the_gui_header(self):
        r = urllib.request.Request(BASE + "/api/upload", data=b"x", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        self.assertEqual(cm.exception.code, 403)

    def test_foreign_host_header_is_refused(self):
        r = urllib.request.Request(BASE + "/api/runs", headers={"Host": "evil.example:80"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(r)
        self.assertEqual(cm.exception.code, 403)

    def test_run_ids_cannot_escape_the_workspace(self):
        for bad in ("..", "..%2F..", "a%20b"):
            self.assertEqual(req("GET", "/api/runs/{}/results".format(bad))[0], 404)
        self.assertEqual(req("GET", "/api/runs/x/file/..%2Fmeta.json")[0], 404)

    def test_page_is_served_with_a_restrictive_policy(self):
        with urllib.request.urlopen(BASE + "/") as resp:
            self.assertIn("default-src 'self'", resp.headers["Content-Security-Policy"])
            page = resp.read().decode()
        self.assertIn("CAST run inspector", page)
        self.assertNotIn("http://", page.split("<script>")[1].replace("http://www.w3.org/2000/svg", ""))  # nothing external


if __name__ == "__main__":
    unittest.main(verbosity=2)
