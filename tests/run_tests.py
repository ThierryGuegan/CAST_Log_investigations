#!/usr/bin/env python3
"""Tests for the CAST run inspector server. Run: python3 tests/run_tests.py (standard library only).

The server runs in this process on a free port and is driven over real HTTP.
"""
import atexit
import io
import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
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
