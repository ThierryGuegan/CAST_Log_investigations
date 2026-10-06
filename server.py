#!/usr/bin/env python3
"""CAST run inspector: a local web GUI for the analyze-logs and analyze-tracebacks skills.

The GUI never analyses anything itself: it runs the two skill scripts and displays the JSON
they write, so every fix to the scripts reaches the GUI and their tests keep covering the logic.

Standard library only, Python 3.8+. Listens on 127.0.0.1 only.

Usage:
  python3 server.py [--port 8765] [--workspace ./workspace] [--skills-dir DIR] [--no-browser]
"""
import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,100}$")
OUTPUT_FILES = ("logs_analysis_report.md", "tracebacks_report.md", "logs_analysis.json", "tracebacks.json",
                "triggers.json", "triggers.shared.json")
INTERNAL_ONLY = ("triggers.json", "triggers.json.bak")
CHUNK = 1024 * 1024


# --------------------------------------------------------------------------- skill scripts
def find_scripts(skills_dir=None):
    """The two skill scripts: --skills-dir, else ./skills next to this file, else installed skills."""
    bases = [Path(skills_dir)] if skills_dir else [
        HERE / "skills", HERE.parent, Path.home() / ".claude" / "skills", Path("/mnt/skills/user")]
    for base in bases:
        logs = base / "analyze-logs" / "scripts" / "analyze_logs.py"
        tbs = base / "analyze-tracebacks" / "scripts" / "analyze_tracebacks.py"
        if logs.is_file() and tbs.is_file():
            return logs, tbs
    raise SystemExit("The skill scripts were not found. Pass --skills-dir pointing to the folder that "
                     "contains analyze-logs/ and analyze-tracebacks/.")


# --------------------------------------------------------------------------- archives
def _check_members(zf, dest):
    dest = dest.resolve()
    for m in zf.infolist():
        target = (dest / m.filename).resolve()
        if target != dest and dest not in target.parents:
            raise ValueError("The archive contains a path outside its folder: {}".format(m.filename))
        if (m.external_attr >> 16) & 0o170000 == 0o120000:      # Unix symlink entry
            raise ValueError("The archive contains a symbolic link, which is not allowed: {}".format(m.filename))


def phase_folder_name(zip_name):
    """analyze_logs(1).zip -> analyze ; snapshot_logs.zip -> snapshot ; other.zip -> other"""
    stem = re.sub(r"\.zip$", "", zip_name, flags=re.I)
    stem = re.sub(r"(_logs)?(\(\d+\))?$", "", stem, flags=re.I)
    return stem or "archive"


class ExtractLimit(ValueError):
    pass


def _reserve(zf, budget):
    """Check the declared uncompressed size BEFORE extracting: a small archive can expand to
    gigabytes (decompression bomb), and nested zips multiply it."""
    need = sum(i.file_size for i in zf.infolist())
    if need > budget[0]:
        raise ExtractLimit("Unpacking would need {:.1f} GB, more than the {:.1f} GB left in the extraction limit. "
                           "Start the server with a higher --max-extract-gb if this archive is genuine."
                           .format(need / 1024 ** 3, budget[0] / 1024 ** 3))
    budget[0] -= need


def extract_archive(zip_path, input_dir, max_depth=3, max_bytes=20 * 1024 ** 3):
    """Extract an uploaded archive. Inner zips that contain logs (one zip per phase, as in CAST 8.3
    exports) are each extracted into their own folder named after the phase, never all into one
    folder: several phases contain files with the same name."""
    input_dir.mkdir(parents=True, exist_ok=True)
    budget = [max_bytes]                    # shared by the archive and every nested zip
    with zipfile.ZipFile(zip_path) as zf:
        _check_members(zf, input_dir)
        _reserve(zf, budget)
        zf.extractall(input_dir)
    for _ in range(max_depth):
        inner = [p for p in input_dir.rglob("*.zip") if p.is_file()]
        if not inner:
            break
        for z in inner:
            try:
                with zipfile.ZipFile(z) as zf:
                    names = zf.namelist()
                    if not any(n.lower().endswith(".log") or n.lower().endswith(".zip") for n in names):
                        continue                    # not a log archive (e.g. zipped sources): leave it
                    target = z.parent / phase_folder_name(z.name)
                    n = 2
                    while target.exists():
                        target = z.parent / "{}_{}".format(phase_folder_name(z.name), n)
                        n += 1
                    _check_members(zf, target)
                    _reserve(zf, budget)
                    zf.extractall(target)
            except zipfile.BadZipFile:
                continue
            z.unlink()
    logs = [p for p in input_dir.rglob("*.log") if p.is_file()]
    runs = [str(p.relative_to(input_dir)) for p in logs if p.name == "0-analyze.log"]
    return len(logs), runs


# --------------------------------------------------------------------------- workspace
class Workspace(object):
    def __init__(self, root, scripts):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.logs_script, self.tb_script = scripts
        self.lock = threading.Lock()

    def run_dir(self, run_id):
        if not RUN_ID_RE.match(run_id or ""):
            raise KeyError(run_id)
        d = self.root / run_id
        if not (d / "meta.json").is_file():
            raise KeyError(run_id)
        return d

    def meta(self, run_id):
        return json.loads((self.run_dir(run_id) / "meta.json").read_text(encoding="utf-8"))

    def save_meta(self, run_id, meta):
        d = self.root / run_id
        if not d.is_dir():                  # deleted meanwhile: never recreate it
            return
        tmp = d / "meta.json.tmp"
        tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        os.replace(str(tmp), str(d / "meta.json"))

    def new_run(self, name, input_path=None):
        base = re.sub(r"[^A-Za-z0-9_.\-]+", "_", name or "run").strip("._-")[:60] or "run"
        with self.lock:
            run_id = "{}-{}".format(base, datetime.now().strftime("%Y%m%d-%H%M%S"))
            n = 2
            while (self.root / run_id).exists():
                run_id = "{}-{}-{}".format(base, datetime.now().strftime("%Y%m%d-%H%M%S"), n)
                n += 1
            (self.root / run_id).mkdir()
        meta = {"id": run_id, "name": name or base, "created": datetime.now().isoformat(timespec="seconds"),
                "input": str(Path(input_path).resolve()) if input_path else str(self.root / run_id / "Input"),
                "external_input": bool(input_path), "job": {"state": "new"}, "options": {}}
        self.save_meta(run_id, meta)
        return meta

    def list_runs(self):
        out = []
        for d in sorted(self.root.iterdir(), key=lambda p: p.name, reverse=True):
            m = d / "meta.json"
            if m.is_file():
                meta = json.loads(m.read_text(encoding="utf-8"))
                status = None
                lj = d / "Output" / "logs_analysis.json"
                if lj.is_file():
                    try:
                        status = json.loads(lj.read_text(encoding="utf-8")).get("run_status", {}).get("status")
                    except ValueError:
                        pass
                out.append({"id": meta["id"], "name": meta["name"], "created": meta["created"],
                            "state": meta["job"]["state"], "status": status})
        return out

    def delete(self, run_id, force=False):
        d = self.run_dir(run_id)
        if not force and self.meta(run_id)["job"].get("state") == "running":
            raise RuntimeError("This run is being analysed. Wait for the analysis to finish, then delete it.")
        shutil.rmtree(str(d))

    # ---- analysis
    def script_args(self, options):
        args = []
        if options.get("redact"):
            args.append("--redact")
        for t in options.get("redact_terms", []):
            if t.strip():
                args += ["--redact-term", t.strip()]
        return args

    def analyse(self, run_id, options):
        meta = self.meta(run_id)
        if meta["job"].get("state") == "running":
            raise RuntimeError("An analysis is already running for this run.")
        meta["options"] = options
        meta["job"] = {"state": "running", "started": time.time(), "steps": []}
        shared = self.run_dir(run_id) / "Output" / "triggers.shared.json"
        if shared.is_file() and not (options.get("redact") or options.get("redact_terms")):
            shared.unlink()                 # left from an earlier masked analysis: now out of date
        self.save_meta(run_id, meta)
        threading.Thread(target=self._analyse, args=(run_id, options), daemon=True).start()

    def _analyse(self, run_id, options):
        d = self.root / run_id
        meta = self.meta(run_id)
        out = d / "Output"
        common = self.script_args(options)
        logs_cmd = [sys.executable, str(self.logs_script), "--input", meta["input"], "--output", str(out), "--json",
                    "--gap-minutes", str(options.get("gap_minutes", 5)),
                    "--top-silences", str(options.get("top_silences", 20))] + common
        tb_cmd = [sys.executable, str(self.tb_script), "--input", meta["input"], "--output", str(out),
                  "--top-warnings", str(options.get("top_warnings", 30)),
                  "--top-errors", str(options.get("top_errors", 50))] + common
        imported = d / "import_triggers.json"
        if imported.is_file():
            tb_cmd += ["--triggers", str(imported)]
        state = "done"
        for label, cmd in (("Timing and environment", logs_cmd), ("Errors and warnings", tb_cmd)):
            p = subprocess.run(cmd, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
            meta["job"]["steps"].append({"step": label, "exit": p.returncode,
                                         "stdout": p.stdout.decode("utf-8", "replace")[-4000:],
                                         "stderr": p.stderr.decode("utf-8", "replace")[-8000:]})
            self.save_meta(run_id, meta)
            if p.returncode != 0:
                state = "failed"
                break
        meta["job"].update(state=state, finished=time.time())
        self.save_meta(run_id, meta)

    def results(self, run_id):
        out = self.run_dir(run_id) / "Output"
        res = {"meta": self.meta(run_id)}
        for name in ("logs_analysis.json", "tracebacks.json", "triggers.json"):
            p = out / name
            res[name.split(".")[0]] = json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None
        return res

    def save_triggers(self, run_id, updates):
        """Update explanation texts only (never keys), keep a backup, then re-render the report."""
        d = self.run_dir(run_id)
        path = d / "Output" / "triggers.json"
        current = json.loads(path.read_text(encoding="utf-8"))
        for k, text in updates.items():
            if k in current and isinstance(text, str):
                current[k]["trigger"] = text.strip()
        shutil.copyfile(str(path), str(path) + ".bak")
        tmp = path.with_name("triggers.json.tmp")
        tmp.write_text(json.dumps(current, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(str(tmp), str(path))
        cmd = [sys.executable, str(self.tb_script), "--render-only", "--output", str(d / "Output")] + \
            self.script_args(self.meta(run_id).get("options", {}))
        p = subprocess.run(cmd, capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode("utf-8", "replace")[-2000:])
        m = re.search(r"Triggers to fill in .*: (\d+)", p.stdout.decode("utf-8", "replace"))
        return int(m.group(1)) if m else None

    def export(self, run_id, shared):
        meta = self.meta(run_id)
        out = self.run_dir(run_id) / "Output"
        redacted = meta.get("options", {}).get("redact") or meta.get("options", {}).get("redact_terms")
        if shared and not redacted:
            raise PermissionError("This run was analysed without redaction. Analyse it again with "
                                  "redaction on before making a pack to share.")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(out.iterdir()):
                if not p.is_file() or p.suffix == ".tmp":
                    continue
                if shared and p.name in INTERNAL_ONLY:
                    continue                        # the share pack never contains the internal triggers
                if not shared and p.name == "triggers.json.bak":
                    continue
                zf.write(str(p), "{}/{}".format(run_id, p.name))
        return buf.getvalue()


# --------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "CASTRunInspector/1.0"

    def log_message(self, fmt, *args):        # quiet console
        pass

    # ---- helpers
    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")    # blocks DNS-rebinding pages

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _error(self, code, message):
        self._send(code, {"error": message})

    def _json_body(self, limit=5 * CHUNK):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise ValueError("Request too large.")
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _guard_write(self):
        # A custom header cannot be sent cross-site without a CORS preflight, which this server never
        # answers: pages from other sites therefore cannot trigger analyses or deletions.
        if self.headers.get("X-CAST-GUI") != "1":
            self._error(403, "Missing X-CAST-GUI header.")
            return False
        return True

    def _route(self):
        parts = [p for p in self.path.split("?")[0].split("/") if p]
        query = dict(q.split("=", 1) for q in self.path.split("?", 1)[1].split("&") if "=" in q) \
            if "?" in self.path else {}
        return parts, query

    # ---- verbs
    def do_GET(self):
        if not self._host_ok():
            return self._error(403, "Use http://127.0.0.1 or http://localhost.")
        parts, query = self._route()
        ws = self.server.ws
        try:
            if not parts:
                return self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            if parts == ["api", "runs"]:
                return self._send(200, ws.list_runs())
            if len(parts) == 3 and parts[:2] == ["api", "runs"]:
                return self._send(200, ws.meta(parts[2]))
            if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "results":
                return self._send(200, ws.results(parts[2]))
            if len(parts) == 5 and parts[:2] == ["api", "runs"] and parts[3] == "file" and parts[4] in OUTPUT_FILES:
                p = ws.run_dir(parts[2]) / "Output" / parts[4]
                if not p.is_file():
                    return self._error(404, "Not produced yet.")
                ctype = "text/markdown; charset=utf-8" if p.suffix == ".md" else "application/json; charset=utf-8"
                return self._send(200, p.read_bytes(), ctype,
                                  {"Content-Disposition": 'attachment; filename="{}"'.format(p.name)})
            if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "export":
                shared = query.get("shared") == "1"
                data = ws.export(parts[2], shared)
                name = "{}{}.zip".format(parts[2], "-share" if shared else "")
                return self._send(200, data, "application/zip",
                                  {"Content-Disposition": 'attachment; filename="{}"'.format(name)})
            return self._error(404, "Unknown address.")
        except KeyError:
            return self._error(404, "No such run.")
        except PermissionError as e:
            return self._error(409, str(e))

    def do_POST(self):
        if not self._host_ok():
            return self._error(403, "Use http://127.0.0.1 or http://localhost.")
        if not self._guard_write():
            return
        parts, _ = self._route()
        ws = self.server.ws
        try:
            if parts == ["api", "upload"]:
                return self._upload()
            if parts == ["api", "folder"]:
                body = self._json_body()
                # Windows "Copy as path" wraps the path in double quotes
                folder = Path(str(body.get("path", "")).strip().strip('"').strip("'").strip()).expanduser()
                if not folder.is_dir():
                    return self._error(400, "Folder not found: {}".format(folder))
                logs = [p for p in folder.rglob("*.log") if p.is_file()]
                if not logs:
                    return self._error(400, "That folder contains no .log file.")
                meta = ws.new_run(body.get("name") or folder.name, input_path=folder)
                runs = [str(p.relative_to(folder)) for p in logs if p.name == "0-analyze.log"]
                return self._send(200, {"run": meta, "logs": len(logs), "runs_found": runs})
            if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "analyse":
                ws.analyse(parts[2], self._options(self._json_body()))
                return self._send(202, {"state": "running"})
            if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "import-triggers":
                body = self._json_body()
                if not isinstance(body, dict):
                    return self._error(400, "The triggers file must contain a JSON object.")
                d = ws.run_dir(parts[2])
                (d / "import_triggers.json").write_text(json.dumps(body, ensure_ascii=False), encoding="utf-8")
                return self._send(200, {"imported": sum(1 for v in body.values()
                                                        if isinstance(v, dict) and v.get("trigger"))})
            return self._error(404, "Unknown address.")
        except KeyError:
            return self._error(404, "No such run.")
        except ValueError as e:
            return self._error(400, str(e))
        except RuntimeError as e:
            return self._error(409, str(e))

    def do_PUT(self):
        if not self._host_ok():
            return self._error(403, "Use http://127.0.0.1 or http://localhost.")
        if not self._guard_write():
            return
        parts, _ = self._route()
        try:
            if len(parts) == 4 and parts[:2] == ["api", "runs"] and parts[3] == "triggers":
                todo = self.server.ws.save_triggers(parts[2], self._json_body())
                return self._send(200, {"saved": True, "todo": todo})
            return self._error(404, "Unknown address.")
        except KeyError:
            return self._error(404, "No such run.")
        except (ValueError, RuntimeError) as e:
            return self._error(400, str(e))

    def do_DELETE(self):
        if not self._host_ok():
            return self._error(403, "Use http://127.0.0.1 or http://localhost.")
        if not self._guard_write():
            return
        parts, _ = self._route()
        try:
            if len(parts) == 3 and parts[:2] == ["api", "runs"]:
                self.server.ws.delete(parts[2])
                return self._send(200, {"deleted": parts[2]})
            return self._error(404, "Unknown address.")
        except KeyError:
            return self._error(404, "No such run.")
        except RuntimeError as e:
            return self._error(409, str(e))

    # ---- endpoints
    def _options(self, body):
        def num(key, default, lo, hi):
            try:
                v = float(body.get(key, default))
            except (TypeError, ValueError):
                v = default
            return max(lo, min(hi, v))
        terms = body.get("redact_terms") or []
        if isinstance(terms, str):
            terms = [t for t in re.split(r"[,\n]", terms)]
        return {"redact": bool(body.get("redact")), "redact_terms": [t.strip() for t in terms if t.strip()][:20],
                "gap_minutes": num("gap_minutes", 5, 0, 1440), "top_warnings": int(num("top_warnings", 30, 0, 1000)),
                "top_errors": int(num("top_errors", 50, 0, 1000)), "top_silences": int(num("top_silences", 20, 0, 1000))}

    def _upload(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return self._error(400, "Empty upload.")
        if n > self.server.max_upload:
            return self._error(413, "The archive is larger than the limit ({} GB).".format(self.server.max_upload // 1024 ** 3))
        name = self.headers.get("X-Filename", "run.zip")
        ws = self.server.ws
        fd, tmp = tempfile.mkstemp(suffix=".zip", dir=str(ws.root))
        try:
            with os.fdopen(fd, "wb") as f:
                left = n
                while left > 0:
                    chunk = self.rfile.read(min(CHUNK, left))
                    if not chunk:
                        break
                    f.write(chunk)
                    left -= len(chunk)
            if not zipfile.is_zipfile(tmp):
                return self._error(400, "That file is not a zip archive.")
            meta = ws.new_run(self.headers.get("X-Run-Name") or phase_folder_name(Path(name).name))
            try:
                nlogs, runs = extract_archive(Path(tmp), Path(meta["input"]), max_bytes=self.server.max_extract)
            except ValueError as e:
                ws.delete(meta["id"], force=True)
                return self._error(400, str(e))
            if nlogs == 0:
                ws.delete(meta["id"], force=True)
                return self._error(400, "The archive contains no .log file.")
            return self._send(200, {"run": meta, "logs": nlogs, "runs_found": runs})
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


def make_server(port, workspace, skills_dir=None, max_upload_gb=4, max_extract_gb=20):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.ws = Workspace(workspace, find_scripts(skills_dir))
    srv.max_upload = int(max_upload_gb * 1024 ** 3)
    srv.max_extract = int(max_extract_gb * 1024 ** 3)
    return srv


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--workspace", default=str(HERE / "workspace"), help="where runs and reports are kept")
    ap.add_argument("--skills-dir", help="folder containing analyze-logs/ and analyze-tracebacks/")
    ap.add_argument("--max-upload-gb", type=float, default=4, help="largest archive accepted")
    ap.add_argument("--max-extract-gb", type=float, default=20,
                    help="largest total size an archive may unpack to, nested zips included")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    srv = make_server(args.port, args.workspace, args.skills_dir, args.max_upload_gb, args.max_extract_gb)
    url = "http://127.0.0.1:{}/".format(srv.server_address[1])
    print("CAST run inspector: {}  (workspace: {})".format(url, srv.ws.root))
    print("Skills: {}".format(srv.ws.logs_script.parent.parent.parent))
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
