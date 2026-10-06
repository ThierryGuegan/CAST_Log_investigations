#!/usr/bin/env python3
"""Analyze a folder of CAST analysis logs.

Produces a markdown report with:
  * environment configuration (CARL/CAIP versions, LISA/LTSA, connection string, KB schema)
  * CAST extensions used, with versions (from 0-analyze.log)
  * execution timeline (start / end / duration per log file)
  * total execution time, run-wide silent periods (no log wrote anything) and active time
  * silent stretches inside each log, with the line before and after

Standard library only, Python 3.8+. Works on Windows and Linux.

Usage:
  python analyze_logs.py [--input Input] [--output Output] [--json]
                         [--gap-minutes 5] [--redact] [--redact-term TEXT ...]
"""
import argparse
import io
import json
import re
import sys
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path

HEAD_LINES = 200            # environment block lives near the top of a log

# Values stop at a tab: CAST 8.3 analyzer logs put more columns after the message.
ENV_FIELDS = [
    ("CARL Version", re.compile(r"CARL Version:\s*([^\t\r]+)")),
    ("CAIP Version", re.compile(r"(?:CAIP|Software) Version:\s*([^\t\r]+)")),
    ("LISA Folder", re.compile(r"LISA Folder:\s*([^\t\r]+)")),
    ("LTSA Folder", re.compile(r"LTSA Folder:\s*([^\t\r]+)")),
    ("Connection string", re.compile(r"Connection string:\s*([^\t\r]+)")),
    ("Knowledge Base Schema", re.compile(r"Knowledge Base on Schema:\s*([^\t\r]+)")),
]
ENV_HEAD_LINES = 2000
_ENV_HINTS = ("Version:", "Folder:", "Connection string:", "connectionProfile:", "Knowledge Base on Schema:")
# used only when the primary label is absent from every log (CAST 8.3 has no "Connection string:")
ENV_FALLBACKS = {"Connection string": re.compile(r"-?connectionProfile:\s*([^\t\r]+)")}

EXT_TOKEN_RE = re.compile(r"com\.castsoftware\.[A-Za-z0-9_.\-]+")
EXT_SPLIT_RE = re.compile(
    r"^(com\.castsoftware\.[A-Za-z0-9_.\-]+?)\.(\d+(?:\.\d+)*(?:-[A-Za-z0-9]+)*)$")
VERSION_AFTER_RE = re.compile(
    r"^['\"]?\s*(?:\(?\s*version\s*[:=]?\s*|v)?(\d+(?:\.\d+)+(?:-[A-Za-z0-9]+)*)", re.I)
VERSION_ON_LINE_RE = re.compile(r"\bversion\b\W{0,3}(\d+(?:\.\d+)+(?:-[A-Za-z0-9]+)*)", re.I)
EXT_LINE_KEYWORDS = re.compile(r"download|install|\bload|\bused?\b|\busing\b", re.I)


# --------------------------------------------------------------------------- I/O helpers
def iter_lines(path):
    return read_lines(path)                 # encoding rules shared with analyze-tracebacks


def head_lines(path, n=HEAD_LINES):
    out = []
    for i, line in enumerate(iter_lines(path)):
        if i >= n:
            break
        out.append(line)
    return out


_ORCH_PREFIXES = ("INF:", "WRN:", "ERR:", "DBG:", "FTL:", "FAT:")


def ts_text(line):
    """The line from its leading timestamp on: after spaces / "[" and after an orchestration-log
    level prefix ("INF: 2026-09-26 00:59:46: message", CAST 8.3 / AIP Console)."""
    s = line.lstrip(" \t[")
    if s[:4] in _ORCH_PREFIXES:
        s = s[4:].lstrip()
    return s


def line_ts(line):
    """Timestamp at the START of a line (optionally after spaces or '['), else None.

    Dates inside the message text are ignored on purpose: "backup made 2019-01-01 10:00:00"
    must not become a log's start time. Parsing is positional for speed.
    """
    s = ts_text(line)
    if len(s) < 19 or s[4] != "-" or s[7] != "-" or s[13] != ":" or s[16] != ":" or s[10] not in " T":
        return None
    try:
        return datetime(int(s[0:4]), int(s[5:7]), int(s[8:10]),
                        int(s[11:13]), int(s[14:16]), int(s[17:19]))
    except ValueError:
        return None


# --------------------------------------------------------------------------- per-log scan
DST_BACK_MONTHS = (3, 4, 10, 11)            # clocks go back: Oct/Nov (north), Mar/Apr (south)
DST_FORWARD_MONTHS = (3, 9, 10)             # clocks go forward: Mar (north), Sep/Oct (south)
DST_CONFIRM = 3                             # distinct later timestamps that must stay "back"


def dst_plausible(raw_ts, back):
    """A clock going back for daylight saving: ~1h, at night, on a Sunday of a change month."""
    return (timedelta(minutes=50) <= back <= timedelta(minutes=70) and raw_ts.weekday() == 6
            and raw_ts.month in DST_BACK_MONTHS and 0 <= raw_ts.hour <= 3)


def scan_log(path, gap_s):
    """One streaming pass over a log.

    Timestamps that go backwards (threads writing out of order) never move the clock back.
    Returns start, end, the silent stretches inside the log (>= gap_s) and the log's
    activity segments (runs of lines less than gap_s apart), used for run-wide silence.
    """
    start = end = raw_end = None
    gaps, segments, clock_changes = [], [], []
    offset = timedelta(0)                   # added after a clock change back (autumn DST)
    candidate = None                        # possible clock change, awaiting confirmation
    prev_key = prev_line = late_key = None
    seg_start = seg_first_line = seg_start_raw = None
    for line in iter_lines(path):
        key = ts_text(line)[:19]
        if key == prev_key:                 # same second as the latest line: no new info
            prev_line = line
            continue
        if key == late_key:                 # same second as the last out-of-order line
            continue
        ts = line_ts(line)
        if ts is None:
            continue
        raw_ts, ts = ts, ts + offset
        if start is None:
            start, seg_start, seg_first_line, seg_start_raw = ts, ts, line, raw_ts
        elif ts < end:
            # Earlier than the latest time seen. Usually an out-of-order or replayed line, which
            # is ignored. A daylight-saving change only if it is plausible AND the clock really
            # keeps running from the earlier time (DST_CONFIRM distinct timestamps in a row).
            if candidate is None and dst_plausible(raw_ts, end - ts):
                candidate = {"at": raw_ts, "n": 0}
            if candidate is not None:
                candidate["n"] += 1
                if candidate["n"] >= DST_CONFIRM:
                    offset += timedelta(hours=1)
                    clock_changes.append({"at": candidate["at"], "shift": timedelta(hours=1), "kind": "back"})
                    candidate = None
                    ts = raw_ts + offset
                    if ts < end:            # still behind after the correction: ignore this line
                        late_key = key
                        continue
                else:
                    late_key = key
                    continue
            else:                           # out-of-order line (multi-threaded logs): ignored, so
                late_key = key              # neither the clock nor "last line before" moves back
                continue
        elif gap_s and (ts - end).total_seconds() >= gap_s:
            # seconds use corrected time; from/to are shown on the log's own clock
            gaps.append({"seconds": (ts - end).total_seconds(), "from": raw_end, "to": raw_ts,
                         "before": prev_line, "after": line})
            segments.append((seg_start, end, seg_first_line, prev_line, seg_start_raw, raw_end))
            seg_start, seg_first_line, seg_start_raw = ts, line, raw_ts
        candidate = None                    # time moved forward again: any candidate was a stray line
        end, raw_end, prev_key, prev_line = ts, raw_ts, key, line
    if start is not None:
        segments.append((seg_start, end, seg_first_line, prev_line, seg_start_raw, raw_end))
    for g in gaps:                          # spring DST: a ~1h jump at night on a Sunday
        a = g["from"]
        if 3300 <= g["seconds"] <= 3900 and a.weekday() == 6 and a.month in DST_FORWARD_MONTHS and 0 <= a.hour <= 3:
            clock_changes.append({"at": a, "shift": timedelta(hours=1), "kind": "forward?"})
    # end: corrected (continuous) time for durations; raw_end: the log's own clock, for display
    return start, end, gaps, segments, clock_changes, raw_end


def fmt_duration(delta):
    secs = int(delta.total_seconds())
    if secs < 0:
        return "negative (clock issue?)"
    d, rem = divmod(secs, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return "{}d {}h {}m {}s".format(d, h, m, s)


def fmt_ts(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "N/A"


def run_wide_silence(seg_list, gap_s):
    """Complement of the union of all activity segments: periods where no log wrote anything.

    seg_list items: (start, end, first_line, last_line, start_raw, end_raw, file). Times are
    corrected for clock changes; *_raw are the logs' own clock, used for display. A silent
    period of gap_s or more contains no line from any log, so it lies between merged segments.
    """
    if not seg_list:
        return []
    # merged item: [start, end, first_line, first_file, last_line, last_file, start_raw, end_raw]
    seg_list = sorted(seg_list, key=lambda s: s[0])
    merged = []
    for st, en, first, last, st_raw, en_raw, f in seg_list:
        if merged and st <= merged[-1][1]:
            if en > merged[-1][1]:
                merged[-1][1], merged[-1][4], merged[-1][5], merged[-1][7] = en, last, f, en_raw
        else:
            merged.append([st, en, first, f, last, f, st_raw, en_raw])
    silent = []
    for a, b in zip(merged, merged[1:]):
        if (b[0] - a[1]).total_seconds() >= gap_s:
            silent.append({"from": a[7], "to": b[6], "seconds": (b[0] - a[1]).total_seconds(),
                           "before": a[4], "before_file": a[5],
                           "after": b[2], "after_file": b[3]})
    return silent


# --------------------------------------------------------------------------- run status
RETURN_RE = re.compile(r"Return value:\s*(-?\d+)")
START_TASK_RE = re.compile(r"starting Task\s+(.+?)\s*$")


def phase_results(input_dir, logs, starts):
    """One row per pipeline phase: each phase's orchestration log (0-<phase>.log) ends with its
    own "Return value: N". Some phases never log one (exclude-files, restore-files, ...):
    those are "not logged", which is not a failure."""
    rows = []
    for p in logs:
        if not p.name.startswith("0-"):
            continue
        value = None
        for line in iter_lines(p):
            m = RETURN_RE.search(line)
            if m:
                value = int(m.group(1))
        rel = str(p.relative_to(input_dir))
        start = starts.get(rel)
        folder = Path(rel).parent
        if start is None and str(folder) != ".":     # e.g. 0-accept.log is only an argument dump:
            start = min((v for k, v in starts.items()  # use the phase folder's earliest log
                         if v and Path(k).parent == folder), default=None)
        rows.append({"phase": p.stem[2:], "log": rel, "return_value": value, "start": start,
                     "result": "not logged" if value is None else ("OK" if value == 0 else "Failed")})
    rows.sort(key=lambda r: (r["start"] is None, r["start"] or datetime.min, r["phase"]))
    for r in rows:
        r["start"] = fmt_ts(r["start"]) if r["start"] else None
    return rows


SUMMARY_STATUS_RE = re.compile(r"^\s*Status:\s*(.+?)\s*$")


def execution_summary(input_dir, logs):
    """CAST 8.3 writes an execution summary ("Status: Execution succeeded") next to the
    analysis logs: an independent second source for the run's outcome."""
    for p in logs:
        if "execution-summary" in p.name.lower():
            for line in iter_lines(p):
                m = SUMMARY_STATUS_RE.match(line)
                if m:
                    return {"status": m.group(1), "source": str(p.relative_to(input_dir))}
    return None


def run_status(input_dir, logs, starts=None):
    """Overall status from every phase, plus the analysis detail (Completed / Failed /
    Did not finish) read from the run-analysis log(s).

    A completed CAST run ends its run-analysis log with "Return value: 0"; a failure has a
    non-zero value. No return value means the logs stop before the end (collected while the
    run was still going, or the process was killed): then the last task started is named.
    """
    phases = phase_results(input_dir, logs, starts or {})
    st = _analysis_status(input_dir, logs)
    summary = execution_summary(input_dir, logs)
    if summary:
        st["summary"] = summary
        if "fail" in summary["status"].lower() and st["status"] != "Failed":
            st = dict(st, status="Failed", summary_failed=True)
    failed = [r for r in phases if r["result"] == "Failed"]
    if failed:                              # any failing phase fails the run, whatever the analysis says
        st = dict(st, status="Failed", failed_phases=[r["phase"] for r in failed])
    st["phases"] = phases
    return st


def _analysis_status(input_dir, logs):
    runlogs = [p for p in logs if "runanalysis" in p.name.lower()]
    if not runlogs:
        return {"status": "Unknown", "detail": "no run-analysis log found"}
    value, where = None, None
    for p in runlogs:
        for line in iter_lines(p):
            m = RETURN_RE.search(line)
            if m:
                value, where = int(m.group(1)), p
    if value is not None:
        return {"status": "Completed" if value == 0 else "Failed", "return_value": value,
                "source": str(where.relative_to(input_dir))}
    # the last two tasks started: the last one alone is often housekeeping started alongside
    # the real step (e.g. "Clean dependency dataset" right after an analyzer)
    tasks = []
    for p in [q for q in logs if q.name == "0-analyze.log"] + runlogs:
        for line in iter_lines(p):
            m = START_TASK_RE.search(line)
            if m and (not tasks or tasks[-1] != m.group(1)):
                tasks.append(m.group(1))
        if tasks:
            break
    return {"status": "Did not finish", "last_tasks": tasks[-2:],
            "source": str(runlogs[-1].relative_to(input_dir))}


# --------------------------------------------------------------------------- environment
def redact_secrets(conn):
    return mask_secrets(conn)           # single masking path, shared with every other output


def extract_env(logs, warnings):
    """Each field from the first log that has it, within each log's first ENV_HEAD_LINES lines.
    CAST 9 / Imaging writes them in one block (with "CARL Version:"); CAST 8.3 spreads them
    over several logs and has no CARL line."""
    env = OrderedDict((k, None) for k, _ in ENV_FIELDS)
    fallback = {k: None for k in ENV_FALLBACKS}
    where, carl_values = {}, set()
    for p in logs:
        for n, line in enumerate(iter_lines(p)):
            if n >= ENV_HEAD_LINES:         # real logs write these fields early (deepest seen: line 295)
                break
            # cheap pre-check: only lines holding one of the labels reach the patterns
            if not any(k in line for k in _ENV_HINTS):
                continue
            for key, rx in ENV_FIELDS:
                m = rx.search(line)
                if m:
                    val = m.group(1).strip()
                    if key == "CARL Version":
                        carl_values.add(val)
                    if env[key] is None and val:
                        env[key], where[key] = val, p
            for key, rx in ENV_FALLBACKS.items():
                if fallback[key] is None:
                    m = rx.search(line)
                    if m and m.group(1).strip():
                        fallback[key] = m.group(1).strip()
                        where.setdefault("_fallback_" + key, p)
        if all(env.values()):
            break
    for key, val in fallback.items():
        if env[key] is None and val:
            env[key] = val
    if env["Connection string"]:
        env["Connection string"] = redact_secrets(env["Connection string"])
    missing = [k for k, v in env.items() if not v]
    if len(missing) == len(env):
        warnings.append("No environment information found in any log.")
    if len(carl_values) > 1:
        warnings.append("Different CARL versions across logs: " + ", ".join(sorted(carl_values)))
    # source shown in the report: the log holding the version line (as with CAST 9's CARL block)
    src = where.get("CARL Version") or where.get("CAIP Version") or next(iter(where.values()), None)
    return env, src


# --------------------------------------------------------------------------- extensions
def split_ext(token, line, token_end, single_on_line):
    token = token.rstrip(".-")
    m = EXT_SPLIT_RE.match(token)
    if m:
        return m.group(1), m.group(2)
    after = VERSION_AFTER_RE.match(line[token_end:].lstrip(" '\""))
    if after:
        return token, after.group(1)
    if single_on_line:                      # a "version x" phrase is only unambiguous then
        near = VERSION_ON_LINE_RE.search(line)
        if near:
            return token, near.group(1)
    return token, None


PLUGIN_PATH_RE = re.compile(r"[\\/]Extensions[\\/](com\.castsoftware\.[A-Za-z0-9_.\-]+?\.\d+(?:\.\d+)*(?:-[A-Za-z0-9]+)*)(?=[\\/])")
# CAST 8.3 install log, "extensions file dump": "com.castsoftware.x=1.2.3-funcrel" lines are
# extensions with their version. Its "com.castsoftware.x ( 1.0.0.0 - UpToDate )" lines are
# installed COMPONENTS (internal.platform.ADG, jee.migration, ...) with component versions
# (nodejs shows 1.0.0.0 there, 2.11.0-funcrel in its plugin folder): they are not used.
DUMP_EQ_RE = re.compile(r"^(com\.castsoftware\.[A-Za-z0-9_.\-]+?)=(\d+(?:\.\d+)*(?:-[A-Za-z0-9]+)*)")
# extensions name themselves in their log lines: "... [com.castsoftware.php] message"
TAG_RE = re.compile(r"\[(com\.castsoftware\.[A-Za-z0-9_.\-]+)\]")
DOWNLOAD_RE = re.compile(r"(?:Downloading|Installing|already downloaded|Installed)\D{0,30}'?(com\.castsoftware\.[A-Za-z0-9_.\-]+?\.\d+(?:\.\d+)*(?:-[A-Za-z0-9]+)*)'?", re.I)


def _extensions_elsewhere(input_dir, warnings):
    """Extensions when 0-analyze.log has none (CAST 8.3): the versioned Extensions folders the
    analyzers load plugins from, the install log's "name=version" lines, download / install
    lines, and the extensions' own log tags "[com.castsoftware.x]" (name only: an analysis-only
    archive may contain no plugin path at all)."""
    found, first, tagged = {}, None, set()
    for p in sorted(q for q in input_dir.rglob("*.log") if q.is_file()):
        for line in iter_lines(p):
            if "com.castsoftware" not in line:
                continue
            st = line.strip()
            dm = DUMP_EQ_RE.match(st)
            if dm:
                found.setdefault(dm.group(1), set()).add(dm.group(2))
                first = first or p
            for rx in (PLUGIN_PATH_RE, DOWNLOAD_RE):
                for m in rx.finditer(line):
                    sm = EXT_SPLIT_RE.match(m.group(1))
                    if sm:
                        found.setdefault(sm.group(1), set()).add(sm.group(2))
                        first = first or p
            for m in TAG_RE.finditer(line):     # name only: the version comes from paths, if any
                if not EXT_SPLIT_RE.match(m.group(1)):
                    tagged.add(m.group(1))
                    first = first or p
    for name in tagged:
        found.setdefault(name, set())
    if found:
        warnings.append("0-analyze.log lists no extensions (CAST 8.3 layout); taken from the plugin paths, the "
                        "install lines and the extensions' own log tags ([com.castsoftware.x]); a version that "
                        "appears nowhere in the logs is shown as 'unknown'.")
        return found, first
    return None


def extract_extensions(input_dir, warnings):
    analyze = sorted(input_dir.rglob("0-analyze.log"))
    if not analyze:
        warnings.append("No '0-analyze.log' found; extension list unavailable.")
        return OrderedDict(), None
    if len(analyze) > 1:
        warnings.append("Several 0-analyze.log files found; using " + str(analyze[0].relative_to(input_dir)))
    path = analyze[0]
    preferred, fallback = {}, {}
    for line in iter_lines(path):
        if "extension" not in line.lower():
            continue
        target = preferred if EXT_LINE_KEYWORDS.search(line) else fallback
        tokens = list(EXT_TOKEN_RE.finditer(line))
        for m in tokens:
            name, ver = split_ext(m.group(0), line, m.end(), len(tokens) == 1)
            target.setdefault(name, set())
            if ver:
                target[name].add(ver)
    found = preferred or fallback
    if not found:                           # CAST 8.3: 0-analyze.log lists none
        found, path = _extensions_elsewhere(input_dir, warnings) or ({}, path)
    result = OrderedDict()
    for name in sorted(found):
        vers = sorted(found[name])
        if len(vers) > 1:
            warnings.append("{} appears with several versions: {}".format(name, ", ".join(vers)))
        result[name] = ", ".join(vers) if vers else "unknown"
    if not result:
        warnings.append("0-analyze.log contains no recognisable com.castsoftware.* extension lines.")
    return result, path


# --------------------------------------------------------------------------- redaction
# >>> shared-redaction: keep byte-identical in analyze_logs.py and analyze_tracebacks.py
# (tests/run_tests.py checks a fingerprint of this block in each skill)
# Credential keys are matched by CONTENT, so prefixed / camelCase / env-style names are caught
# (connectPassword, DB_PASSWORD, PGPASSWORD, CAST_TOKEN, secret_key, api-token ...).
_PASSY = r"password|passwd|passphrase|passcode|pwd"
_OTHER = r"secret|token|apikey|api_key|api-key|accesskey|access_key|privatekey|private_key|credential"
_KEY = r"[A-Za-z0-9_.\-]*?(?:" + _PASSY + "|" + _OTHER + r")s?[A-Za-z0-9_.\-]*"
# unquoted value: stops at whitespace, quotes, "<>", "," "&", and at ';' that starts the next
# key=value. Brackets are part of the value: a password may contain them (Pass(word)1), so a
# closing bracket of the surrounding text may be masked too, which is only cosmetic.
# Backticks and pipes are never part of a value: they are report syntax (code spans, tables).
_UNQUOTED = r"(?:[^\s'\"<>,&;`|]|;(?!\s*[\w .]+=|\s*$))+"
# quoted values may use escaped quotes, as in JSON logged as a string: \"password\": \"x\"
_VALUE = r"(?:\\?\"(?:[^\"\\]|\\(?!\"))*\\?\"|'[^']*'|" + _UNQUOTED + ")"
_CRED_KV_RE = re.compile(r"(?i)(?<![\w.\-])(\\?\"?)(" + _KEY + r")(\1)(\s*[=:]\s*)(" + _VALUE + ")")
_CRED_CLI_RE = re.compile(r"(?i)(?<![\w\-])(-{1,2}" + _KEY + r")(\s+|=)(" + _VALUE + ")")
_CRED_XML_RE = re.compile(r"(?i)(<(" + _KEY + r")\b[^>]*>)([^<]*)(</\2\s*>)")
_PASSY_RE = re.compile(r"(?i)" + _PASSY)
SECRET_RES = [
    (re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?:(?:bearer|basic|token|negotiate)\s+)?[^\s;,'\"]+"), r"\1****"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=\-]{8,}"), r"\1****"),
    (re.compile(r"(://[^:/@\s]+):[^@\s]+@"), r"\1:****@"),            # scheme://user:pass@host
    (re.compile(r"\bCRYPTED:[A-Za-z0-9+/=]+"), "CRYPTED:****"),        # CAST encrypted credentials
]


# Code in traceback source lines, not secrets. Deliberately narrow, because real passwords
# such as Pass(word)1, P@ss(1) or Summer.Rain must still be masked:
#  - a call with no argument or a lowercase name as argument, where the value may stop at a
#    quote: get_secret("db") -> "get_secret(", parser.next_token(), read(path)
#  - a Python attribute: lowercase dotted name, e.g. self.connection_password
# Known limits: an all-lowercase dotted password (summer.rain), or one shaped exactly like a
# call with a lowercase argument (Pass(word)), is taken for code.
_CODE_CALL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*\((?:[a-z_][a-z0-9_.]*)?\)*")
_CODE_ATTR_RE = re.compile(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)+")


def _is_code(v):
    return bool(_CODE_CALL_RE.fullmatch(v) or _CODE_ATTR_RE.fullmatch(v))


def _mask_value(v):
    if v.startswith('\\"'):
        return '\\"****\\"'
    if v[:1] in "\"'" and v[-1:] == v[:1] and len(v) >= 2:
        return v[0] + "****" + v[0]
    return "****"


def _kv(m):
    key, sep, val = m.group(2), m.group(4), m.group(5)
    # "***" too: a quoted line cut at the report's width may end in a partial mask
    if val.strip("\\\"'").startswith("***") or key.lower() == "publickeytoken":
        return m.group(0)                   # PublicKeyToken: public .NET assembly identity
    if val[:1] not in "\"'\\" and _is_code(val):
        return m.group(0)
    # "Unexpected token: '}'" and similar parser messages: a bare token/key word with ':'
    # is a message, not a credential. Password-like keys are masked with any separator.
    if ":" in sep and not m.group(1) and not _PASSY_RE.search(key) and key.lower() in (
            "token", "tokens", "secret", "credential", "credentials"):
        return m.group(0)
    return m.group(1) + key + m.group(3) + sep + _mask_value(val)


_CRED_HINTS = ("pass", "pwd", "secret", "token", "credential", "crypted", "bearer", "authoriz",
               "apikey", "api_key", "api-key", "accesskey", "access_key", "privatekey", "private_key", "@")


def mask_line(line):
    """Cheap pre-check, then mask. Use on every log line AS IT IS READ, so nothing derived
    from it (templates, sample values, truncated quotes, labels) can carry a secret.
    Plain substring tests on the lowercased line: ~7x faster than a regex pre-check."""
    low = line.lower()
    return mask_secrets(line) if any(k in low for k in _CRED_HINTS) else line


def map_strings(obj, fn, skip_keys=()):
    """Apply fn to every string in a JSON-able structure (dict keys included). Mask DATA before
    json.dumps: masking serialised JSON text corrupts escapes and produces invalid JSON."""
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):                # always a plain ordered dict: rebuilding a dict
        return OrderedDict((fn(k) if isinstance(k, str) else k,   # subclass such as Counter
                            v if k in skip_keys else map_strings(v, fn, skip_keys))  # would corrupt it
                           for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return [map_strings(v, fn, skip_keys) for v in obj]
    return obj


def mask_secrets(text):
    """Always applied to every output: log lines are quoted verbatim in reports."""
    text = _CRED_XML_RE.sub(lambda m: m.group(1) + "****" + m.group(4), text)
    text = _CRED_CLI_RE.sub(lambda m: m.group(0) if (m.group(3).strip("\"'").startswith("***") or
                                                     (m.group(3)[:1] not in "\"'" and _is_code(m.group(3))))
                            else m.group(1) + m.group(2) + _mask_value(m.group(3)), text)
    text = _CRED_KV_RE.sub(_kv, text)
    for rx, repl in SECRET_RES:
        text = rx.sub(repl, text)
    return text


_TLDS = ("com|net|org|io|info|biz|local|lan|corp|internal|intra|intranet|cloud|"
         "fr|de|eu|ch|be|uk|nl|es|it|lu|at|pl|pt|se|dk|no|fi|ie|cz|us|ca|au|jp|cn|br")
HOST_RES = [
    # host part of a CAST connection string: "Connection string: LIBPQ:<host>:5432,db"
    (re.compile(r"(Connection string:\s*[A-Za-z0-9_]+:)([^:,;\s]+)"), r"\1<host>"),
    # host=... / Server=... / Data Source=...
    (re.compile(r"(?i)\b(host|hostname|server|data source|address|addr)(\s*=\s*)[^;,\s'\"&]+"), r"\1\2<host>"),
    # CAST 8.3 connection profiles: "<profile> on CastStorageService _ <host>:<port>"
    (re.compile(r"(CastStorageService\s*_\s*)[^\s:,;'\"]+"), r"\1<host>"),
    # any host followed by a port, whatever its domain (private ones such as server.lan.corp.acme):
    # at least three labels, so file references such as analyser.py:492 are not touched
    (re.compile(r"(?<![\w.\-/\\@])(?![\w.\-]*castsoftware)[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+){2,}(?=:\d{2,5}\b)"),
     "<host>"),
    # scheme-less "//host:port/db" (CAST 8.3 DssRun connection strings)
    (re.compile(r"(?<![\w:])//(?![\w.\-]*castsoftware)[A-Za-z0-9][\w\-]*(?:\.[\w\-]+)*(?=:\d{2,5}\b)"), "//<host>"),
    # scheme://[user@]host  (CAST's own sites are kept)
    # (the scheme may start only where no scheme character precedes it, and is at most 16 chars:
    #  an unanchored "[a-z][a-z0-9+.-]*://" is quadratic on long dotted lines)
    (re.compile(r"(?i)((?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]{0,15}://(?:[^@/\s]{0,256}@)?)"
                r"(?![\w.\-]{0,256}castsoftware)[^/:\s'\"<>|`]+"), r"\1<host>"),
]
USER_RES = [
    # -user X / --username X / user=X / User ID=X / uid=X / "user": "X"
    (re.compile(r"(?i)(?<![\w\-])(-{1,2}(?:user|username|login))(\s+|=)[^\s\]\)'\"]+"), r"\1\2<user>"),
    (re.compile(r"(?i)(?<![\w.\-])(\"?)(user|username|user id|userid|uid|login)(\1)(\s*[=:]\s*)"
                r"(?:\"[^\"]*\"|'[^']*'|[^;,\s'\"&)\]}]+)"), r"\1\2\3\4<user>"),
]
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
# lowercase only: CamelCase .NET namespaces such as System.IO are not hosts
FQDN_RE = re.compile(r"(?<![\w.\-])(?![\w.\-]*castsoftware)(?:[a-z0-9][a-z0-9\-]*\.)+(?:" + _TLDS + r")(?![\w.\-])")
UNC_RE = re.compile(r"\\\\[^\\\s|`'\"()<>,;]+\\(?:[^\\\s|`'\"()<>,;]+\\)*")
UNIX_PATH_RE = re.compile(r"(?<![\w.:/\\<])(/(?:[^\s/|`'\"()<>,;]+/)+)")
# Windows paths with either separator: C:\cast-node\... and c:/cast-node/... (both occur in CAST logs)
WIN_PATH_RE = re.compile(r"(?<![\w\\/])([A-Za-z]:[\\/](?:[^\\/\s|`'\"()<>,;]+[\\/])+)")
CAST_DIR_RE = re.compile(r"[\\/](?:CAST|CASTMS)[\\/]")   # case-sensitive: /opt/cast/... is customer data
_PLACEHOLDER = r"<(?:path|host|ip|user|redacted)>|\*\*\*\*"


def redact_text(text, terms, full):
    """full=True masks hosts, IPs, user names and non-CAST absolute paths (file names are
    kept); terms are masked in any case. Call mask_secrets first."""
    if full:
        for rx, repl in HOST_RES + USER_RES:
            text = rx.sub(repl, text)

        def ip(m):                          # 4-part NuGet/assembly versions are not IPs
            before = m.string[max(0, m.start() - 9):m.start()].lower()
            return m.group(0) if "version" in before else "<ip>"
        text = IPV4_RE.sub(ip, text)
        text = FQDN_RE.sub("<host>", text)
        text = UNC_RE.sub(r"<path>\\", text)
        text = UNIX_PATH_RE.sub(lambda m: m.group(1) if CAST_DIR_RE.search(m.group(1)) else "<path>/", text)
        text = WIN_PATH_RE.sub(lambda m: m.group(1) if CAST_DIR_RE.search(m.group(1))
                               else "<path>" + m.group(1)[2], text)          # keep the path's own separator
    terms = [t for t in terms if t]
    if terms:                               # placeholders are protected: a term like "path" or
        rx = re.compile("(" + _PLACEHOLDER + ")|" +   # "ip" must not turn <path> into <<redacted>>
                        "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True)), re.I)
        text = rx.sub(lambda m: m.group(1) or "<redacted>", text)
    return text
def mask_text(text, terms=(), full=False):
    """Mask any text the way reports are masked (used by --mask for lines quoted in chat)."""
    return redact_text("\n".join(mask_secrets(l) for l in text.split("\n")), list(terms), full)


# --- encoding detection (shared so both skills read files identically)
def _sniff_utf16(sample):
    """UTF-16 without a BOM (written by some Windows tools): ASCII text then has a NUL in
    every other byte. Returns 'utf-16-le', 'utf-16-be' or None."""
    if len(sample) < 8:
        return None
    odd, even = sample[1::2], sample[0::2]
    if odd.count(0) > 0.4 * len(odd) and even.count(0) < 0.05 * len(even):
        return "utf-16-le"
    if even.count(0) > 0.4 * len(even) and odd.count(0) < 0.05 * len(odd):
        return "utf-16-be"
    return None
# Bytes that are common French letters in the OEM console code page 850 (é è ç ê â î ë ï ü É)
# but rare symbols in Windows-1252 (‚ Š ‡ ˆ ƒ Œ ‰ ‹, or unassigned). Ambiguous bytes such as
# 0x85 (à / …) or 0x92 (Æ / ’) are deliberately not counted.
_CP850_EVIDENCE = frozenset(b"\x82\x8a\x87\x88\x83\x8c\x89\x8b\x81\x90")


def _legacy_codepage(raw):
    """Windows-1252 (ANSI) unless the line clearly is code page 850 (console tools' output on
    French Windows), whose accented letters would otherwise turn into punctuation."""
    oem = sum(1 for b in raw if b in _CP850_EVIDENCE)
    ansi = sum(1 for b in raw if b >= 0xC0)          # Windows-1252 accented letters
    return "cp850" if oem > ansi else "cp1252"


def decode_line(raw):
    """UTF-8 when valid, else Windows-1252 or code page 850 (see _legacy_codepage): Windows
    tools often write log lines in a legacy code page. A byte-order mark at the start of any
    line (logs concatenated on Windows) is removed, so its timestamp is still recognised."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode(_legacy_codepage(raw), errors="replace")
    return text.lstrip("\ufeff")


def read_lines(path):
    """Yield a log's lines as text, whatever its encoding: UTF-16 with or without a BOM, or
    UTF-8 / Windows-1252 decided line by line (files mixing both are common)."""
    with open(path, "rb") as f:
        sample = f.read(4096)
    enc = "utf-16" if sample.startswith((b"\xff\xfe", b"\xfe\xff")) else _sniff_utf16(sample)
    if enc:
        with open(path, encoding=enc, errors="replace") as f:
            for line in f:
                yield line.rstrip("\r\n").lstrip("\ufeff")
        return
    with open(path, "rb") as f:
        for raw in f:
            yield decode_line(raw.rstrip(b"\r\n"))     # also drops a BOM on any line


def decode_text(data):
    """The same rules for a whole byte string (used by --mask on stdin)."""
    enc = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else _sniff_utf16(data[:4096])
    if enc:
        return data.decode(enc, errors="replace")
    return "\n".join(decode_line(l) for l in data.split(b"\n"))
# <<< shared-redaction


# --------------------------------------------------------------------------- report
def md_cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def code(text):
    """Values taken from logs go in code spans: they render literally (no <host> swallowed, no
    __init__ turned bold) and stay readable as plain text. Pipes are escaped for tables."""
    t = md_cell(text).replace("`", "'").strip()
    return "`{}`".format(t) if t else "—"


_MD_SPECIAL_RE = re.compile(r"([\\`*\[\]<>|~])")
_MD_UNDERSCORE_RE = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")


def md_text(text):
    """Escape free text for Markdown. Underscores inside words (exclude_files) are left as is."""
    t = _MD_SPECIAL_RE.sub(r"\\\1", str(text).replace("\n", " "))
    return _MD_UNDERSCORE_RE.sub(r"\\_", t)


def strip_ts(line):
    return re.sub(r"^\s*\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\]?\s*", "", line or "")


def code_cell(line, n=100):
    # mask BEFORE truncating: a cut-off quoted value would otherwise escape the patterns
    return code(mask_line(strip_ts(line))[:n])


def build_report(r):
    out = ["# CAST Analysis Summary", "",
           "**Generated:** {}  ".format(datetime.now().strftime("%Y-%m-%d %H:%M")),
           "**Input folder:** {}".format(code(r["input_dir"])), "", "---", "", "## Run Status", ""]
    st = r["status"]
    if st["status"] == "Completed":
        out.append("**Completed** (return value 0, in {}).".format(code(st["source"])))
    elif st["status"] == "Failed":
        bad = [ph for ph in st.get("phases", []) if ph["result"] == "Failed"]
        if st.get("summary_failed") and not bad:
            out.append("**⚠ Failed:** the execution summary says {} (in {}), although no phase returned a "
                       "non-zero value. Check the errors and the last steps in the timeline.".format(
                           code(st["summary"]["status"]), code(st["summary"]["source"])))
        elif bad:
            what = "; ".join("phase {} returned {} (in {})".format(code(ph["phase"]), ph["return_value"], code(ph["log"]))
                             for ph in bad)
        else:
            what = "the analysis returned {} (in {})".format(st["return_value"], code(st["source"]))
        if not (st.get("summary_failed") and not bad):
            out.append("**⚠ Failed:** {}. Figures below cover the run up to the failure; check the errors and the "
                   "last steps in the timeline.".format(what))
    elif st["status"] == "Did not finish":
        last = r["timeline"] and max((t["end"] for t in r["timeline"] if t["end"]), default=None)
        out.append("**⚠ Did not finish:** no return value in {}, so the logs stop before the end of the run "
                   "(collected while it was still running, or the process was stopped).{}{} Durations and "
                   "counts cover only what ran.".format(
                       code(st["source"]),
                       " The last tasks started were {}.".format(", then ".join(code(t) for t in st["last_tasks"]))
                       if len(st.get("last_tasks", [])) > 1 else
                       " The last task started was {}.".format(code(st["last_tasks"][0])) if st.get("last_tasks") else "",
                       " The last log line is at {}.".format(fmt_ts(last)) if last else ""))
    else:
        out.append("**Unknown:** {}.".format(st["detail"]))
    if st.get("summary"):
        out += ["", "CAST execution summary: {} (in {}).".format(code(st["summary"]["status"]), code(st["summary"]["source"]))]
    if st.get("phases"):
        out += ["", "| Phase | Result | Log |", "|-------|--------|-----|"]
        for ph in st["phases"]:
            res = {"OK": "OK (0)", "Failed": "**⚠ Failed ({})**".format(ph["return_value"]),
                   "not logged": "not logged"}[ph["result"]]
            if ph["phase"] == "analyze" and ph["result"] == "not logged" and st["status"] == "Did not finish":
                res = "**⚠ no return value** (did not finish)"
            out.append("| {} | {} | {} |".format(code(ph["phase"]), res, code(ph["log"])))
        out += ["", "*\"not logged\": that phase never writes a return value; it is not a failure. Phases "
                "missing from this table were not in the archive.*"]
    out += ["", "---", "", "## Environment Configuration", ""]
    if r["env_source"]:
        out += ["Source log: {}".format(code(r["env_source"])), ""]
    out += ["| Parameter | Value |", "|-----------|-------|"]
    for key, val in r["env"].items():
        out.append("| {} | {} |".format(key, code(val) if val else "*(absent in this deployment)*"))
    out += ["", "---", "", "## CAST Extensions Used", ""]
    if r["extensions"]:
        out.append("Source log: {} ({} extensions)".format(code(r["ext_source"]), len(r["extensions"])))
        out += ["", "| Extension | Version |", "|-----------|---------|"]
        out += ["| {} | {} |".format(code(n), code(v)) for n, v in r["extensions"].items()]
    else:
        out.append("*No extension information available.*")
    out += ["", "---", "", "## Execution Timeline", "",
            "| File | Start | End | Duration |", "|------|-------|-----|----------|"]
    for t in r["timeline"]:
        out.append("| {} | {} | {} | {} |".format(code(t["file"]), fmt_ts(t["start"]),
                                                fmt_ts(t["end"]), t["duration"]))
    out.append("")
    total = r["total"]
    if total:
        s, e, d = total
        out.append("**Total execution time (start: {} --> end: {}):** {} (approximately {:.1f} hours)".format(
            fmt_ts(s), fmt_ts(e), fmt_duration(d), d.total_seconds() / 3600))
        if r["gap_minutes"]:
            silent_s = sum(g["seconds"] for g in r["silent"])
            share = 100.0 * silent_s / d.total_seconds() if d.total_seconds() else 0
            out += ["", "**Run-wide silent time** (no log wrote anything for {}+ min): {} ({:.0f}% of the run). "
                    "**Time with log activity:** {}.".format(
                        r["gap_minutes"], fmt_duration(_td(silent_s)), share,
                        fmt_duration(_td(d.total_seconds() - silent_s)))]
        out += ["", "*Measured from the earliest start to the latest end; logs run in parallel, "
                "so this is not the sum of individual durations.*"]
    else:
        out.append("**Total execution time:** N/A (no log had both a start and an end timestamp)")
    if r["gap_minutes"]:
        out += ["", "---", "", "## Silent Periods (no log output anywhere for {}+ minutes)".format(r["gap_minutes"]), ""]
        if r["silent"]:
            shown = r["silent"]
            if len(shown) > r["top_silences"]:   # long runs: the longest periods, longest first
                shown = sorted(shown, key=lambda g: -g["seconds"])[:r["top_silences"]]
                out += ["*{} silent periods; the {} longest are shown, longest first. The silent time above "
                        "counts all of them{}.*".format(len(r["silent"]), len(shown), _full_list_note(r)), ""]
            out += ["| From | To | Duration | Last line before | First line after |",
                    "|------|----|----------|------------------|------------------|"]
            for g in shown:
                out.append("| {} | {} | {} | {} ({}) | {} ({}) |".format(
                    fmt_ts(g["from"]), fmt_ts(g["to"]), fmt_duration(_td(g["seconds"])),
                    code_cell(g["before"]), code(g["before_file"]),
                    code_cell(g["after"]), code(g["after_file"])))
        else:
            out.append("*None found.*")
        out += ["", "### Silent stretches inside individual logs", ""]
        if r["gaps"]:
            out += ["*A step can be silent while another step works, so these are not all idle time; "
                    "they show which step was waiting and on what.*", "",
                    "| File | From | To | Gap | Last line before | First line after |",
                    "|------|------|----|-----|------------------|------------------|"]
            if len(r["gaps"]) > r["top_silences"]:
                out += ["*{} stretches; the {} longest are shown{}.*".format(
                    len(r["gaps"]), r["top_silences"], _full_list_note(r)), ""]
            for g in r["gaps"][:r["top_silences"]]:     # already sorted longest first
                out.append("| {} | {} | {} | {} | {} | {} |".format(
                    code(g["file"]), fmt_ts(g["from"]), fmt_ts(g["to"]),
                    fmt_duration(_td(g["seconds"])), code_cell(g["before"]), code_cell(g["after"])))
        else:
            out.append("*None found.*")
    if r["warnings"]:
        out += ["", "---", "", "## Notes and Warnings", ""]
        out += ["- " + md_text(w) for w in r["warnings"]]
    return "\n".join(out) + "\n"


def _full_list_note(r):
    return "; the full list is in logs_analysis.json" if r.get("json") else \
        "; run with --json for the full list"


def non_negative(text):
    v = int(text)
    if v < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return v


def _td(seconds):
    return timedelta(seconds=seconds)


def utf8_stdio():
    """Write status and --mask output as UTF-8. On Windows, redirected or captured output
    (e.g. when Claude Code runs the script) otherwise uses the ANSI code page and any path or
    log text outside it raises UnicodeEncodeError after the report has been written."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, io.UnsupportedOperation):
            try:                            # Python < 3.7
                setattr(sys, name, io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace",
                                                    line_buffering=True))
            except AttributeError:
                pass


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="Input", help="folder containing the logs (searched recursively)")
    ap.add_argument("--output", default="Output", help="folder for the report")
    ap.add_argument("--json", action="store_true", help="also write logs_analysis.json")
    ap.add_argument("--top-silences", type=non_negative, default=20,
                    help="silent periods and per-log stretches shown in the report (the longest; "
                         "all are counted, and all are listed in the JSON)")
    ap.add_argument("--gap-minutes", type=float, default=5,
                    help="minimum silence to report, in minutes (0 disables)")
    ap.add_argument("--mask", action="store_true",
                    help="mask text read from stdin (credentials always; hosts/paths with --redact) and "
                         "print it: use before quoting any raw log line in a chat or a ticket")
    ap.add_argument("--redact", action="store_true",
                    help="mask IPs, host names and non-CAST absolute paths in the outputs")
    ap.add_argument("--redact-term", action="append", default=[],
                    help="extra text to mask (repeatable), e.g. a project or customer name")
    args = ap.parse_args()
    if args.mask:
        data = sys.stdin.buffer.read()
        sys.stdout.write(mask_text(decode_text(data), args.redact_term, args.redact))
        return 0

    input_dir = Path(args.input).resolve()
    if not input_dir.is_dir():
        print("Input folder not found: {}".format(input_dir), file=sys.stderr)
        return 2
    out_dir = Path(args.output).resolve()
    if out_dir == input_dir or out_dir in input_dir.parents:
        print("--output must be a different folder from --input (and not contain it): files in the "
              "output folder are never analysed.", file=sys.stderr)
        return 2
    logs = sorted(p for p in input_dir.rglob("*.log")
                  if p.is_file() and out_dir not in p.parents)
    if not logs:
        print("No *.log files under {}".format(input_dir), file=sys.stderr)
        return 2

    warnings = []
    env, env_source = extract_env(logs, warnings)
    exts, ext_source = extract_extensions(input_dir, warnings)
    gap_s = args.gap_minutes * 60

    timeline, na_files, empty_files, gaps, all_segments = [], [], [], [], []
    for p in logs:
        rel = str(p.relative_to(input_dir))
        start, end, lgaps, segs, changes, raw_end = scan_log(p, gap_s)
        for c in changes:
            if c["kind"] == "back":
                warnings.append("{}: the clock went back 1 hour at {} (daylight-saving change). This log's "
                                "duration and silences are computed on continuous time and include the repeated "
                                "hour; all times shown are the log's own clock. Figures that combine several logs "
                                "(run total, run-wide silence) may be off by up to 1 hour around the change.".format(
                                    rel, fmt_ts(c["at"])))
            else:
                warnings.append("{}: the ~1h silence starting {} may be a daylight-saving clock change "
                                "(clocks forward), not a real wait.".format(rel, fmt_ts(c["at"])))
        timeline.append({"file": rel, "start": start, "end": raw_end, "end_corrected": end,
                         "duration": fmt_duration(end - start) if start and end else "N/A"})
        if start is None:
            (empty_files if p.stat().st_size == 0 else na_files).append(rel)
        for g in lgaps:
            g["file"] = rel
            gaps.append(g)
        all_segments += [s + (rel,) for s in segs]
    timeline.sort(key=lambda t: (t["start"] is None, t["start"] or datetime.min, t["file"]))
    gaps.sort(key=lambda g: -g["seconds"])
    if na_files:
        warnings.append("No line starting with a timestamp (shown as N/A, excluded from the total; normal "
                        "for bundled tool output such as profiler or 7-Zip logs): " + ", ".join(na_files))
    if empty_files:
        warnings.append("Empty log file (0 bytes; shown as N/A): " + ", ".join(empty_files))

    paired = [t for t in timeline if t["start"] and t["end"]]
    total = None
    if paired:
        s = min(t["start"] for t in paired)
        last = max(paired, key=lambda t: t["end_corrected"])
        total = (s, last["end"], last["end_corrected"] - s)      # shown on the log's clock
    silent = run_wide_silence(all_segments, gap_s) if gap_s else []

    status = run_status(input_dir, logs, {t["file"]: t["start"] for t in timeline})
    report = {"input_dir": args.input, "env": env, "status": status,          # as given, not the machine's path
              "env_source": str(env_source.relative_to(input_dir)) if env_source else None,
              "extensions": exts,
              "ext_source": str(ext_source.relative_to(input_dir)) if ext_source else None,
              "timeline": timeline, "total": total, "gap_minutes": args.gap_minutes if gap_s else 0,
              "silent": silent, "gaps": gaps, "warnings": warnings,
              "top_silences": args.top_silences, "json": args.json}

    out_dir.mkdir(parents=True, exist_ok=True)
    # redact the data first: quoted lines are cut at the report width while building, and a
    # cut-off host ("castlin02") would no longer be recognised by a pass over the final text
    if args.redact or args.redact_term:
        report = map_strings(report, lambda t: apply_redaction(t, args), skip_keys=("input_dir",))
    text = build_report(report)
    text = apply_redaction(text, args)
    report_path = out_dir / "logs_analysis_report.md"
    report_path.write_text(text, encoding="utf-8")

    if args.json:
        conv = lambda d: {k: (fmt_ts(v) if isinstance(v, datetime) else v) for k, v in d.items()}
        data = {
            "run_status": status,
            "environment": env, "environment_source": report["env_source"],
            "extensions": exts, "extensions_source": report["ext_source"],
            "timeline": [conv(t) for t in timeline],
            "total": {"start": fmt_ts(total[0]), "end": fmt_ts(total[1]),
                      "duration": fmt_duration(total[2]),
                      "hours": round(total[2].total_seconds() / 3600, 2)} if total else None,
            "silent_periods": [conv(g) for g in silent],
            "silent_seconds_total": sum(g["seconds"] for g in silent),
            "per_log_silent_stretches": [conv(g) for g in gaps],
            "warnings": warnings,
        }
        js = json.dumps(map_strings(data, lambda t: apply_redaction(t, args)), indent=2)
        (out_dir / "logs_analysis.json").write_text(js, encoding="utf-8")

    print("Report written to {}".format(report_path))
    print("Run status: {} | Logs: {} | Extensions: {} | Silent periods: {} | Warnings: {}".format(
        status["status"], len(logs), len(exts), len(silent), len(warnings)))
    for w in warnings:
        print("WARNING: " + w, file=sys.stderr)
    return 0


def apply_redaction(text, args):
    return redact_text(mask_secrets(text), args.redact_term, args.redact)


if __name__ == "__main__":
    sys.exit(main())
