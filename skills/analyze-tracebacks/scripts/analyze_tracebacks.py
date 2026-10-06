#!/usr/bin/env python3
"""Find, segment and categorize Python tracebacks (and non-traceback warnings/errors)
in CAST analysis logs.

Each traceback is parsed as its own block (header -> context -> frames -> exception),
tracked per thread ID when log lines carry one, so fields never mix between tracebacks.
Blocks are grouped by exception type + normalized message + raise site.

Outputs (in --output):
  tracebacks_report.md   markdown report
  tracebacks.json        machine-readable data (input for --render-only)
  triggers.json          {group signature: {"label", "trigger"}}; fill the empty "trigger"
                         values, then re-render. Kept across runs, so explanations survive.

Standard library only, Python 3.8+. Usage:
  python analyze_tracebacks.py [--input Input] [--output Output] [--triggers FILE]
                               [--redact] [--redact-term TEXT ...] [--top-warnings 30]
  python analyze_tracebacks.py --render-only [--output Output] ...   # re-render, no parsing
"""
import argparse
import io
import hashlib
import json
import os
import re
import sys
from collections import Counter, OrderedDict
from datetime import date
from pathlib import Path

TB_START_RE = re.compile(r"\bTraceback\b")                    # case-sensitive on purpose
HEADER_RE = re.compile(r"\[TRACEBACK\]|has encountered an issue", re.I)
FRAME_RE = re.compile(r'^File "([^"]+)", line (\d+), in (\S+)')
TS_RE = re.compile(r"^\s*\[?\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\]?")
LEVEL_RE = re.compile(r"(INFO|WARNING|WARN|ERROR|DEBUG|CRITICAL|FATAL|SEVERE|TRACE)\b")
PROBLEM_LEVELS = {"WARNING": "WARNING", "WARN": "WARNING", "ERROR": "ERROR",
                  "CRITICAL": "CRITICAL", "FATAL": "FATAL", "SEVERE": "ERROR"}
EXC_RE = re.compile(
    r"^([A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt|Iteration|Warning))(?::\s?(.*))?$")
# Any class name, used only at the exception position (first unindented line after a
# traceback's source line), so custom classes such as cast.application.Abort are recognised.
ANY_EXC_RE = re.compile(r"^([A-Za-z_][\w.]*)(?::\s?(.*))?$")
CHAIN_RE = re.compile(r"During handling of the above exception|The above exception was the direct cause")
CONTEXT_RE = re.compile(r"During (\w+) on\b")
# Error code only where CAST puts it: right after the [TRACEBACK] tag and optional [..] tags.
CODE_RE = re.compile(r"\[TRACEBACK\](?:\s*\[[^\]]*\])*\s+([A-Z][A-Z0-9_]*-\d{2,})\s*:")
HDR_EXT_RE = re.compile(r"(com\.castsoftware\.[A-Za-z0-9_\-]+(?:\.[A-Za-z_][A-Za-z0-9_\-]*)*)")
EXT_PATH_RE = re.compile(
    r"com\.castsoftware\.([A-Za-z0-9_.\-]+?)\.(\d+(?:\.\d+)*(?:-[A-Za-z0-9]+)*)(?=[\\/])")
ENV_RES = {"CARL": re.compile(r"CARL Version:\s*(.+)"), "CAIP": re.compile(r"CAIP Version:\s*(.+)")}
# warning codes: DOTNET.0150: / JAVA068: / SECJAVA.12 - (.NET, Java and security analyzers)
WARN_CODE_RE = re.compile(r"^([A-Z][A-Z0-9_]*?(?:\.\d+|\d{2,}))\s*(?::|\s-\s)\s*")

HEADER_LOOKBACK = 10      # max lines between a [TRACEBACK] header and "Traceback (...)"
PRE_FRAME_LIMIT = 3       # lines after "Traceback" with no frame: it was just a word
FOREIGN_LIMIT = 20        # unrelated lines tolerated inside an unfinished traceback
MAX_BLOCK_LINES = 400
MAX_EXAMPLE_LINES = 80


# --------------------------------------------------------------------------- I/O
def iter_lines(path):
    return read_lines(path)                 # encoding rules shared with analyze-logs


_SEVERITY = {"TRACE": 0, "DEBUG": 0, "INFO": 1, "WARN": 2, "WARNING": 2, "ERROR": 3, "SEVERE": 3,
             "CRITICAL": 4, "FATAL": 4}


def _more_severe(current, new):
    """Some extensions log "[INFO] [thread] [ERROR] message": an INFO wrapper around their own
    level. The most severe level on the line is the real one."""
    if current is None or _SEVERITY.get(new.upper(), 0) > _SEVERITY.get(current.upper(), 0):
        return new
    return current


# Other CAST log layouts, normalised to "<timestamp> [LEVEL] message" before parsing:
#  - CAST 8.3 analyzer logs, tab-separated, with trailing columns after the message:
#    " 2026-09-30 11:50:19.000474<TAB>Warning<TAB>MODULMSG ; Job execution<TAB>[ext] message<TAB>0 ; 0..."
#  - orchestration logs, level first: "INF: 2026-09-26 00:59:46: message" (WRN:, ERR:, DBG:)
# (some lines also carry BEL control characters next to the tabs: "...,039 \x07\tINFO\x07\t...")
_TABLOG_RE = re.compile(r"^\s?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)[\s\x07]*\t\x07?([A-Za-z]+)\x07?\t"
                        r"[^\t]*\t\x07?([^\t]*)")
_ORCH_RE = re.compile(r"^(INF|WRN|ERR|DBG|FTL|FAT):\s+(?:(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}):\s?)?(.*)$")
_LEVEL_WORDS = {"information": "INFO", "info": "INFO", "warning": "WARNING", "warn": "WARNING", "error": "ERROR",
                "fatal": "FATAL", "critical": "CRITICAL", "severe": "SEVERE", "debug": "DEBUG", "trace": "TRACE",
                "inf": "INFO", "wrn": "WARNING", "err": "ERROR", "dbg": "DEBUG", "ftl": "FATAL", "fat": "FATAL"}


def canonical(line):
    m = _TABLOG_RE.match(line)
    if m and m.group(2).lower() in _LEVEL_WORDS:
        return "{} [{}] {}".format(m.group(1), _LEVEL_WORDS[m.group(2).lower()], m.group(3).strip("\x07"))
    m = _ORCH_RE.match(line)
    if m:                                   # the timestamp is optional (multi-line messages)
        return "{}[{}] {}".format(m.group(2) + " " if m.group(2) else "", _LEVEL_WORDS[m.group(1).lower()],
                                  m.group(3).lstrip("\t"))
    return line


def split_prefix(line):
    """Split a log line into (has_prefix, rest, thread_id, tag, level).

    The prefix is an optional timestamp followed by [..] groups and level words. Indentation
    of the remainder is preserved, so traceback source lines stay recognisable even when every
    line carries a prefix. Bracket groups are only taken as prefix at column 0 or after
    another prefix element, so source code such as "    [x for x in y]" is left alone.
    """
    line = canonical(line)
    i, n, has = 0, len(line), False
    m = TS_RE.match(line)
    if m:
        i, has = m.end(), True
    tid = tag = level = None
    while True:
        j = i
        if has:
            while j < n and line[j] in " \t":
                j += 1
        elif j != 0:
            break
        if j < n and line[j] == "[":
            k = line.find("]", j)
            if k == -1:
                break
            inner = line[j + 1:k]
            if inner.isdigit():
                tid = tid or inner
            elif LEVEL_RE.fullmatch(inner):
                level = _more_severe(level, inner)
            elif inner.upper() != "TRACEBACK" and tag is None:
                tag = inner
            i, has = k + 1, True
            continue
        # A bare level word is the line's level only when no level was seen yet ("2026-... ERROR msg").
        # After "[INFO]" it is message text ("[INFO] ERROR: INVALID LINK POSITIONS : 4267" is an INFO
        # statistic), so it is neither taken as the level nor stripped from the message.
        lm = LEVEL_RE.match(line, j) if (has and level is None) else None
        if lm:
            level = lm.group(1)
            i = lm.end()
            continue
        break
    rest = line[i:]
    if has and rest[:1] == " ":
        rest = rest[1:]
    return has, rest, tid, tag, level


# --------------------------------------------------------------------------- traceback parsing
class Block(object):
    def __init__(self, log, line_no, header_lines, context, tid, tag=None):
        self.log, self.line_no, self.tid, self.tag = log, line_no, tid, tag
        self.expect_exc = False       # last line routed here was a frame or its source line
        self.lines = list(header_lines)
        self.header = next((l for l in header_lines if HEADER_RE.search(l)), "")
        self.context = context
        self.frames, self.chain = [], []
        self.exc_type, self.exc_msg = None, ""
        self.state = "pre"            # pre -> frames -> done (-> pre again when chained)
        self.chain_pending = False
        self.pre_lines = self.foreign = self.blank = 0
        self.interleaved = False


def is_problem_candidate(raw):
    return ("WARN" in raw or "ERROR" in raw or "FATAL" in raw or "CRITICAL" in raw or "SEVERE" in raw
            or "\tWarning\t" in raw or "\tError\t" in raw or "\tFatal\t" in raw     # CAST 8.3 tab logs
            or raw.startswith(("WRN:", "ERR:", "FTL:", "FAT:")))                      # orchestration logs


class LogParser(object):
    def __init__(self, rel):
        self.rel = rel
        self.blocks, self.open = [], []
        self.pending = {}              # tid -> [line_no, lines]
        self.stray = 0
        self.warn = []                 # (level, tag, message)

    # ---- helpers
    def close(self, b):
        self.open.remove(b)
        if b.frames or (b.interleaved and b.exc_type):
            self.blocks.append(b)
        elif b.header:
            self.stray += 1

    def close_where(self, pred):
        for b in [b for b in self.open if pred(b)]:
            self.close(b)

    def candidates(self, tid, states):
        bs = [b for b in self.open if b.state in states]
        if tid is not None:
            same = [b for b in bs if b.tid == tid]
            if same:
                return same
        return bs

    # ---- main entry
    def may_keep(self, raw):
        """False only for lines the parser is guaranteed to discard (nothing open, no
        traceback or warning marker). Every other line is masked before feed()."""
        return bool(self.open or self.pending or "Traceback" in raw or "TRACEBACK" in raw
                    or "encountered an issue" in raw or is_problem_candidate(raw))

    def feed(self, line_no, raw):
        # Fast path: nothing open and the line cannot start anything interesting.
        if not self.open and not self.pending:
            if ("Traceback" not in raw and "TRACEBACK" not in raw and "encountered an issue" not in raw):
                if is_problem_candidate(raw):
                    self.maybe_warning(raw)
                return
        has, rest, tid, tag, level = split_prefix(raw)
        s = rest.strip()
        indented = rest[:1] in (" ", "\t")
        is_header = bool(HEADER_RE.search(raw))
        is_tb = bool(TB_START_RE.search(raw)) and not indented
        is_chain = bool(CHAIN_RE.search(raw))
        frame = FRAME_RE.match(s) if indented else None
        exc = EXC_RE.match(s) if (s and not indented and not is_tb and not is_header) else None

        # expire pending headers
        for k in list(self.pending):
            if line_no - self.pending[k][0] > HEADER_LOOKBACK:
                del self.pending[k]
                self.stray += 1
        for k in self.pending:
            if k == tid or tid is None or k is None:
                if not is_header or self.pending[k][0] != line_no:
                    self.pending[k][1].append(raw)

        if is_header:
            # a new header ends unfinished tracebacks of the same thread (cut off / false start)
            self.close_where(lambda b: b.state == "done" and not b.chain_pending)
            self.close_where(lambda b: b.state in ("pre", "frames") and (b.tid == tid or tid is None)
                             and not b.interleaved)
            if tid in self.pending:
                self.stray += 1
            self.pending[tid] = [line_no, [raw]]

        if is_tb:
            cont = [b for b in self.candidates(tid, ("done",)) if b.chain_pending]
            if cont:
                b = cont[-1]
                b.chain.append((b.exc_type, b.exc_msg))
                b.exc_type, b.exc_msg, b.state, b.chain_pending = None, "", "pre", False
                b.lines.append(raw)
                return
            self.close_where(lambda b: b.state == "done" and not b.chain_pending)
            p = self.pending.pop(tid, None)
            if p is None and tid is not None:
                p = self.pending.pop(None, None)
            header_lines, start_no, context = [raw], line_no, None
            if p:
                header_lines = p[1] if p[1][-1] == raw else p[1] + [raw]
                start_no = p[0]
                for r in p[1]:
                    m = CONTEXT_RE.search(r)
                    if m:
                        context = m.group(1)
            nb = Block(self.rel, start_no, header_lines, context, tid, tag)
            unfinished = [b for b in self.open if b.state in ("pre", "frames")]
            if unfinished:
                nb.interleaved = True
                for b in unfinished:
                    b.interleaved = True
            self.open.append(nb)
            return

        if is_header:
            return

        if is_chain:
            done = self.candidates(tid, ("done",))
            if done:
                done[-1].chain_pending = True
                done[-1].lines.append(raw)
            return

        if frame:
            cands = self.candidates(tid, ("pre", "frames"))
            if cands:
                b = cands[-1]                            # most recently opened
                b.frames.append({"path": frame.group(1), "line": int(frame.group(2)),
                                 "func": frame.group(3), "code": None})
                b.state, b.foreign, b.expect_exc = "frames", 0, True
                b.lines.append(raw)
            return

        if exc and self.open:
            cands = self.candidates(tid, ("frames",)) or self.candidates(tid, ("pre",))
            if cands:
                self.finish_exc(cands[0], exc, raw)      # earliest unfinished
                return
        if (not exc and self.open and s and not indented and not is_tb
                and not is_header and not is_chain):
            m = ANY_EXC_RE.match(s)
            # Custom class at the exception position. Guard against ordinary log lines:
            # it must follow a frame/source line of the same traceback, and look like
            # "Name: msg", "pkg.Name", or (unprefixed) a bare CamelCase name.
            if m and (m.group(2) is not None or "." in m.group(1) or (not has and m.group(1)[:1].isupper())):
                cands = [b for b in self.candidates(tid, ("frames",)) if b.expect_exc and
                         (not has or (tag and tag == b.tag) or (tid is not None and tid == b.tid))]
                if cands:
                    self.finish_exc(cands[0], m, raw)
                    return

        if indented and s:
            cands = self.candidates(tid, ("frames",))
            if cands and cands[-1].frames and cands[-1].frames[-1]["code"] is None:
                cands[-1].frames[-1]["code"] = s
                cands[-1].lines.append(raw)
                cands[-1].expect_exc = True
                return

        if not s:
            for b in list(self.open):
                if b.state == "done":
                    b.blank += 1
                    if b.blank > 3:
                        self.close(b)
            return

        # ordinary (foreign) log line
        for b in list(self.open):
            if b.state == "done":
                b.foreign += 1
                if not b.chain_pending or b.foreign > PRE_FRAME_LIMIT:
                    self.close(b)
            elif b.state == "pre":
                b.pre_lines += 1
                if b.pre_lines > PRE_FRAME_LIMIT:
                    self.close(b)
            else:
                b.foreign += 1
                if b.foreign > FOREIGN_LIMIT or len(b.lines) > MAX_BLOCK_LINES:
                    self.close(b)
        self.maybe_warning(raw)

    def finish_exc(self, b, m, raw):
        b.exc_type, b.exc_msg = m.group(1), (m.group(2) or "").strip()
        b.state, b.blank, b.expect_exc = "done", 0, False
        b.lines.append(raw)

    def maybe_warning(self, raw):
        if HEADER_RE.search(raw):
            return
        has, rest, tid, tag, level = split_prefix(raw)
        if level and level.upper() in PROBLEM_LEVELS and rest.strip():
            self.warn.append((PROBLEM_LEVELS[level.upper()], tag or "", rest.strip()))

    def finish(self):
        for b in list(self.open):
            self.close(b)
        self.stray += len(self.pending)
        self.pending = {}
        return self.blocks


def parse_log(path, rel):
    p = LogParser(rel)
    for n, raw in enumerate(iter_lines(path), 1):
        # every line that could be kept is masked first: secrets never enter blocks,
        # warning templates, sample values or labels
        p.feed(n, mask_line(raw) if p.may_keep(raw) else raw)
    return p.finish(), p.stray, p.warn


# --------------------------------------------------------------------------- analysis
def normalize(msg):
    m = re.sub(r"0x[0-9a-fA-F]+", "0x?", msg)
    m = re.sub(r"File\([^)]*\)", "File(<path>)", m)
    m = re.sub(r"(['\"])[^'\"]*[\\/][^'\"]*\1", r"\1<path>\1", m)
    m = re.sub(r"\b\d+\b", "N", m)
    return m.strip()


def _pattern_v1(msg):
    """Grouping pattern of the previous release (quoted values only); kept for migration."""
    m = re.sub(r"0x[0-9a-fA-F]+", "0x?", msg)
    m = re.sub(r"File\([^)]*\)", "File(…)", m)
    m = re.sub(r"(['\"])[^'\"]*\1", r"\1…\1", m)
    m = re.sub(r"(?:[A-Za-z]:\\|/)[^\s,;'\"]+", "<path>", m)
    m = re.sub(r"\d+(?:\.\d+)*", "N", m)
    return m.strip()


_DOTTED_NAME_RE = re.compile(r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+\b")


def message_pattern(msg):
    """Exception message with its variable parts replaced, so one bug raised with different
    names forms one group: quoted values (KeyError: 'TABLE_0001_COL'), unquoted dotted names
    (Symbol not found: com.acme.billing.InvoiceService), paths, numbers. Only used together
    with the exception type and the raise site, so different bugs never merge."""
    m = re.sub(r"0x[0-9a-fA-F]+", "0x?", msg)
    m = re.sub(r"File\([^)]*\)", "File(…)", m)
    m = re.sub(r"(['\"])[^'\"]*\1", r"\1…\1", m)
    m = re.sub(r"(?:[A-Za-z]:\\|/)[^\s,;'\"]+", "<path>", m)
    m = _DOTTED_NAME_RE.sub("<name>", m)
    m = re.sub(r"\d+(?:\.\d+)*", "N", m)
    return m.strip()


MAX_VARIANTS = 20                           # distinct raw messages kept per group


def ext_from_path(path):
    m = EXT_PATH_RE.search(path)
    if not m:
        return None, None
    return "com.castsoftware.{}.{}".format(m.group(1), m.group(2)), path[m.end():].lstrip("\\/")


def describe(block):
    ext_frames = [f for f in block.frames if "com.castsoftware" in f["path"]]
    deepest = block.frames[-1] if block.frames else None
    deepest_ext = ext_frames[-1] if ext_frames else None
    extension, rel_in_ext = (None, None)
    if deepest_ext:
        extension, rel_in_ext = ext_from_path(deepest_ext["path"])
    if not extension:
        hm = HDR_EXT_RE.search(block.header)
        extension = hm.group(1) + " (version unknown)" if hm else ""
    code = CODE_RE.search(block.header)
    site = deepest_ext or deepest
    exc_type = block.exc_type or "UnknownError (truncated traceback)"
    site_str = "{}:{}".format(site["path"], site["line"]) if site else "?"
    signature = "{}|{}|{}".format(exc_type, message_pattern(block.exc_msg), site_str)
    # keys of earlier groupings: triggers written under them are migrated
    legacy = ["{}|{}|{}".format(exc_type, normalize(block.exc_msg), site_str),      # before patterns
              "{}|{}|{}".format(exc_type, _pattern_v1(block.exc_msg), site_str)]   # quoted values only
    return {
        "signature": signature,
        "signature_id": signature_id(signature),
        "legacy_ids_one": [signature_id(x) for x in legacy if x != signature],
        "pattern": exc_type + (": " + message_pattern(block.exc_msg) if block.exc_msg else ""),
        "exc_type": exc_type,
        "exc_msg": block.exc_msg,
        "label": exc_type + (": " + block.exc_msg if block.exc_msg else ""),
        "extension": extension,
        "block": block.context or (site["func"] if site else "?"),
        "source": "{}:{}".format(deepest["path"], deepest["line"]) if deepest else "?",
        "extension_source": "{}:{}".format(deepest_ext["path"], deepest_ext["line"]) if deepest_ext else None,
        "short_source": "{}:{}".format(rel_in_ext or Path(site["path"].replace("\\", "/")).name,
                                       site["line"]) if site else "?",
        "raised_code": deepest["code"] if deepest else None,
        "error_code": code.group(1) if code else "",
        "chain": ["{}: {}".format(t, m) if m else t for t, m in block.chain],
        "thread": block.tid,
        "interleaved": block.interleaved,
        "log": block.log,
        "line_no": block.line_no,
    }


def warning_template(msg):
    """Turn a warning message into (code, template, values) so similar warnings group."""
    code = ""
    m = WARN_CODE_RE.match(msg)
    if m:
        code, msg = m.group(1), msg[m.end():]
    values = []

    def keep(m, repl):
        values.append(m.group(0))
        return repl

    def keep_name(name):
        if name == "<name>" or name.lower() in ("the", "a", "an"):
            return name
        values.append(name)
        return "<name>"

    t = re.sub(r"\b([A-Z][A-Za-z]*)\((?:[^()]|\([^()]*\))*\)", lambda m: keep(m, m.group(1) + "(…)"), msg)
    t = re.sub(r"(?:\\x[0-9a-fA-F]{2},?)+", "<bytes>", t)             # byte dumps: \xc3,\xa9,...
    t = re.sub(r'"([^"\n]{1,200})"', lambda m: keep(m, '"…"'), t)      # double quotes: may hold spaces
    # Java/.NET signatures in single quotes: 'pkg.Class.method(List, int)#param' (spaces allowed
    # only inside the brackets, so French apostrophes in prose are not mistaken for quotes)
    t = re.sub(r"'[\w$.#<>\[\]]*\([^()'\n]{0,200}\)[\w$.#<>\[\]]*'", lambda m: keep(m, "'…'"), t)
    t = re.sub(r"'([^'\s]{1,120})'", lambda m: keep(m, "'…'"), t)      # single quotes: one word
    t = re.sub(r"(?:[A-Za-z]:\\|/)[^\s,;]+", "<path>", t)
    t = re.sub(r"\b[A-Za-z_]\w*(?=\(\))", lambda m: keep_name(m.group(0)), t)   # getOrderCode()
    # unquoted names after a naming keyword. After package / assembly / library / extraction any
    # word is a name (lowercase NuGet ids such as xunit included); after type, class, method...
    # only identifier-like words (capitals, digits, . _ -), so "type variable" or "method
    # declaration" stay English
    def _kw(m):
        kw, word = m.group(1), m.group(2)
        always = kw.lower() in ("package", "assembly", "library", "extraction")
        return kw + " " + (keep_name(word) if always or re.search(r"[A-Z0-9._\-]", word) else word)
    t = re.sub(r"\b(package|assembly|project|reference to|namespace|type|class|method|table|library|extraction)"
               r"\s+(?!(?:version|reference|references|call|calls|of|for|is|was|not|the|a|an|in|to|from|with"
               r"|and|or)\b)([A-Za-z_][\w.\-]*[\w])", _kw, t, flags=re.I)
    t = re.sub(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\b(?![(<])", lambda m: keep_name(m.group(0)), t)
    t = re.sub(r"\d+(?:\.\d+)*", "N", t)      # numbers and versions of any length
    return code, t.strip(), values


def trim_example(lines):
    if len(lines) <= MAX_EXAMPLE_LINES:
        return lines
    head, tail = 15, MAX_EXAMPLE_LINES - 15
    return lines[:head] + ["... ({} lines omitted) ...".format(len(lines) - head - tail)] + lines[-tail:]


def extract_env(logs):
    env = {}
    for p in logs:
        for i, line in enumerate(iter_lines(p)):
            if i >= 200:
                break
            for k, rx in ENV_RES.items():
                if k not in env:
                    m = rx.search(line)
                    if m:
                        env[k] = m.group(1).strip()
        if len(env) == len(ENV_RES):
            break
    return env


def analyze(input_dir, out_dir):
    logs = sorted(p for p in input_dir.rglob("*.log") if p.is_file() and out_dir not in p.parents)
    per_file, stray, groups = OrderedDict(), {}, OrderedDict()
    wgroups, wtotals, wfiles = OrderedDict(), Counter(), Counter()
    for p in logs:
        rel = str(p.relative_to(input_dir))
        blocks, n_stray, warns = parse_log(p, rel)
        if n_stray:
            stray[rel] = n_stray
        if blocks:
            per_file[rel] = len(blocks)
        for b in blocks:
            d = describe(b)
            g = groups.get(d["signature"])
            if g is None:
                g = groups[d["signature"]] = dict(d, count=0, by_file=Counter(), message_variants=OrderedDict(),
                                                  variant_count=0, legacy_ids=OrderedDict(),
                                                  interleaved_count=0, example_lines=trim_example(b.lines))
            g["count"] += 1
            g["by_file"][rel] += 1
            if d["exc_msg"] not in g["message_variants"]:
                if len(g["message_variants"]) < MAX_VARIANTS:
                    g["message_variants"][d["exc_msg"]] = None
                g["variant_count"] += 1
            for old in d["legacy_ids_one"]:
                g["legacy_ids"][old] = None
            g["interleaved_count"] += 1 if b.interleaved else 0
        for level, tag, msg in warns:
            code, tmpl, values = warning_template(msg)
            key = (level, tag, code, tmpl)
            wg = wgroups.get(key)
            if wg is None:
                wg = wgroups[key] = {"level": level, "source": tag, "code": code, "template": tmpl,
                                     "count": 0, "by_file": Counter(), "values": OrderedDict(), "example": msg}
            wg["count"] += 1
            wg["by_file"][rel] += 1
            for v in values:
                if len(wg["values"]) < 8:
                    wg["values"][v] = None
            wtotals[level] += 1
            wfiles[rel] += 1
    runs = sorted(str(p.relative_to(input_dir)) for p in logs if p.name == "0-analyze.log")
    ordered = sorted(groups.values(), key=lambda g: -g["count"])
    for g in ordered:
        g["by_file"] = OrderedDict(g["by_file"].most_common())
        g["message_variants"] = list(g["message_variants"])
        g["legacy_ids"] = list(g["legacy_ids"])
        g.pop("legacy_ids_one", None)
    wordered = sorted(wgroups.values(), key=lambda g: (-g["count"], g["template"]))
    for g in wordered:
        g["by_file"] = OrderedDict(g["by_file"].most_common())
        g["values"] = list(g["values"])
    return {"analysis_date": date.today().isoformat(), "logs_scanned": len(logs),
            "environment": extract_env(logs), "per_file": per_file, "stray_headers": stray,
            "runs": runs,
            "groups": ordered,
            "problems": {"totals": dict(wtotals), "by_file": OrderedDict(wfiles.most_common()),
                         "groups": wordered}}


# --------------------------------------------------------------------------- triggers
def signature_id(signature):
    """Stable key for triggers.json, computed BEFORE any redaction, so redacted outputs and
    --render-only still find the explanations, and the key itself reveals nothing."""
    return hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16]


class TriggersFileError(Exception):
    pass


def load_triggers(path):
    """A missing file is a fresh start. An unreadable one is an ERROR: treating it as empty
    would overwrite (and so destroy) every explanation after a single hand-editing mistake."""
    path = Path(path)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        raise TriggersFileError("{} is not valid JSON ({}). Fix it, or restore {}.bak. "
                                "Nothing was written.".format(path, e, path.name))
    except OSError as e:
        raise TriggersFileError("{} cannot be read ({}). Nothing was written.".format(path, e))
    if not isinstance(raw, dict):
        raise TriggersFileError("{} must contain a JSON object. Nothing was written.".format(path))
    out = {}
    for k, v in raw.items():                 # migrate files keyed by the raw signature
        out[signature_id(k) if "|" in k else k] = v
    return out


def merge_triggers(triggers, data, update_labels=True):
    for g in data["groups"]:
        g["signature_id"] = g.get("signature_id") or signature_id(g["signature"])
    current = {g["signature_id"] for g in data["groups"]}
    for g in data["groups"]:
        sid = g["signature_id"]
        t = triggers.setdefault(sid, {"label": g.get("pattern") or g["label"], "trigger": ""})
        if not t.get("trigger"):            # inherit explanations written under earlier groupings
            found = OrderedDict()
            for old in g.get("legacy_ids", []):
                o = triggers.get(old) or {}
                if o.get("trigger") and o["trigger"] not in found:
                    found[o["trigger"]] = o.get("label", "")
            if len(found) == 1:
                t["trigger"] = next(iter(found))
            elif found:                     # earlier groups had different explanations: keep all
                t["trigger"] = "Merged from earlier groups: " + " ".join(
                    "({}) {}: {}".format(i, "`{}`".format(lbl) if lbl else "group", txt)
                    for i, (txt, lbl) in enumerate(found.items(), 1))
        if update_labels:
            t["label"] = g.get("pattern") or g["label"]
        # Superseded entries of this group (keys of earlier groupings) are dropped once they add
        # nothing: empty, or their explanation is already in the current entry. Any other text
        # is kept. Entries unrelated to this run (another application's groups) are never touched.
        for old in g.get("legacy_ids", []):
            o = triggers.get(old)
            if o is not None and old not in current and (not o.get("trigger") or o["trigger"] in t.get("trigger", "")):
                del triggers[old]
    return triggers


def write_safely(path, text):
    """Keep the previous version as <name>.bak and replace the file atomically, so neither a
    bad edit nor an interrupted run can lose the explanations."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            path.with_name(path.name + ".bak").write_bytes(path.read_bytes())
        except OSError:
            pass
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(str(tmp), str(path))


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
def cell(text):
    return str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ")


def code(text):
    """Values taken from logs go in code spans: they render literally (no <tag> swallowed, no
    __init__ turned bold) and stay readable as plain text. Pipes are escaped for tables."""
    t = cell(text).strip()
    return "`{}`".format(t) if t else "—"


def short(text, n=90):
    return text if len(text) <= n else text[: n - 1] + "…"


FAILURE_RE = re.compile(r"fail|error|exception|abort|crash", re.I)
MAX_NOTABLE = 30


def build_report(data, triggers, top_warnings, top_errors=50):
    env, per_file, groups = data["environment"], data["per_file"], data["groups"]
    parts = ["CARL " + code(env["CARL"])] if env.get("CARL") else []
    if env.get("CAIP"):
        parts.append("CAIP " + code(env["CAIP"]))
    total = sum(per_file.values())
    out = ["# CAST Analysis Tracebacks Report", "",
           "**Analysis Date:** {}  ".format(data["analysis_date"]),
           "**Environment:** {}  ".format(" / ".join(parts) if parts else "*(not found in logs)*"),
           "**Logs scanned:** {} ({} with tracebacks)".format(data["logs_scanned"], len(per_file)),
           "", "---", "", "## Summary", "", "| Log File | Tracebacks |", "|----------|------------|"]
    for f, c in sorted(per_file.items(), key=lambda kv: (-kv[1], kv[0])):
        out.append("| {} | {} |".format(code(f), c))
    out += ["| **Total** | **{}** |".format(total), "", "---", "", "## Errors by Type", ""]
    if len(data.get("runs", [])) > 1:
        out += ["> ⚠ **{} runs in one folder** ({}): their counts are combined below. Analyse each run "
                "with its own `--input` for per-run figures.".format(
                    len(data["runs"]), ", ".join(code(r) for r in data["runs"])), ""]
    if not groups:
        out.append("*No tracebacks found.*")
    if len(groups) > top_errors:
        out += ["*{} error groups: the {} most frequent have a full section below; all are in the "
                "Summary Table.*".format(len(groups), top_errors), ""]
    for i, g in enumerate(groups[:top_errors], 1):
        title = g["label"] if g.get("variant_count", 1) <= 1 else g.get("pattern") or g["label"]
        out += ["### {}. {} — {} occurrence{}".format(i, code(short(title, 120)), g["count"],
                                                     "" if g["count"] == 1 else "s"), "",
                "| Property | Value |", "|----------|-------|",
                "| **Extension** | {} |".format(code(g["extension"])),
                "| **Block** | {} |".format(code(g["block"])),
                "| **Source** | {} |".format(code(g["source"]))]
        if g["extension_source"] and g["extension_source"] != g["source"]:
            out.append("| **Extension frame** | {} |".format(code(g["extension_source"])))
        out.append("| **Log File** | {} |".format(
            ", ".join("{} ({})".format(code(f), c) for f, c in g["by_file"].items())))
        out.append("| **Error Code** | {} |".format(code(g["error_code"])))
        if g["raised_code"]:
            out.append("| **Raised at** | {} |".format(code(g["raised_code"])))
        if g["chain"]:
            out.append("| **Chained from** | {} |".format(" → ".join(code(c) for c in g["chain"])))
        if g.get("variant_count", len(g["message_variants"])) > 1:
            out.append("| **Message variants** | {} distinct (e.g. {}) |".format(
                g.get("variant_count", len(g["message_variants"])),
                "; ".join(code(short(m, 60)) for m in g["message_variants"][:3])))
        if g["interleaved_count"]:
            out.append("| **Attribution** | ⚠ {} of {} occurrence(s) interleaved with another thread's "
                       "traceback; frames/exception pairing is best-effort |".format(
                           g["interleaved_count"], g["count"]))
        trig = (triggers.get(g["signature_id"]) or {}).get("trigger") or "TRIGGER_TODO"
        runs = [len(r) for l in g["example_lines"] for r in re.findall(r"`+", l)]
        fence = "`" * max(3, max(runs or [0]) + 1)   # a log line starting with ``` can't close it
        out += ["", "> **Trigger:** " + trig, "",            # trigger: Markdown written on purpose
                "**Full Traceback** (first occurrence, {} line {}):".format(code(g["log"]), g["line_no"]),
                "", fence + "text"] + g["example_lines"] + [fence, "", "---", ""]
    out += ["## Summary Table", "",
            "| # | Error | Extension | Block | Source | Log File | Count |",
            "|---|-------|-----------|-------|--------|----------|-------|"]
    for i, g in enumerate(groups, 1):
        files = list(g["by_file"])
        out.append("| {} | {} | {} | {} | {} | {}{} | {} |".format(
            i, code(short(g["label"] if g.get("variant_count", 1) <= 1 else g.get("pattern") or g["label"], 70)),
            code(g["extension"]), code(g["block"]),
            code(g["short_source"]), code(files[0]),
            " (+{} more)".format(len(files) - 1) if len(files) > 1 else "", g["count"]))

    pr = data["problems"]
    out += ["", "---", "", "## Warnings and Errors Without a Traceback", ""]
    if not pr["groups"]:
        out.append("*None found.*")
    else:
        out.append("**Totals:** " + ", ".join("{} {}".format(v, k) for k, v in sorted(pr["totals"].items())) +
                   " in {} log file(s). Top files: ".format(len(pr["by_file"])) +
                   ", ".join("{} ({})".format(code(f), c) for f, c in list(pr["by_file"].items())[:3]) + ".")
        out += ["", "Similar messages are grouped: quoted names, `Kind(...)` objects, paths and numbers are "
                "replaced by placeholders; sample values are listed.", "",
                "| # | Level | Log | Source | Code | Message pattern | Count | Sample values |",
                "|---|-------|-----|--------|------|-----------------|-------|---------------|"]
        for i, g in enumerate(pr["groups"][:top_warnings], 1):
            out.append("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
                i, g["level"], _main_log(g), code(g["source"]), code(g["code"]), code(short(g["template"], 110)),
                g["count"], ", ".join(code(v) for v in _fit(g["values"], 90)) or "—"))
        rest = pr["groups"][top_warnings:]
        # Frequency hides rare but serious messages: every ERROR-level pattern, and every warning that
        # mentions a failure, is shown even beyond the top N (on a CAST 8.3 run the only error and a
        # plugin failure ranked 64th and 72nd of 78).
        notable = [g for g in rest if g["level"] != "WARNING" or FAILURE_RE.search(g["template"])][:MAX_NOTABLE]
        if notable:
            out += ["", "**Errors and failure-like messages beyond the top {}** (rare, but often the most "
                    "important):".format(top_warnings), "",
                    "| Level | Log | Source | Code | Message pattern | Count | Sample values |",
                    "|-------|-----|--------|------|-----------------|-------|---------------|"]
            for g in notable:
                out.append("| {} | {} | {} | {} | {} | {} | {} |".format(
                    g["level"], _main_log(g), code(g["source"]), code(g["code"]), code(short(g["template"], 110)),
                    g["count"], ", ".join(code(v) for v in _fit(g["values"], 90)) or "—"))
        if rest:
            out += ["", "*{} more pattern(s) ({} lines) beyond the top {}{} are listed in tracebacks.json.*".format(
                len(rest), sum(g["count"] for g in rest), top_warnings,
                ", including those above," if notable else "")]
    if data["stray_headers"]:
        out += ["", "## Notes", "",
                "- `[TRACEBACK]` headers with no parseable stack trace (not counted above): " +
                ", ".join("{} ({})".format(code(f), c) for f, c in sorted(data["stray_headers"].items()))]
    return "\n".join(out) + "\n"


def _main_log(g):
    """The log holding most of a pattern's lines (the step that produced it), "+N" for others."""
    files = list(g["by_file"])
    if not files:
        return "—"
    first = files[0].replace("\\", "/").split("/")[-1]
    return code(first) + (" +{}".format(len(files) - 1) if len(files) > 1 else "")


def _fit(values, budget):
    """As many sample values as fit in about `budget` characters (the last one shortened)."""
    out, used = [], 0
    for v in values:
        if used + len(v) > budget:
            if not out:
                out.append(short(v, budget))
            break
        out.append(v)
        used += len(v) + 2
    return out


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


def non_negative(text):
    v = int(text)
    if v < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return v


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="Input")
    ap.add_argument("--output", default="Output")
    ap.add_argument("--triggers", help="extra trigger file to READ, e.g. one uploaded from an earlier "
                                       "session (may be read-only); the working copy is always "
                                       "<output>/triggers.json")
    ap.add_argument("--render-only", action="store_true",
                    help="re-render the report from tracebacks.json and triggers.json without parsing logs")
    ap.add_argument("--top-warnings", type=non_negative, default=30, help="warning patterns shown in the report")
    ap.add_argument("--top-errors", type=non_negative, default=50,
                    help="error groups shown with a full section (all appear in the summary table)")
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

    out_dir = Path(args.output).resolve()
    json_path = out_dir / "tracebacks.json"
    trig_path = out_dir / "triggers.json"   # the working copy is always written here
    import_path = Path(args.triggers).resolve() if args.triggers else None

    try:                                    # read triggers first: on error, write nothing at all
        stored_triggers = load_triggers(trig_path)
        imported = 0
        if import_path and import_path != trig_path:
            if not import_path.exists():
                raise TriggersFileError("--triggers file not found: {}. Nothing was written.".format(import_path))
            for k, v in load_triggers(import_path).items():
                if v.get("trigger") and not (stored_triggers.get(k) or {}).get("trigger"):
                    stored_triggers[k] = v  # explanations already in the working copy win
                    imported += 1
    except TriggersFileError as e:
        print("ERROR: {}".format(e), file=sys.stderr)
        return 2

    if args.render_only:
        if not json_path.exists():
            print("--render-only needs {}; run without it first.".format(json_path), file=sys.stderr)
            return 2
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if any(k not in data for k in ("groups", "per_file")) or \
                any("signature" not in g for g in data.get("groups", [])):
            print("{} comes from an incompatible release; run again without --render-only.".format(
                json_path), file=sys.stderr)
            return 2
        for k, v in (("problems", {"totals": {}, "by_file": {}, "groups": []}), ("stray_headers", {}),
                     ("runs", []), ("environment", {}), ("logs_scanned", len(data["per_file"])),
                     ("analysis_date", "")):
            data.setdefault(k, v)           # sections added by later releases
        for g in data["groups"]:
            g.setdefault("variant_count", len(g.get("message_variants", [])))
            g.setdefault("interleaved_count", 0)
    else:
        input_dir = Path(args.input).resolve()
        if not input_dir.is_dir():
            print("Input folder not found: {}".format(input_dir), file=sys.stderr)
            return 2
        if out_dir == input_dir or out_dir in input_dir.parents:
            print("--output must be a different folder from --input (and not contain it): files in "
                  "the output folder are never analysed.", file=sys.stderr)
            return 2
        data = analyze(input_dir, out_dir)
        if not data["logs_scanned"]:
            print("No *.log files under {}".format(input_dir), file=sys.stderr)
            return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    redact = lambda t: redact_text(mask_secrets(t), args.redact_term, args.redact)
    redacting = bool(args.redact or args.redact_term)
    # Working file: NOT redacted (beyond credentials), so explanations are never destroyed.
    # A tracebacks.json from a redacted run holds redacted labels: keep the stored ones then.
    triggers = merge_triggers(stored_triggers, data, update_labels=not args.render_only)
    clean = OrderedDict((k, {"label": mask_secrets(v.get("label", "")), "trigger": mask_secrets(v.get("trigger", ""))})
                        for k, v in triggers.items())
    write_safely(trig_path, json.dumps(clean, indent=2, ensure_ascii=False))
    shared_path = trig_path.with_name(trig_path.stem + ".shared.json")
    if redacting:                           # shareable copy; keys are hashes, only values redacted
        shared = OrderedDict((k, {"label": redact(v["label"]), "trigger": redact(v["trigger"])})
                             for k, v in clean.items())
        shared_path.write_text(json.dumps(shared, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "tracebacks_report.md").write_text(
        redact(build_report(map_strings(data, redact, skip_keys=("signature_id",)) if redacting else data,
                            triggers, args.top_warnings, args.top_errors)), encoding="utf-8")
    if not args.render_only:
        json_path.write_text(json.dumps(map_strings(data, redact, skip_keys=("signature_id",)),
                                        indent=2, ensure_ascii=False), encoding="utf-8")

    shown = data["groups"][:args.top_errors]  # triggers are needed for the groups shown in full
    todo = sum(1 for g in shown if not (triggers.get(g["signature_id"]) or {}).get("trigger"))
    print("Report written to {}".format(out_dir / "tracebacks_report.md"))
    print("Logs scanned: {} | with tracebacks: {} | tracebacks: {} | error groups: {} | "
          "warning/error lines: {}".format(data["logs_scanned"], len(data["per_file"]),
                                           sum(data["per_file"].values()), len(data["groups"]),
                                           sum(data["problems"]["totals"].values())))
    if data["stray_headers"]:
        print("Headers without a stack trace: {}".format(sum(data["stray_headers"].values())))
    print("Triggers to fill in {}: {}".format(trig_path, todo))
    if import_path and import_path != trig_path:
        print("Read {} explanation(s) from {}; the working copy is {}".format(imported, import_path, trig_path))
    if len(data.get("runs", [])) > 1:
        print("WARNING: {} runs found in one folder ({}); their counts are combined. Analyse each run "
              "with its own --input.".format(len(data["runs"]), ", ".join(data["runs"])), file=sys.stderr)
    if redacting:
        print("Shareable (redacted) triggers: {}  |  {} stays internal".format(shared_path, trig_path.name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
