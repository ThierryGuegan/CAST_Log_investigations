#!/usr/bin/env python3
"""Explain the warnings of CAST C / C++ analysis logs (CAST Imaging / AIP C/C++ analyzer).

A C/C++ log can hold millions of WARNING lines. Most of them come from a handful of root
causes: headers that were not delivered (system headers, third-party SDKs), macros and types
that are therefore unknown, and the same header re-parsed for every source file that includes
it. This script streams the logs (never loading one in memory), counts the lines per kind and
reports the root causes with their evidence and a recommendation.

Outputs (in --output):
  cpp_warnings_report.md   markdown report: verdict, findings, tables
  cpp_warnings.json        machine-readable data

Standard library only, Python 3.8+. Usage:
  python analyze_cpp_warnings.py [--input Input] [--output Output] [--top 15]
                                 [--redact] [--redact-term TEXT ...]
  python analyze_cpp_warnings.py --mask [--redact] < raw_lines.txt

Exit code 2: refused, nothing written (input missing, no C/C++ analyzer log found, --output is
(or contains) the input folder).
"""
import argparse
import io
import json
import os
import re
import sys
from collections import Counter, OrderedDict
from datetime import date, datetime
from pathlib import Path

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

# --------------------------------------------------------------------------- log formats
# Layouts other than "<timestamp> [LEVEL] message", normalised before parsing (copy of the
# rules used by analyze-tracebacks): CAST 8.3 tab-separated analyzer logs and orchestration logs.
_TABLOG_RE = re.compile(r"^\s?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)[\s\x07]*\t\x07?([A-Za-z]+)\x07?\t"
                        r"[^\t]*\t\x07?([^\t]*)")
_LEVEL_WORDS = {"information": "INFO", "info": "INFO", "warning": "WARNING", "warn": "WARNING", "error": "ERROR",
                "fatal": "FATAL", "critical": "CRITICAL", "severe": "ERROR", "debug": "DEBUG", "trace": "TRACE"}
LINE_RE = re.compile(r"^\s?(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s+\[([A-Za-z]+)\]\s?(.*)$")
LEVELS = {"INFO": "INFO", "WARNING": "WARNING", "WARN": "WARNING", "ERROR": "ERROR", "SEVERE": "ERROR",
          "CRITICAL": "ERROR", "FATAL": "ERROR", "DEBUG": "DEBUG", "TRACE": "DEBUG"}

PARSING_RE = re.compile(r"^Parsing file \((\d+)/(\d+)\)\s*(.*?)(?:\.\.\.)?$")
COMPILING_RE = re.compile(r"^Compiling source files \((\d+) items\)")
MISSING_RE = re.compile(r"^Preprocessor cannot find file '([^']*)'\.?\s*(?:\(file (.*?), line (\d+)\))?")
SEVERAL_RE = re.compile(r"^Preprocessor has found several possibilities for (.+?)\. Chose closest : ([^\t]*)(?:\t(.*))?$")
TYPEDEF_RE = re.compile(r"^Skipping illegal redefinition of typedef (\S+?)\.?\s")
TAGGED_RE = re.compile(r"^\[(\w+)\]\s+(.*)$")
IGNORED_RE = re.compile(r"^(.*?):\s+Ignored token '([^']*)'")
ALREADY_RE = re.compile(r"variable already has type (\S+?)\.?$")
UNKNOWN_RE = re.compile(r"Unknown identifier '([^']*)'")
FILEPOS_RE = re.compile(r"\[file '([^']*)'\((\d+),(\d+)\)\]")
ROOT_RE = re.compile(r"^\+root path:\s*(.+)$")
INCLUDE_RE = re.compile(r"^include path: '([^']*)' \(from ([^)]*)\)")
UNIT_RE = re.compile(r"^Running analysis '([^']*)'")
CPP_EXT_RE = re.compile(r"com\.castsoftware\.cpp\.([A-Za-z0-9_.\-]+?)[\\/]")
ENV_RES = {"CARL": re.compile(r"CARL Version:\s*(.+)"), "CAIP": re.compile(r"CAIP Version:\s*(.+)")}
FAILURE_RE = re.compile(r"fail|error|exception|abort|crash|cannot|unable", re.I)

MAX_TEMPLATES = 5000        # distinct message patterns kept (the rest is counted as "other")
MAX_FILES = 100000          # distinct files tracked for per-file counts
MAX_HEADERS = 50000         # distinct missing headers tracked
MAX_TOKENS = 100000         # distinct unknown identifiers tracked
MAX_INCLUDERS = 2000        # distinct includers tracked per missing header
MAX_SAMPLES = 8


# --------------------------------------------------------------------------- header knowledge
# Headers that belong to the operating system / toolchain, not to the analysed application.
C_STD = frozenset("""assert.h ctype.h errno.h float.h limits.h locale.h math.h setjmp.h signal.h stdarg.h
    stddef.h stdint.h stdio.h stdlib.h string.h time.h wchar.h wctype.h inttypes.h stdbool.h iso646.h
    complex.h fenv.h tgmath.h stdalign.h stdatomic.h stdnoreturn.h threads.h uchar.h""".split())
POSIX = frozenset("""unistd.h pthread.h fcntl.h dirent.h semaphore.h sched.h netdb.h poll.h strings.h termios.h
    utime.h dlfcn.h regex.h glob.h grp.h pwd.h syslog.h libgen.h ftw.h fnmatch.h getopt.h iconv.h
    langinfo.h mqueue.h spawn.h sysexits.h wordexp.h aio.h alloca.h malloc.h memory.h stdalign.h""".split())
POSIX_PREFIXES = ("sys/", "netinet/", "arpa/", "linux/", "net/", "bits/", "asm/", "asm-generic/")
CPP_STD = frozenset("""algorithm array atomic bitset chrono condition_variable deque exception fstream functional
    future initializer_list iomanip ios iosfwd iostream istream iterator limits list locale map memory mutex
    new numeric ostream queue random regex set sstream stack stdexcept streambuf string thread tuple
    type_traits typeinfo unordered_map unordered_set utility valarray vector cassert cctype cerrno cfloat
    climits cmath csetjmp csignal cstdarg cstddef cstdint cstdio cstdlib cstring ctime cwchar cwctype""".split())
# QNX Neutrino SDP headers (not found on a Linux / Windows analysis host).
QNX_HEADERS = frozenset("""sys/neutrino.h sys/dispatch.h sys/sched_aps.h sys/netmgr.h sys/iofunc.h sys/resmgr.h
    sys/procmgr.h sys/syspage.h sys/trace.h sys/slog.h sys/slogcodes.h sys/iomsg.h sys/platform.h sys/siginfo.h
    sys/rsrcdbmgr.h sys/rsrcdb.h sys/memmsg.h sys/procfs.h sys/debug.h sys/image.h sys/pps.h
    devctl.h gulliver.h hw/inout.h hw/pci.h hw/sysinfo.h""".split())
QNX_PREFIXES = ("hw/", "sys/dcmd_", "photon/", "screen/", "bps/")
WINDOWS_HEADERS = frozenset("""windows.h winsock2.h winsock.h ws2tcpip.h tchar.h winbase.h winnt.h direct.h conio.h objbase.h shlobj.h atlbase.h afx.h afxwin.h
    d3d9.h d3d11.h dxgi.h mmsystem.h""".split())
# (vendor, header regex on the lower-case include name, identifier-prefix families)
SDK_VENDORS = [
    ("RTI Connext DDS", re.compile(r"^(?:rti_[\w.]*|ndds[\w./]*|reda/.*|osapi/.*|dds_c/.*|dds_cpp/.*|netio/.*|"
                                   r"pres/.*|wh_sm/.*|rh_sm/.*|writer_history/.*|reader_history/.*|dpse/.*|dpde/.*|"
                                   r"disc_dpse/.*|disc_dpde/.*|cdr/.*|commend/.*|db/.*|sysdep/.*|"
                                   r"transport/.*|udp_transport/.*)$"), ("RTI", "NDDS", "DDS", "REDA", "PRES")),
    ("Boost", re.compile(r"^boost/.*$"), ("BOOST",)),
    ("Qt", re.compile(r"^(?:qt[\w./]*|q[a-z]+(?:/.*)?|q[a-z]+\.h)$"), ("Q",)),
    ("OpenSSL", re.compile(r"^openssl/.*$"), ("OPENSSL", "SSL")),
    ("JDK (JNI)", re.compile(r"^(?:jni|jni_md|jvmti)\.h$"), ("JNI",)),
    ("Google Test / Mock", re.compile(r"^(?:gtest|gmock)/.*$"), ("GTEST", "GMOCK")),
]


def classify_header(name):
    """(category, label) of an include name as written in the source (case-insensitive).
    Categories: 'platform' (QNX / Windows SDK), 'system' (C, POSIX, C++ standard library),
    'sdk' (a known third-party SDK), 'other' (project or unknown third-party header)."""
    low = name.replace("\\", "/").lower().lstrip("./")
    if low in QNX_HEADERS or low.startswith(QNX_PREFIXES):
        return "platform", "QNX Neutrino SDP"
    if low in WINDOWS_HEADERS:
        return "platform", "Windows SDK"
    if low in C_STD or low in POSIX or low in CPP_STD or low.startswith(POSIX_PREFIXES):
        return "system", "C / POSIX / C++ standard"
    for label, rx, _fam in SDK_VENDORS:
        if rx.match(low):
            return "sdk", label
    return "other", "not recognised"


def families_of(label):
    for lab, _rx, fam in SDK_VENDORS:
        if lab == label:
            return fam
    return ()


def token_family(token):
    """Identifier prefix before the first underscore (RTI_BOOL -> RTI), '' when there is none."""
    head = token.split("_", 1)[0]
    return head if "_" in token and 2 <= len(head) <= 12 and head.isupper() else ""


# --------------------------------------------------------------------------- parsing
def canonical(line):
    m = _TABLOG_RE.match(line)
    if m and m.group(2).lower() in _LEVEL_WORDS:
        return "{} [{}] {}".format(m.group(1), _LEVEL_WORDS[m.group(2).lower()], m.group(3).strip("\x07"))
    return line


TS_LEN = 24                                         # "YYYY-MM-DD HH:MM:SS.mmm " (a masking regex never spans it)
MASK_CACHE_MAX = 150000


def masked_line(line, cache):
    """mask_line() with a memo. A header is parsed again for every source file that includes it, so
    millions of lines repeat exactly, apart from their timestamp. The memo returns what mask_line
    returns for the first such line, so nothing is masked differently, only computed once."""
    if line[:2] != "20" or len(line) <= TS_LEN or line[19] not in ".," or line[23] != " ":
        return mask_line(line)             # another timestamp layout: no memo
    key = line[TS_LEN:]
    tail = cache.get(key)
    if tail is None:
        tail = mask_line(line)[TS_LEN:]
        if len(cache) < MASK_CACHE_MAX and len(key) < 2000:
            cache[key] = tail
    return line[:TS_LEN] + tail


def parse_ts(text):
    text = text.replace("T", " ").replace(",", ".")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def seconds(a, b):
    return int(round((b - a).total_seconds())) if a and b else None


_NUM_RE = re.compile(r"\d+")
_QUOTED_RE = re.compile(r"'[^']*'")
_SPACE_RE = re.compile(r"\s+")


def message_template(text):
    """Quoted values and numbers become placeholders; the identifier a parser message starts
    with ("RTI_BOOL: Ignored token ...") is a placeholder too."""
    t = _SPACE_RE.sub(" ", text.strip())
    t = re.sub(r"^[^\s:'\"]+: ", "<id>: ", t)
    t = _QUOTED_RE.sub("'…'", t)
    t = re.sub(r"(has type) \S+?\.$", r"\1 <id>.", t)
    return _NUM_RE.sub("N", t)


class Counters(object):
    """Everything counted while streaming one or several logs. Memory is bounded: every
    dictionary has a cap, and what does not fit is counted in an overflow bucket."""

    def __init__(self):
        self.logs = []
        self.tags = Counter()                       # (level, tag) -> lines
        self.templates = OrderedDict()              # (level, template) -> [count, sample, {files}]
        self.template_overflow = 0
        self.missing = {}                           # header -> [count, {includer: n}, first_includer, line]
        self.tokens = {}                            # token -> [ignored, unknown, decorator]
        self.files = {}                             # file -> [warnings, {source file index}]
        self.units = []                             # [index, path, start, warnings]
        self.several = {}                           # header -> [count, chosen, {includer: n}]
        self.typedefs = {}                          # typedef -> [count, file]
        self.includes = []
        self.root = ""
        self.unit_names = []
        self.cpp_versions = OrderedDict()
        self.env = {}
        self.overflow = Counter()
        self.parser_other = 0
        self.cache = {}
        self.mask_cache = {}


def _template_slot(c, level, tmpl, sample, fpath):
    key = (level, tmpl)
    slot = c.templates.get(key)
    if slot is None:
        if len(c.templates) >= MAX_TEMPLATES:
            c.template_overflow += 1
            return
        slot = c.templates[key] = [0, sample, {}]
    slot[0] += 1
    if fpath and (fpath in slot[2] or len(slot[2]) < 200):
        slot[2][fpath] = slot[2].get(fpath, 0) + 1


def _tagged(head, level):
    """(tag, kind, token, template) of a "[Tag] ..." message head (without its [file ..] tail)."""
    m = TAGGED_RE.match(head)
    if not m:
        return None, "other", "", message_template(head)
    tag, rest = m.group(1), m.group(2)
    mi = IGNORED_RE.match(rest)
    if mi:
        return tag, "ignored", mi.group(2), message_template(rest)
    ma = ALREADY_RE.search(rest)
    if ma:
        return tag, "decorator", ma.group(1), message_template(rest)
    mu = UNKNOWN_RE.search(rest)
    if mu:
        return tag, "unknown", mu.group(1), message_template(rest)
    return tag, "other", "", message_template(rest)


def _bump_file(c, fpath, unit):
    slot = c.files.get(fpath)
    if slot is None:
        if len(c.files) >= MAX_FILES:
            c.overflow["files"] += 1
            return
        slot = c.files[fpath] = [0, set()]
    slot[0] += 1
    if len(slot[1]) < 20000:
        slot[1].add(unit)


def _bump_token(c, token, kind):
    slot = c.tokens.get(token)
    if slot is None:
        if len(c.tokens) >= MAX_TOKENS:
            c.overflow["tokens"] += 1
            return
        slot = c.tokens[token] = [0, 0, 0]
    slot["ignored unknown decorator".split().index(kind)] += 1


def parse_log(path, rel, c):
    """Stream one log into the counters. Every line is masked as it is read."""
    info = {"file": rel, "size": 0, "lines": 0, "levels": Counter(), "bytes": Counter(), "first": None,
            "last": None, "progress": None, "total": None, "compiling": 0, "cpp_signals": 0, "unprefixed": 0}
    try:
        info["size"] = path.stat().st_size
    except OSError:
        pass
    unit = -1                                       # index of the source file being parsed
    first_ts = last_ts = None
    for raw in read_lines(path):
        info["lines"] += 1
        line = masked_line(canonical(raw), c.mask_cache)
        m = LINE_RE.match(line)
        if not m:
            info["unprefixed"] += 1
            continue
        ts, lvl, msg = m.group(1), LEVELS.get(m.group(2).upper()), m.group(3)
        if lvl is None:
            info["unprefixed"] += 1
            continue
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        info["levels"][lvl] += 1
        info["bytes"][lvl] += len(raw) + 1
        if lvl == "INFO":
            if msg.startswith("Parsing file"):
                mp = PARSING_RE.match(msg)
                if mp:
                    unit += 1
                    info["progress"], info["total"] = int(mp.group(1)), int(mp.group(2))
                    info["cpp_signals"] += 1
                    c.units.append([unit, mp.group(3), parse_ts(ts), 0])
            elif msg.startswith("Skipping illegal redefinition"):
                mt = TYPEDEF_RE.match(msg)
                mf = FILEPOS_RE.search(msg)
                if mt:
                    info["cpp_signals"] += 1
                    slot = c.typedefs.setdefault(mt.group(1), [0, mf.group(1) if mf else ""])
                    slot[0] += 1
            elif "found several possibilities" in msg:
                ms = SEVERAL_RE.match(msg)
                if ms:
                    info["cpp_signals"] += 1
                    slot = c.several.setdefault(ms.group(1), [0, ms.group(2), {}])
                    slot[0] += 1
                    inc = ms.group(3) or ""
                    if inc in slot[2] or len(slot[2]) < 200:
                        slot[2][inc] = slot[2].get(inc, 0) + 1
            elif msg.startswith("Compiling source files"):
                mc = COMPILING_RE.match(msg)
                if mc:
                    info["compiling"] += 1
                    info["cpp_signals"] += 1
            elif msg.startswith("+root path") and not c.root:
                mr = ROOT_RE.match(msg)
                if mr:
                    c.root = mr.group(1).strip()
            elif msg.startswith("include path"):
                mi = INCLUDE_RE.match(msg)
                if mi:
                    info["cpp_signals"] += 1
                    if len(c.includes) < 200:
                        c.includes.append((mi.group(1), mi.group(2)))
                    me = CPP_EXT_RE.search(mi.group(1))
                    if me:
                        c.cpp_versions[me.group(1)] = None
            elif msg.startswith("Running analysis"):
                mu = UNIT_RE.match(msg)
                if mu and mu.group(1) not in c.unit_names and len(c.unit_names) < 50:
                    c.unit_names.append(mu.group(1))
            else:
                for key, rx in ENV_RES.items():
                    if key not in c.env and key in msg:
                        me = rx.search(msg)
                        if me:
                            c.env[key] = me.group(1).strip()
            continue
        if lvl != "WARNING":
            if lvl == "ERROR":
                _template_slot(c, "ERROR", message_template(msg[:300]), msg[:300], "")
            continue
        # ---- WARNING
        if msg.startswith("Preprocessor cannot find"):
            mm = MISSING_RE.match(msg)
            if mm:
                info["cpp_signals"] += 1
                header, includer = mm.group(1), (mm.group(2) or "")
                slot = c.missing.get(header)
                if slot is None:
                    if len(c.missing) >= MAX_HEADERS:
                        c.overflow["headers"] += 1
                        continue
                    slot = c.missing[header] = [0, {}, includer]
                slot[0] += 1
                if includer in slot[1] or len(slot[1]) < MAX_INCLUDERS:
                    slot[1][includer] = slot[1].get(includer, 0) + 1
                if includer:
                    _bump_file(c, includer, unit)
                if c.units and unit >= 0:
                    c.units[unit][3] += 1
                c.tags[("WARNING", "Preprocessor")] += 1
                continue
        i = msg.find(" [file '")
        head = msg[:i] if i >= 0 else msg
        fpath = ""
        if i >= 0:
            mf = FILEPOS_RE.search(msg, i)
            fpath = mf.group(1) if mf else ""
        parsed = c.cache.get(head)
        if parsed is None:
            parsed = _tagged(head, lvl)
            if len(c.cache) < 200000:
                c.cache[head] = parsed
        tag, kind, token, tmpl = parsed
        c.tags[("WARNING", tag or "untagged")] += 1
        if tag in ("Parser", "Configuration"):
            info["cpp_signals"] += 1
        if kind != "other":
            _bump_token(c, token, kind)
        _template_slot(c, "WARNING", ("[{}] ".format(tag) if tag else "") + tmpl, head[:300], fpath)
        if fpath:
            _bump_file(c, fpath, unit)
        if unit >= 0:
            c.units[unit][3] += 1
    info["first"], info["last"] = parse_ts(first_ts) if first_ts else None, parse_ts(last_ts) if last_ts else None
    return info


def analyze(input_dir, out_dir):
    logs = sorted(p for p in input_dir.rglob("*.log") if p.is_file() and out_dir not in p.parents)
    c = Counters()
    infos = []
    for p in logs:
        info = parse_log(p, str(p.relative_to(input_dir)), c)
        infos.append(info)
    cpp_logs = [i for i in infos if i["cpp_signals"]]
    return c, infos, cpp_logs, len(logs)


# --------------------------------------------------------------------------- results
def module_of(path, root):
    """First folder under the analysed root ("source/manual/EQT_DDS_MFD/..." -> eqt_dds_mfd)."""
    p = path.replace("\\", "/").lower()
    r = root.replace("\\", "/").lower().rstrip("/")
    if r and p.startswith(r + "/"):
        rest = p[len(r) + 1:].split("/")
        return rest[0] if len(rest) > 1 else ""
    return ""


def base(path):
    return path.replace("\\", "/").rstrip("/").split("/")[-1]


def build_data(c, infos, cpp_logs, scanned, top):
    warn_total = sum(i["levels"]["WARNING"] for i in infos)
    info_total = sum(i["levels"]["INFO"] for i in infos)
    err_total = sum(i["levels"]["ERROR"] for i in infos)
    lines_total = sum(sum(i["levels"].values()) for i in infos)
    bytes_warn = sum(i["bytes"]["WARNING"] for i in infos)
    bytes_all = sum(sum(i["bytes"].values()) for i in infos)

    # ---- timing and progress of each log
    logs = []
    for i in infos:
        if not i["cpp_signals"]:
            continue
        done = i["progress"] is not None and i["total"] is not None and i["progress"] >= i["total"]
        logs.append({"file": i["file"], "size_bytes": i["size"], "lines": sum(i["levels"].values()),
                     "warnings": i["levels"]["WARNING"], "info": i["levels"]["INFO"],
                     "errors": i["levels"]["ERROR"],
                     "first": i["first"].strftime("%Y-%m-%d %H:%M:%S") if i["first"] else "",
                     "last": i["last"].strftime("%Y-%m-%d %H:%M:%S") if i["last"] else "",
                     "duration_s": seconds(i["first"], i["last"]),
                     "files_parsed": i["progress"], "files_total": i["total"],
                     "all_files_reached": bool(done)})

    # ---- missing headers
    missing = []
    for header, (n, includers, first) in c.missing.items():
        cat, label = classify_header(header)
        top_inc = sorted(includers.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        missing.append({"header": header, "count": n, "category": cat, "label": label,
                        "includers": len(includers), "top_includers": [{"file": f, "count": k} for f, k in top_inc]})
    missing.sort(key=lambda r: (-r["count"], r["header"]))
    by_cat = OrderedDict()
    for cat in ("sdk", "other", "platform", "system"):
        rows = [r for r in missing if r["category"] == cat]
        if rows:
            by_cat[cat] = {"headers": len(rows), "warnings": sum(r["count"] for r in rows)}
    labels = OrderedDict()
    for r in missing:
        if r["category"] in ("sdk", "platform"):
            s = labels.setdefault(r["label"], {"category": r["category"], "headers": 0, "warnings": 0})
            s["headers"] += 1
            s["warnings"] += r["count"]

    # ---- unknown identifiers
    tokens = []
    for tok, (ign, unk, dec) in c.tokens.items():
        tokens.append({"token": tok, "ignored": ign, "unknown_directive": unk, "decorator": dec,
                       "count": ign + unk + dec, "family": token_family(tok)})
    tokens.sort(key=lambda r: (-r["count"], r["token"]))
    fam = Counter()
    for t in tokens:
        fam[t["family"] or "(no prefix)"] += t["count"]

    # ---- files
    files = []
    for f, (n, units) in c.files.items():
        files.append({"file": f, "warnings": n, "source_files": len(units)})
    files.sort(key=lambda r: (-r["warnings"], r["file"]))
    tracked = sum(r["warnings"] for r in files)

    # ---- source files (parsing units): most warnings, longest parse
    units = []
    for k, u in enumerate(c.units):
        nxt = c.units[k + 1][2] if k + 1 < len(c.units) else None
        end = nxt or (cpp_logs[-1]["last"] if cpp_logs else None)
        dur = seconds(u[2], end) if (u[2] and end and end >= u[2]) else None
        units.append({"index": u[0] + 1, "file": u[1], "warnings": u[3], "seconds": dur})
    heavy_units = sorted(units, key=lambda r: (-r["warnings"], r["index"]))[:top]
    slow_units = sorted([u for u in units if u["seconds"] is not None], key=lambda r: (-r["seconds"], r["index"]))[:top]
    unit_secs = sum(u["seconds"] or 0 for u in units)

    # ---- ambiguous includes and typedefs
    several = []
    for header, (n, chosen, includers) in c.several.items():
        cross = sum(k for inc, k in includers.items()
                    if module_of(chosen, c.root) and module_of(inc, c.root)
                    and module_of(chosen, c.root) != module_of(inc, c.root))
        several.append({"header": header, "count": n, "chosen": chosen, "includers": len(includers),
                        "chosen_module": module_of(chosen, c.root), "other_module_count": cross,
                        "top_includer": max(includers.items(), key=lambda kv: kv[1])[0] if includers else ""})
    several.sort(key=lambda r: (-r["count"], r["header"]))
    typedefs = sorted(({"typedef": t, "count": n, "file": f} for t, (n, f) in c.typedefs.items()),
                      key=lambda r: (-r["count"], r["typedef"]))
    typedef_files = Counter()
    for r in typedefs:
        typedef_files[r["file"]] += r["count"]

    # ---- message patterns
    patterns = []
    for (lvl, tmpl), (n, sample, fmap) in c.templates.items():
        top_file = max(fmap.items(), key=lambda kv: kv[1])[0] if fmap else ""
        patterns.append({"level": lvl, "pattern": tmpl, "count": n, "sample": sample,
                         "files": len(fmap), "top_file": top_file})
    patterns.sort(key=lambda r: (-r["count"], r["pattern"]))
    ignored_total = sum(t["ignored"] for t in tokens)
    parser_total = sum(n for (lvl, tag), n in c.tags.items() if tag in ("Parser", "Configuration"))

    data = OrderedDict()
    data["schema"] = 1
    data["analysis_date"] = date.today().isoformat()
    data["logs_scanned"] = scanned
    data["cpp_logs"] = len(cpp_logs)
    data["environment"] = {"CARL": c.env.get("CARL", ""), "CAIP": c.env.get("CAIP", ""),
                           "cpp_extension": list(c.cpp_versions), "analysis_units": c.unit_names,
                           "root_path": c.root, "include_paths": [{"path": p, "from": s} for p, s in c.includes[:30]]}
    data["totals"] = {"lines": lines_total, "warnings": warn_total, "info": info_total, "errors": err_total,
                      "warning_bytes": bytes_warn, "all_bytes": bytes_all,
                      "by_tag": OrderedDict((("{}:{}".format(l, t)), n) for (l, t), n in c.tags.most_common()),
                      "parser_and_configuration": parser_total, "ignored_token": ignored_total,
                      "overflow": dict(c.overflow), "template_overflow": c.template_overflow}
    data["logs"] = logs
    data["missing_headers"] = {"distinct": len(missing), "warnings": sum(r["count"] for r in missing),
                               "by_category": by_cat, "by_label": labels, "rows": missing[:max(top * 4, 60)]}
    data["unknown_identifiers"] = {"distinct": len(tokens), "warnings": sum(t["count"] for t in tokens),
                                   "by_family": OrderedDict(fam.most_common(15)), "rows": tokens[:max(top * 2, 40)]}
    data["files"] = {"distinct": len(files), "tracked_warnings": tracked, "rows": files[:top]}
    data["source_files"] = {"parsed": len(units), "seconds": unit_secs, "most_warnings": heavy_units,
                            "slowest": slow_units}
    data["ambiguous_includes"] = {"distinct": len(several), "count": sum(r["count"] for r in several),
                                  "rows": several[:top]}
    data["typedef_redefinitions"] = {"distinct": len(typedefs), "count": sum(r["count"] for r in typedefs),
                                     "by_file": [{"file": f, "count": n} for f, n in typedef_files.most_common(5)],
                                     "rows": typedefs[:top]}
    data["patterns"] = patterns
    data["findings"] = build_findings(data)
    return data


# --------------------------------------------------------------------------- findings
def pct(part, whole):
    if not whole:
        return "0%"
    v = 100.0 * part / whole
    return "{:.1f}%".format(v) if 99 <= v < 100 or (0 < v < 1) else "{:.0f}%".format(v)


def n(v):
    return "{:,}".format(v)


def build_findings(d):
    """Root causes in order of impact. Each: id, severity, title, evidence, recommendation."""
    out = []
    tot = d["totals"]
    warn = tot["warnings"]
    cats = d["missing_headers"]["by_category"]
    rows = d["missing_headers"]["rows"]
    labels = d["missing_headers"]["by_label"]

    if cats.get("sdk"):
        sdk = [r for r in rows if r["category"] == "sdk"]
        names = ", ".join("`{}` ({})".format(r["header"], n(r["count"])) for r in sdk[:5])
        vend = [l for l, s in labels.items() if s["category"] == "sdk"]
        fam_words = []
        for v in vend:
            fam_words += list(families_of(v))
        linked = sum(t["count"] for t in d["unknown_identifiers"]["rows"] if t["family"] in fam_words) if fam_words else 0
        ev = ["{} headers of {} not found ({} warnings): {}.".format(
            n(cats["sdk"]["headers"]), ", ".join(vend), n(cats["sdk"]["warnings"]), names)]
        if linked:
            ev.append("Identifiers with the {} prefix account for {} unknown-identifier warnings.".format(
                "/".join(sorted(set(fam_words))), n(linked)))
        out.append({"id": "missing-sdk-headers", "severity": "high",
                    "title": "Third-party SDK headers were not delivered ({})".format(", ".join(vend)),
                    "evidence": ev,
                    "recommendation": "Deliver these headers with the sources (an include folder of the analysis unit, "
                                      "or a dependency / environment profile) so macros and types resolve."})
    if cats.get("other"):
        oth = [r for r in rows if r["category"] == "other"]
        out.append({"id": "missing-other-headers", "severity": "medium",
                    "title": "Other headers were not found",
                    "evidence": ["{} headers not recognised as system or known SDK headers ({} warnings): {}.".format(
                        n(cats["other"]["headers"]), n(cats["other"]["warnings"]),
                        ", ".join("`{}` ({})".format(r["header"], n(r["count"])) for r in oth[:6]))],
                    "recommendation": "Project headers that were not delivered, or an unlisted third-party library: "
                                      "check each against the delivered sources."})
    if cats.get("system") or cats.get("platform"):
        sysrows = [r for r in rows if r["category"] in ("system", "platform")]
        names = ", ".join("`{}`".format(r["header"]) for r in sysrows[:8])
        plat = [l for l, s in labels.items() if s["category"] == "platform"]
        sys_cnt = (cats.get("system") or {}).get("warnings", 0) + (cats.get("platform") or {}).get("warnings", 0)
        sys_hd = (cats.get("system") or {}).get("headers", 0) + (cats.get("platform") or {}).get("headers", 0)
        ev = ["{} system / platform headers not found ({} warnings): {}.".format(n(sys_hd), n(sys_cnt), names)]
        if plat:
            ev.append("Headers of {} are among them, which suggests the code targets {}.".format(
                ", ".join(plat), "that platform" if len(plat) == 1 else "one of these platforms"))
        rec = "Configure a system include path for the target platform"
        if "QNX Neutrino SDP" in plat:
            rec += " (the QNX SDP headers, or a matching environment profile)"
        elif "Windows SDK" in plat:
            rec += " (the Windows SDK / compiler headers)"
        out.append({"id": "missing-system-headers", "severity": "high",
                    "title": "No system include path for the target platform", "evidence": ev,
                    "recommendation": rec + "."})
    ident = d["unknown_identifiers"]
    if ident["rows"]:
        top = ident["rows"][:6]
        ratio = (tot["parser_and_configuration"] / float(tot["ignored_token"])) if tot["ignored_token"] else 0
        ev = ["{} distinct unknown identifiers cause {} warnings; the most frequent: {}.".format(
            n(ident["distinct"]), n(ident["warnings"]),
            ", ".join("`{}` ({})".format(t["token"], n(t["count"])) for t in top))]
        if ratio >= 1.5:
            ev.append("Each ignored token is followed by other parser warnings ({:.1f} parser/configuration "
                      "warnings per ignored token overall).".format(ratio))
        decos = [t["token"] for t in ident["rows"] if t["decorator"]][:3]
        if decos:
            ev.append("Found in front of declarations (probably export / decoration macros): {}.".format(
                ", ".join("`{}`".format(x) for x in decos)))
        out.append({"id": "unknown-identifiers", "severity": "high",
                    "title": "Unknown macros and types cascade into parser warnings", "evidence": ev,
                    "recommendation": "Fixing the missing headers removes most of them. Otherwise declare the macros in "
                                      "the C/C++ analysis unit (empty for export / decoration macros, the real type for "
                                      "type aliases such as a boolean or fixed-width integer)."})
    f = d["files"]["rows"]
    if f and warn:
        top3 = f[:3]
        share = sum(r["warnings"] for r in top3)
        if share >= 0.3 * warn:
            ev = ["{} files produce {} of {} warnings ({}): {}.".format(
                len(top3), n(share), n(warn), pct(share, warn),
                ", ".join("`{}` ({} warnings, in {} source files)".format(base(r["file"]), n(r["warnings"]),
                                                                          n(r["source_files"])) for r in top3))]
            if top3[0]["source_files"] > 1:
                ev.append("A header is parsed again for every source file that includes it, so one problem in "
                          "it is reported again each time.")
            out.append({"id": "concentrated", "severity": "medium",
                        "title": "A few headers account for most of the warnings", "evidence": ev,
                        "recommendation": "Fix these files first (their missing includes or unknown macros), or take "
                                          "them out of the analysis if they are generated and not wanted in the results."})
    amb = d["ambiguous_includes"]
    if amb["distinct"]:
        cross = [r for r in amb["rows"] if r["other_module_count"]]
        ev = ["{} headers have several candidates ({} messages); the analyzer chose the closest one: {}.".format(
            n(amb["distinct"]), n(amb["count"]), ", ".join("`{}` ({})".format(r["header"], n(r["count"]))
                                                           for r in amb["rows"][:5]))]
        if cross:
            ev.append("For {} of them the chosen copy is in another top-level folder than the including file, "
                      "so the choice may be wrong.".format(len(cross)))
        out.append({"id": "ambiguous-includes", "severity": "low",
                    "title": "Several headers exist with the same name", "evidence": ev,
                    "recommendation": "Check that each include resolves to the intended copy; add the right include "
                                      "folder first or remove the duplicated header from the delivered sources."})
    td = d["typedef_redefinitions"]
    if td["distinct"]:
        out.append({"id": "typedef-redefinitions", "severity": "low",
                    "title": "Typedefs defined twice",
                    "evidence": ["{} typedef redefinitions ({} distinct), mostly in {}.".format(
                        n(td["count"]), n(td["distinct"]),
                        ", ".join("`{}`".format(base(x["file"])) for x in td["by_file"][:3]))],
                    "recommendation": "Informational: the analyzer skips the second definition. Usually the same type "
                                      "declared by two headers; no action needed unless the types differ."})
    # run progress
    unfinished = [l for l in d["logs"] if l["files_total"] and not l["all_files_reached"]]
    for l in unfinished:
        out.append({"id": "run-incomplete", "severity": "high",
                    "title": "The log stops before the last source file",
                    "evidence": ["`{}` ends at {} after source file {} of {}: the run did not finish.".format(
                        l["file"], l["last"], n(l["files_parsed"]), n(l["files_total"])),
                        "The log gives no reason for the stop (cancellation, timeout, crash or machine problem); "
                        "check the analyze-logs report and the job history."],
                    "recommendation": "Fix the causes above, then rerun. If it stops again, look for a time limit or an "
                                      "operator action on the step."})
    if warn and tot["lines"] and warn >= 0.5 * tot["lines"] and tot["all_bytes"]:
        out.append({"id": "log-volume", "severity": "medium",
                    "title": "Warnings dominate the log",
                    "evidence": ["{} of {} lines ({}) and {} of the log size are WARNING lines.".format(
                        n(warn), n(tot["lines"]), pct(warn, tot["lines"]), pct(tot["warning_bytes"], tot["all_bytes"]))],
                    "recommendation": "Writing and parsing this volume costs time and disk. Fixing the causes above "
                                      "removes most of it."})
    if tot["errors"]:
        out.append({"id": "errors", "severity": "high", "title": "Error-level lines",
                    "evidence": ["{} ERROR lines; see 'Error-level messages' below.".format(n(tot["errors"]))],
                    "recommendation": "Read them first: unlike warnings, they usually mean results are missing."})
    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda x: order[x["severity"]])
    return out


# --------------------------------------------------------------------------- report
def cell(text):
    return str(text).replace("|", "\\|").replace("`", "'").replace("\n", " ")


def code(text):
    t = cell(text).strip()
    return "`{}`".format(t) if t else "—"


def short(text, k=90):
    return text if len(text) <= k else text[: k - 1] + "…"


def size_text(b):
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024 or unit == "GB":
            return "{:.1f} {}".format(b, unit) if unit != "B" else "{} B".format(b)
        b /= 1024.0


def duration_text(s):
    if s is None:
        return "—"
    return "{}h {:02d}m {:02d}s".format(s // 3600, s % 3600 // 60, s % 60)


def build_report(d, top):
    env, tot = d["environment"], d["totals"]
    out = ["# CAST C/C++ Analysis Warnings Report", "",
           "**Analysis Date:** {}  ".format(d["analysis_date"]),
           "**Logs scanned:** {} ({} with C/C++ analyzer output)  ".format(d["logs_scanned"], d["cpp_logs"])]
    bits = []
    if env["cpp_extension"]:
        bits.append("C/C++ extension " + ", ".join(code(v) for v in env["cpp_extension"]))
    if env["CARL"]:
        bits.append("CARL " + code(env["CARL"]))
    if env["CAIP"]:
        bits.append("CAIP " + code(env["CAIP"]))
    if bits:
        out.append("**Environment:** " + " / ".join(bits) + "  ")
    if env["analysis_units"]:
        out.append("**Analysis units:** " + ", ".join(code(u) for u in env["analysis_units"]) + "  ")
    out += ["", "---", "", "## Verdict", ""]
    unfinished = [l for l in d["logs"] if l["files_total"] and not l["all_files_reached"]]
    if unfinished:
        l = unfinished[0]
        out += ["> ⚠ **The run did not finish**: the log ends after source file {} of {} ({}). Every count below "
                "covers only the part that ran.".format(n(l["files_parsed"]), n(l["files_total"]), l["last"]), ""]
    out.append("{} lines: **{} WARNING**, {} INFO, {} ERROR ({} of the lines and {} of the size are warnings).".format(
        n(tot["lines"]), n(tot["warnings"]), n(tot["info"]), n(tot["errors"]),
        pct(tot["warnings"], tot["lines"]), pct(tot["warning_bytes"], tot["all_bytes"])))
    out.append("")
    if d["findings"]:
        out += ["| # | Severity | Finding |", "|---|----------|---------|"]
        for k, f in enumerate(d["findings"], 1):
            out.append("| {} | {} | {} |".format(k, f["severity"], cell(f["title"])))
    else:
        out.append("*No known root cause found.*")
    out += ["", "---", "", "## Findings", ""]
    for k, f in enumerate(d["findings"], 1):
        out += ["### {}. {}".format(k, f["title"]), ""]
        out += ["- " + e for e in f["evidence"]]
        out += ["", "**Recommendation:** " + f["recommendation"], ""]

    out += ["---", "", "## Run overview", "", "| Log | Size | Lines | WARNING | INFO | ERROR | Start | End | Duration | "
            "Source files reached |", "|-----|------|-------|---------|------|-------|-------|-----|----------|"
            "------|"]
    for l in d["logs"]:
        prog = "{} / {}".format(n(l["files_parsed"]), n(l["files_total"])) if l["files_total"] else "—"
        out.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
            code(l["file"]), size_text(l["size_bytes"]), n(l["lines"]), n(l["warnings"]), n(l["info"]), n(l["errors"]),
            l["first"] or "—", l["last"] or "—", duration_text(l["duration_s"]), prog))
    out += ["", "Warnings by source tag: " + ", ".join(
        "{} {}".format(code(k.split(":", 1)[1]), n(v)) for k, v in list(tot["by_tag"].items())[:8]
        if k.startswith("WARNING:")), ""]

    mh = d["missing_headers"]
    out += ["---", "", "## Headers the preprocessor could not find", ""]
    if not mh["distinct"]:
        out.append("*None.*")
    else:
        out += ["{} distinct headers, {} warnings.".format(n(mh["distinct"]), n(mh["warnings"])), "",
                "| Kind | Headers | Warnings |", "|------|---------|----------|"]
        names = {"sdk": "Third-party SDK", "other": "Not recognised (project or third-party)",
                 "platform": "Platform SDK", "system": "System (C / POSIX / C++)"}
        for cat, s in mh["by_category"].items():
            out.append("| {} | {} | {} |".format(names[cat], n(s["headers"]), n(s["warnings"])))
        out += ["", "| Header | Kind | Warnings | Including files | Most frequent includer |",
                "|--------|------|----------|-----------------|------------------------|"]
        for r in mh["rows"][:max(top * 2, 30)]:
            ti = r["top_includers"][0]["file"] if r["top_includers"] else ""
            out.append("| {} | {} | {} | {} | {} |".format(code(r["header"]), cell(r["label"]), n(r["count"]),
                                                          n(r["includers"]), code(base(ti)) if ti else "—"))
    ui = d["unknown_identifiers"]
    out += ["", "---", "", "## Unknown identifiers", ""]
    if not ui["rows"]:
        out.append("*None.*")
    else:
        out += ["{} distinct identifiers, {} warnings. *Ignored token*: the parser skipped it; *Unknown directive*: "
                "reported as probably an unknown compilation directive; *Before declaration*: found where a type "
                "was expected (typical of export macros).".format(n(ui["distinct"]), n(ui["warnings"])), "",
                "| Identifier | Warnings | Ignored token | Unknown directive | Before declaration | Prefix |",
                "|------------|----------|---------------|-------------------|--------------------|--------|"]
        for t in ui["rows"][:max(top * 2, 30)]:
            out.append("| {} | {} | {} | {} | {} | {} |".format(code(t["token"]), n(t["count"]), n(t["ignored"]),
                                                               n(t["unknown_directive"]), n(t["decorator"]),
                                                               code(t["family"])))
        out += ["", "By prefix: " + ", ".join("{} {}".format(code(k), n(v)) for k, v in ui["by_family"].items()), ""]

    fl = d["files"]
    out += ["---", "", "## Where the warnings come from", "", "Files that produce the most warnings. *Source files* "
            "is how many parsed source files reported warnings for it: a header is parsed again for each file that "
            "includes it.", "", "| File | Warnings | Share | Source files |", "|------|----------|-------|--------------|"]
    for r in fl["rows"]:
        out.append("| {} | {} | {} | {} |".format(code(r["file"]), n(r["warnings"]),
                                                   pct(r["warnings"], tot["warnings"]), n(r["source_files"])))
    sf = d["source_files"]
    if sf["parsed"]:
        out += ["", "Source files with the most warnings (all warnings logged while parsing them, headers included):", "",
                "| # | Source file | Warnings | Time |", "|---|-------------|----------|------|"]
        for r in sf["most_warnings"][:min(top, 10)]:
            out.append("| {} | {} | {} | {} |".format(r["index"], code(r["file"]), n(r["warnings"]),
                                                      duration_text(r["seconds"])))
        out += ["", "Slowest source files:", "", "| # | Source file | Time | Warnings |", "|---|-------------|------|----------|"]
        for r in sf["slowest"][:min(top, 10)]:
            out.append("| {} | {} | {} | {} |".format(r["index"], code(r["file"]), duration_text(r["seconds"]),
                                                      n(r["warnings"])))
    amb = d["ambiguous_includes"]
    out += ["", "---", "", "## Ambiguous includes", ""]
    if not amb["distinct"]:
        out.append("*None.*")
    else:
        out += ["{} headers, {} messages. The log names only the copy that was chosen.".format(n(amb["distinct"]),
                                                                                              n(amb["count"])), "",
                "| Header | Messages | Chosen copy | Including files | Chosen in another folder |",
                "|--------|----------|-------------|-----------------|--------------------------|"]
        for r in amb["rows"]:
            out.append("| {} | {} | {} | {} | {} |".format(code(r["header"]), n(r["count"]), code(r["chosen"]),
                                                          n(r["includers"]), n(r["other_module_count"])))
    td = d["typedef_redefinitions"]
    out += ["", "---", "", "## Typedef redefinitions", ""]
    if not td["distinct"]:
        out.append("*None.*")
    else:
        out += ["{} messages, {} distinct typedefs.".format(n(td["count"]), n(td["distinct"])), "",
                "| Typedef | Messages | File |", "|---------|----------|------|"]
        for r in td["rows"]:
            out.append("| {} | {} | {} |".format(code(r["typedef"]), n(r["count"]), code(base(r["file"]))))
    pats = d["patterns"]
    shown = [p for p in pats if p["level"] == "WARNING"][:top]
    out += ["", "---", "", "## Warning patterns", "", "| Warnings | Pattern | Files | Example file |",
            "|----------|---------|-------|--------------|"]
    for p in shown:
        out.append("| {} | {} | {} | {} |".format(n(p["count"]), code(short(p["pattern"], 110)), n(p["files"]),
                                                  code(base(p["top_file"])) if p["top_file"] else "—"))
    errs = [p for p in pats if p["level"] == "ERROR"]
    out += ["", "## Error-level messages", ""]
    if not errs:
        out.append("*None.*")
    else:
        out += ["| Count | Pattern |", "|-------|---------|"]
        for p in errs[:30]:
            out.append("| {} | {} |".format(n(p["count"]), code(short(p["pattern"], 140))))
    notes = []
    ov = tot["overflow"]
    if ov or tot["template_overflow"]:
        notes.append("Some counters hit their memory cap (more distinct values than tracked): {}. The figures "
                     "are lower bounds.".format(", ".join("{} {}".format(k, n(v)) for k, v in ov.items())
                                                or "message patterns"))
    if notes:
        out += ["", "---", "", "## Notes", ""] + ["- " + x for x in notes]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- command line
def utf8_stdio():
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, io.UnsupportedOperation):
            try:
                setattr(sys, name, io.TextIOWrapper(stream.buffer, encoding="utf-8", errors="replace",
                                                    line_buffering=True))
            except AttributeError:
                pass


def positive(text):
    v = int(text)
    if v < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return v


def main():
    utf8_stdio()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="Input")
    ap.add_argument("--output", default="Output")
    ap.add_argument("--top", type=positive, default=15, help="rows per table in the report (default 15)")
    ap.add_argument("--mask", action="store_true",
                    help="mask text read from stdin (credentials always; hosts/paths with --redact) and print it")
    ap.add_argument("--redact", action="store_true", help="mask IPs, host names and non-CAST absolute paths")
    ap.add_argument("--redact-term", action="append", default=[],
                    help="extra text to mask (repeatable), e.g. a project or customer name")
    args = ap.parse_args()
    if args.mask:
        sys.stdout.write(mask_text(decode_text(sys.stdin.buffer.read()), args.redact_term, args.redact))
        return 0

    input_dir, out_dir = Path(args.input).resolve(), Path(args.output).resolve()
    if not input_dir.is_dir():
        print("Input folder not found: {}".format(input_dir), file=sys.stderr)
        return 2
    if out_dir == input_dir or out_dir in input_dir.parents:
        print("--output must be a different folder from --input (and not contain it): files in the output "
              "folder are never analysed.", file=sys.stderr)
        return 2
    c, infos, cpp_logs, scanned = analyze(input_dir, out_dir)
    if not scanned:
        print("No *.log files under {}".format(input_dir), file=sys.stderr)
        return 2
    if not cpp_logs:
        print("No C/C++ analyzer log found among the {} log(s) under {} (no 'Parsing file (n/N)', "
              "'Preprocessor ...' or '[Parser]' lines). Nothing was written.".format(scanned, input_dir),
              file=sys.stderr)
        return 2
    data = build_data(c, infos, cpp_logs, scanned, args.top)

    out_dir.mkdir(parents=True, exist_ok=True)
    redact = lambda t: redact_text(mask_secrets(t), args.redact_term, args.redact)
    redacting = bool(args.redact or args.redact_term)
    shown = map_strings(data, redact) if redacting else data
    (out_dir / "cpp_warnings_report.md").write_text(redact(build_report(shown, args.top)), encoding="utf-8")
    (out_dir / "cpp_warnings.json").write_text(json.dumps(map_strings(data, redact), indent=2, ensure_ascii=False),
                                               encoding="utf-8")
    t = data["totals"]
    print("Report written to {}".format(out_dir / "cpp_warnings_report.md"))
    print("C/C++ logs: {} of {} | lines: {} | WARNING: {} | ERROR: {} | findings: {}".format(
        len(cpp_logs), scanned, n(t["lines"]), n(t["warnings"]), n(t["errors"]), len(data["findings"])))
    for l in data["logs"]:
        if l["files_total"] and not l["all_files_reached"]:
            print("WARNING: {} ends after source file {} of {}: the run did not finish.".format(
                l["file"], l["files_parsed"], l["files_total"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
