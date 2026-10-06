---
name: analyze-tracebacks
description: Finds every Python traceback in CAST (AIP / Imaging) analysis log files, parses each one individually (per thread when lines carry thread IDs) and groups them by exception type, message pattern and raise site, with the extension and version, block or function, full source path and line, CAST error code (e.g. SQL-002, FORMSREPORT-001) and a full example traceback; it also groups WARNING and ERROR lines that have no traceback into message patterns. Use this skill whenever the user asks about errors, exceptions, tracebacks, warnings, crashes or issues in CAST analysis logs, wants them counted or categorized, wants to know which extension is failing, or needs material for a CAST support ticket. It is one half of a complete log analysis, so for a general request such as "analyze these logs", also run the analyze-logs skill, which covers timing, environment and extensions.
compatibility: Python 3.8+ (standard library only). Works on Windows and Linux.
---

# Analyze CAST Analysis Logs for Tracebacks and Warnings

Parsing is done by `scripts/analyze_tracebacks.py`. Your job is to run it, then add the one thing a script cannot do well: explain **why** each error happens.

## Running both skills

analyze-logs (timing, environment, extensions) and analyze-tracebacks (errors, tracebacks, warnings) are complementary. For a general request ("analyze these CAST logs", "what happened in this run?"), run **both** on the same input. Give them the same `--output` folder, then answer with one combined summary. **Start with the run status** from the analyze-logs report (Completed, Failed or Did not finish), then give the duration and silent share, then the main error groups and warning patterns. If the run did not finish or failed, say so first: every count then covers only part of the run. Run only one when the request is clearly about its subject alone ("how long did it take?", "which extension is failing?").

## Where things are

- **Scripts:** `scripts/` is relative to this skill's folder, the one containing this SKILL.md (e.g. `/mnt/skills/user/analyze-tracebacks/` in claude.ai). Call the script with its full path, from the folder that holds the logs.
- **Outputs:** in claude.ai, write them where the user can download them: pass `--output /mnt/user-data/outputs/<run-name>`, then present the report files. Elsewhere, the default `Output/` is fine.
- **Uploaded archives:** unzip them into a working folder first, and pass that folder as `--input`. Some exports (CAST 8.3 / AIP Console) contain **one zip per phase** (`analyze_logs.zip`, `snapshot_logs(1).zip`…) and no `.log` file at the top level. Extract each inner zip into its own folder named after the phase (`analyze`, `snapshot`…). Never extract them all into one folder: several phases contain files with the same name, which would overwrite each other.
- **Quoting log lines.** Reports are masked; raw log files are not. If you read logs directly (grep, head, a quick Python loop) and want to quote a line in your answer or in a support ticket, either take it from a generated report or pass it through the mask first:
  ```bash
  grep -rh --include='*.log' "connect" Input | python3 <skill-dir>/scripts/analyze_tracebacks.py --mask [--redact]
  ```
  Never paste unmasked raw lines into the chat: CAST logs contain credentials (for example `connectPassword="CRYPTED:…"` and `--password` on command lines).

## Steps

1. **Run the script.** The input defaults to `Input/` (recursive) and the output to `Output/`. If the user uploaded a `triggers.json` from an earlier session, pass it with `--triggers <file>`. It is only *read* (uploads are read-only), and its explanations are copied into the working `triggers.json` in the output folder:
   ```bash
   python3 <skill-dir>/scripts/analyze_tracebacks.py --input Input --output Output
   ```
   On Windows use `py <skill-dir>\scripts\analyze_tracebacks.py ...` if `python3` is not on PATH. It writes three files:
   - `tracebacks_report.md`
   - `tracebacks.json`
   - `triggers.json`

   Exit code 2 means the run was refused and nothing was written: the input folder or the logs are missing, `--output` is the input folder (or contains it), or a trigger file can't be read. The message on stderr says which.

   Optional flags:
   - `--top-warnings N` sets how many warning patterns appear in the report (default 30).
   - `--top-errors N` sets how many error groups get a full section (default 50). Every group stays in the Summary Table, and triggers are needed only for the groups shown in full.
   - `--redact` masks IPs, host names and non-CAST paths.
   - `--redact-term TEXT` masks a customer or project name; it can be repeated. Use these when the report will leave the company.

   Credentials are **always** masked, in every output, by key name *content*. This catches `password`, `pwd`, `passphrase`, `secret`, `token`, `api_key`, `access_key`, `private_key` and `credential` anywhere in an identifier, so `connectPassword`, `DB_PASSWORD`, `PGPASSWORD`, `CAST_TOKEN` and `secret_key` are all covered. It works with `=` or `:`, as CLI flags (`-password x`, `--password "x y"`), in JSON (also escaped `\"password\": \"x\"`), XML and YAML, and with quoted or unquoted values. `CRYPTED:…` (CAST-encrypted), `Authorization: Bearer …` and `user:pass@host` are masked too. Lines are masked as they are read, before anything is derived from them. Passwords that contain brackets or dots (`Pass(word)1`, `Summer.Rain`) are masked. Two shapes are indistinguishable from code and are left alone: an all-lowercase dotted value (`summer.rain`), and a call-like value with a lowercase argument (`Pass(word)`).

   It deliberately leaves alone code in traceback source lines (calls such as `parser.next_token()` or `get_secret("db")`, lowercase attributes such as `self.connection_password`), parser messages ("Unexpected token: '}'"), .NET identifiers (`PasswordDeriveBytes`, `Tokens.Jwt`), CAST's own `<<…>>` masked values and public `PublicKeyToken=` assembly ids.

   Before sharing outside the company, also pass the customer's company name with `--redact-term`, because it often appears in Java package names (`com.<company>.…`) that `--redact` doesn't touch.

   `--redact` additionally masks:
   - user names: `-user x`, `User ID=x`, `username=x`
   - hosts: connection-string hosts, `Server=` / `host=` values, URL hosts, IPs, lowercase host names (including country-code domains), and any host followed by a port, including private domains (`dbsrv02.lan.corp.acme:5432`, `//host:5432/db`, `CastStorageService _ host`)
   - paths: UNC paths and non-CAST absolute paths (the file name is kept)

   CAST install paths and `doc.castsoftware.com` links are kept. `--redact-term` values never alter the placeholders (`<path>`, `<host>`…), and JSON outputs are masked value by value, so they stay valid JSON.

2. **Fill in every trigger in `triggers.json`** (the working copy in the output folder). Never fill them in the report, and never in `triggers.shared.json`: neither is read back, so edits there are lost on the next render.

   `triggers.json` maps a short hash of each error group's signature to `{"label", "trigger"}`. The hash is computed before redaction, so it works with redacted outputs and reveals nothing. For each group with an empty `"trigger"`, write one or two sentences explaining what in the analyzed source or the extension causes the error. Base it on the exception message, the **Raised at** code line, the **Block**, and the `During <step> on File(...)` context in the example traceback. Say "Likely inference:" when the evidence is thin. Then re-render without re-parsing:
   ```bash
   python3 <skill-dir>/scripts/analyze_tracebacks.py --render-only --output Output
   ```
   Repeat any `--redact` / `--redact-term` options from the first run. The script prints how many triggers are still empty for the groups shown in full; it must be 0.

   **Keep `triggers.json` valid JSON.** If it can't be read (a trailing comma, a missing quote), the script stops with the line and column of the problem and writes **nothing**, so no explanation is lost. Fix the file, or restore `triggers.json.bak`, the copy kept before every write.

   The two trigger files have different roles:
   - **`triggers.json`** is the internal working file. It is never redacted (only credentials are masked), and it is the only one you edit.
   - **`triggers.shared.json`** is written only when `--redact` / `--redact-term` is used. It is a redacted copy to send outside the company, together with the redacted report.

   Triggers are kept across reruns in the same output folder, and explanations written under earlier groupings are carried over automatically. When several earlier groups merge into one, their explanations are kept side by side, labelled; rewrite them into one if they describe the same cause. Entries of earlier groupings are removed once their explanation lives in the current entry, so the file holds only what is still needed; entries for groups not in this run (another application or run) are kept. In claude.ai the sandbox is wiped between conversations, so **always deliver `triggers.json` with the reports**, saying which file is internal and which can be shared. Tell the user to upload it next time, and to keep it under version control if they track runs. Never wipe an output folder that holds a filled `triggers.json`; copy it out first.

3. **Sanity-check the results.**
   - If the analyze-logs report says the run **did not finish** or **failed**, the counts here cover only the part that ran. Say so before giving them.
   - If the report says **several runs in one folder**, the counts of those runs are combined. Tell the user, and analyse each run separately with its own `--input` if they want per-run figures.
   - The Summary total must equal the sum of the group counts.
   - Mention `[TRACEBACK]` headers without a stack trace, if any.
   - Mention any group flagged **⚠ interleaved**: two threads wrote tracebacks at the same time, so pairing frames with the exception is best-effort.

4. **Answer the user.** Give the top error groups (count, extension and version, one-line trigger), then the main warning patterns from "Warnings and Errors Without a Traceback". The warnings are often the more useful part. Repeated "no definition found" or "no resource found for nuget package" warnings usually mean internal packages or projects were not delivered, so links to them are missing from the results. Point to the report and keep it out of the chat unless asked.

## How tracebacks are parsed (so you can explain results)

- **Each traceback is its own block:** optional `[TRACEBACK]` / "has encountered an issue" header → optional `During X on ...` context → `Traceback (most recent call last)` → frames → exception line.
- **Threads.** Lines are routed by thread ID (`[INFO] [72023] ...`) when present, so concurrent tracebacks do not mix. When unprefixed lines interleave, both tracebacks are still counted and flagged.
- **Counting** uses the case-sensitive `Traceback` marker. A header and its `Traceback (...)` line count once, and a chained traceback counts once, with earlier exceptions listed under **Chained from**. "Traceback" as an ordinary word in a message is ignored when no stack frames follow.
- **Encodings.** UTF-8, UTF-16 (with or without a byte-order mark), Windows-1252 and code page 850 are detected automatically. Windows-1252 is the code page Windows tools often use on French and other Western European systems; code page 850 is the one console tools use there. The encoding is decided line by line, so files mixing them keep every accented character, and a byte-order mark at the start of any line (logs concatenated on Windows) is ignored. One limit: a code-page-850 line whose only accented letters are ambiguous with Windows-1252 punctuation (`voilà`) is read as Windows-1252.
- **Log formats.** These layouts are normalised to `<timestamp> [LEVEL] message` before parsing, so their warnings, errors and tracebacks count like any other:
  - **CAST 8.3 tab-separated analyzer logs:** `Information` / `Warning` / `Error` become levels, and the trailing columns `0 ; 0 …` are dropped.
  - **Orchestration logs:** `INF:` / `WRN:` / `ERR:` / `DBG:`, with or without a timestamp.
- **Log-line prefixes** (timestamp, level, thread ID, `[com.castsoftware.x]` tag) are stripped while keeping indentation. Only indented lines count as frames or source code, so an unrelated log line inside a traceback is never reported as the raising code.
- **Exception lines.** Standard names (ending in Error, Exception, Exit, Interrupt, Iteration or Warning, including dotted ones like `xml.etree.ElementTree.ParseError`) are recognized anywhere in a traceback. Any other class name, such as `cast.application.Abort`, is recognized at the exception position: the first unindented line right after a frame's source line in the same traceback (same thread or tag, or unprefixed).
- **Grouping** uses exception type + message *pattern* + raise site. Quoted values, unquoted dotted names (`com.acme.billing.InvoiceService` → `<name>`), numbers, hex addresses and paths in the message become placeholders, so one bug raised with many different names (`KeyError: 'TABLE_0001_COL'`, `'TABLE_0002_COL'`…) is one group. Different exception types or raise sites never merge. The heading then shows the pattern (`KeyError: '…'`), and **Message variants** gives the number of distinct messages with examples.
- **Field definitions:**
  - **Extension**: from the deepest `com.castsoftware.*` frame path. Names may contain dots and hyphens. If no frame has a versioned path, the name is taken from the header and marked "version unknown".
  - **Block**: the `During X on` marker if present; otherwise the function of the deepest extension frame.
  - **Source**: the full path and line of the deepest frame. If that frame is outside the extension, an extra **Extension frame** row gives the actionable location.
  - **Error Code**: only a `XXX-NNN:` code that directly follows the `[TRACEBACK]` tag (and optional `[..]` tags). Codes are never taken from message text.
- Paths are reported exactly as logged, unless `--redact` is used.

## Warnings and errors without a traceback

**Before attributing a pattern to a technology or step, look at its Log column**: the log holding most of its lines, which names the step (`4-run-metrics-calculation-for-main.log`, `11-run-j2ee-analyzer-….log`). A source tag such as `MAv2` alone is not enough. On a CAST 8.3 run, 1,714 warnings that quote a regular expression containing `SELECT` came from metrics calculation on PHP sources, not from the SQL analysis.

**Before interpreting a large pattern, look at its sample values and their variety.** A pattern with thousands of lines but only a handful of distinct values is usually one repeated, harmless situation, not a broad problem. For example, on a CAST 8.3 run, 40,573 lines of "Duplicate object of type 'phpSection' has been detected : 'php'" came from files with several `<?php … ?>` blocks, each named "php". That is not files being analysed twice. When the logs don't show a cause directly, present it as "likely" (as in triggers), or say the cause is not visible in the logs.

These are lines whose level is WARNING/WARN, ERROR/SEVERE, CRITICAL or FATAL. They are grouped into patterns: quoted names, `Kind(...)` objects, names after words like package/project/type, dotted identifiers, paths and numbers become placeholders, and up to 8 sample values are kept. Each row also shows the **log** most of its lines come from (with "+N" when other logs have some), so the step that produced it is visible. A leading code is kept as its own column, because it identifies the warning kind: `DOTNET.0142:` (.NET), `JAVA068:` (Java), `SECJAVA.004 - ` (security). Method names before `()`, byte dumps (`\xc3,\xa9`), double-quoted text and Java/.NET signatures in single quotes (`'pkg.Class.method(List, int)#param'`) are also variable parts. On real Java runs this turns thousands of warning lines into a few dozen patterns. The report shows the top patterns by frequency, then, in a separate table, **every error-level pattern and every warning mentioning a failure** beyond them. Rare messages are often the most important: on a CAST 8.3 run, the only error and a PHP plugin failure ranked 64th and 72nd of 78 patterns. Always read that table and mention what it contains. A plugin failure doesn't stop the run, so the status can still be Completed, but the results that plugin produces may be missing. All patterns are in `tracebacks.json`.

## Report layout

Every value taken from the logs (file names, messages, paths, versions, placeholders such as `<host>`) is in code formatting. The report therefore reads the same rendered (claude.ai, GitLab, VS Code preview) or as plain text: nothing is swallowed as an HTML tag, and `__init__.py` is not turned bold. Status messages are written as UTF-8, so non-Latin folder names work with any console encoding.

The report contains these sections, in order:
1. Header (date, CARL/CAIP environment, number of logs scanned)
2. Summary table per log file, with a total
3. One section per error group for the `--top-errors` most frequent (default 50), sorted by count. Each has a property table, the trigger and the full first-occurrence traceback (trimmed in the middle beyond 80 lines); groups beyond the cap appear only in the Summary Table.
4. Summary Table, with Source relative to the extension folder
5. Warnings and Errors Without a Traceback
6. Notes (headers without a stack trace)

## Known extensions (context for triggers)

| Extension | Typical error source |
|-----------|---------------------|
| com.castsoftware.formsreport | forms_parser / analyser |
| com.castsoftware.sqlanalyzer | sqlscript_parser |
| com.castsoftware.jee, jeeextensibility | JEE analyser / extensibility |
| com.castsoftware.camel | JavaRoute / JavaRouteChain |
| com.castsoftware.springdata | conversion.py / jdbc.py |
| com.castsoftware.dotnetweb | analyser_dotnet.py (MVC / routing config) |
| com.castsoftware.springmvc, awsjava, html5 | respective analysers |
| com.castsoftware.internal.platform | java_parser/symbols.py, often appears in camel/springdata stacks; the root cause is usually in the calling extension |

## Maintenance

`tests/run_tests.py` holds regression tests for every bug found so far. Run `python3 tests/run_tests.py` after any change to the script; all tests must pass. The redaction code between the `shared-redaction` markers is deliberately identical in analyze-logs and analyze-tracebacks. Apply any change to both scripts, then update `SHARED_BLOCK_SHA` in both test files; the tests fail until you do. The fingerprint only proves that a skill's block hasn't changed since its own test was updated. Each skill installs separately and cannot see the other's code, so two different edits with both fingerprints updated would go unnoticed. Always edit the block in one place and copy it whole into the other script.
