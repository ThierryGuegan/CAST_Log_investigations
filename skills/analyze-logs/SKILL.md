---
name: analyze-logs
description: Analyzes a folder of CAST (AIP / Imaging) deep-analysis log files and writes a markdown report with the execution timeline (start, end and duration per log), total run time, run-wide silent periods versus real activity time, environment configuration (CARL and CAIP versions, LISA and LTSA folders, redacted connection string, Knowledge Base schema) and the CAST extensions used with their versions. Use this skill whenever the user asks to analyze CAST analysis logs, wants to know how long a CAST analysis or a step took or why it was slow, which CARL/CAIP version or which com.castsoftware extensions were used, or asks for a summary of a CAST log run, even if they do not say "report". It is one half of a complete log analysis, so for a general request such as "analyze these logs", also run the analyze-tracebacks skill, which covers errors, tracebacks and warnings.
compatibility: Python 3.8+ (standard library only). Works on Windows and Linux.
---

# Analyze CAST Analysis Logs

All parsing is done by `scripts/analyze_logs.py`. Run it rather than re-implementing the logic inline: it handles edge cases (one-line files, UTF-16 logs, trailing blank lines, out-of-order timestamps, dates inside message text, multi-GB files) that ad-hoc snippets get wrong.

## Running both skills

analyze-logs (timing, environment, extensions) and analyze-tracebacks (errors, tracebacks, warnings) are complementary. For a general request ("analyze these CAST logs", "what happened in this run?"), run **both** on the same input. Give them the same `--output` folder, then answer with one combined summary. **Start with the run status** from the analyze-logs report (Completed, Failed or Did not finish), then give the duration and silent share, then the main error groups and warning patterns. If the run did not finish or failed, say so first: every count then covers only part of the run. Run only one when the request is clearly about its subject alone ("how long did it take?", "which extension is failing?").

## Where things are

- **Scripts:** `scripts/` is relative to this skill's folder, the one containing this SKILL.md (e.g. `/mnt/skills/user/analyze-logs/` in claude.ai). Call the script with its full path, from the folder that holds the logs.
- **Outputs:** in claude.ai, write them where the user can download them: pass `--output /mnt/user-data/outputs/<run-name>`, then present the report files. Elsewhere, the default `Output/` is fine.
- **Uploaded archives:** unzip them into a working folder first, and pass that folder as `--input`. Some exports (CAST 8.3 / AIP Console) contain **one zip per phase** (`analyze_logs.zip`, `snapshot_logs(1).zip`…) and no `.log` file at the top level. Extract each inner zip into its own folder named after the phase (`analyze`, `snapshot`…). Never extract them all into one folder: several phases contain files with the same name, which would overwrite each other.
- **Quoting log lines.** Reports are masked; raw log files are not. If you read logs directly (grep, head, a quick Python loop) and want to quote a line in your answer or in a support ticket, either take it from a generated report or pass it through the mask first:
  ```bash
  grep -rh --include='*.log' "connect" Input | python3 <skill-dir>/scripts/analyze_logs.py --mask [--redact]
  ```
  Never paste unmasked raw lines into the chat: CAST logs contain credentials (for example `connectPassword="CRYPTED:…"` and `--password` on command lines).

## Steps

1. **Locate the logs.** The default input is `Input/` (searched recursively) and the default output is `Output/`.

2. **Run the script:**
   ```bash
   python3 <skill-dir>/scripts/analyze_logs.py --input Input --output Output --json
   ```
   On Windows use `py <skill-dir>\scripts\analyze_logs.py ...` if `python3` is not on PATH. Optional flags:
   - `--gap-minutes N` sets the silence threshold (default 5; 0 disables).
   - `--top-silences N` sets how many silent periods and per-log stretches the report lists (default 20, the longest first when there are more). The silence total always counts all of them, and `--json` keeps the full lists. Multi-day runs can have hundreds.
   - `--redact` masks IPs, host names and non-CAST absolute paths. The file name is kept, and CAST install paths are left intact.
   - `--redact-term TEXT` masks a customer or project name; it can be repeated. Use it with `--redact` whenever the user plans to share the report outside their company.

   Credentials are **always** masked, in every output, by key name *content*. This catches `password`, `pwd`, `passphrase`, `secret`, `token`, `api_key`, `access_key`, `private_key` and `credential` anywhere in an identifier, so `connectPassword`, `DB_PASSWORD`, `PGPASSWORD`, `CAST_TOKEN` and `secret_key` are all covered. It works with `=` or `:`, as CLI flags (`-password x`, `--password "x y"`), in JSON (also escaped `\"password\": \"x\"`), XML and YAML, and with quoted or unquoted values. `CRYPTED:…` (CAST-encrypted), `Authorization: Bearer …` and `user:pass@host` are masked too. Lines are masked as they are read, before anything is derived from them. Passwords that contain brackets or dots (`Pass(word)1`, `Summer.Rain`) are masked. Two shapes are indistinguishable from code and are left alone: an all-lowercase dotted value (`summer.rain`), and a call-like value with a lowercase argument (`Pass(word)`).

   It deliberately leaves alone code in traceback source lines (calls such as `parser.next_token()` or `get_secret("db")`, lowercase attributes such as `self.connection_password`), parser messages ("Unexpected token: '}'"), .NET identifiers (`PasswordDeriveBytes`, `Tokens.Jwt`), CAST's own `<<…>>` masked values and public `PublicKeyToken=` assembly ids.

   Before sharing outside the company, also pass the customer's company name with `--redact-term`, because it often appears in Java package names (`com.<company>.…`) that `--redact` doesn't touch.

   `--redact` additionally masks:
   - user names: `-user x`, `User ID=x`, `username=x`
   - hosts: connection-string hosts, `Server=` / `host=` values, URL hosts, IPs, lowercase host names (including country-code domains), and any host followed by a port, including private domains (`dbsrv02.lan.corp.acme:5432`, `//host:5432/db`, `CastStorageService _ host`)
   - paths: UNC paths and non-CAST absolute paths (the file name is kept)

   CAST install paths and `doc.castsoftware.com` links are kept. `--redact-term` values never alter the placeholders (`<path>`, `<host>`…), and JSON outputs are masked value by value, so they stay valid JSON.

   The script writes `Output/logs_analysis_report.md` and, with `--json`, `Output/logs_analysis.json`. Exit code 2 means the run was refused and nothing was written: the input folder or the logs are missing, or `--output` is the input folder (or contains it). The message on stderr says which.

3. **Read the Run Status first** (top of the report, also printed on screen). Every phase in the archive is listed with its own result (each phase's `0-<phase>.log` ends with a return value: analyze, snapshot, prepare-analysis-config, install-extensions…). The overall status:
   - **Completed** means the analysis returned 0 and no phase failed.
   - **Failed** means some phase returned a non-zero value; the report names it. A failed snapshot after a successful analysis is still a failed run.
   - **Did not finish** means there is no return value: the logs stop before the end of the run, either because they were collected while it was still running or because the process was stopped. The report names the last two tasks started; the step in progress is usually one of them.
   - **Unknown** means there is no run-analysis log.

   CAST 8.3 also writes an execution summary (`Status: Execution succeeded`); it is shown under the status, and a summary that reports a failure makes the run **Failed** even if every return value is 0. A phase whose main log has no timestamps (CAST 8.3's `0-accept.log` holds only the command's arguments) is placed by the earliest log in its folder.

   Phases marked "not logged" never write a return value; that is not a failure. Phases missing from the table were not in the archive, which happens when only the analysis logs were collected; say so if the user asks about the snapshot.

   Lead your answer with it. For a run that did not finish, durations, silence and counts describe only the part that ran, so present them that way, never as the duration of the analysis.

4. **Review the warnings** printed on stderr, which are also listed at the end of the report:
   - **A clock change** means the run spans a daylight-saving change; the logs use local time.
     - **Clock going back** ("the clock went back 1 hour") is recognised only when the jump is about 1 hour, at night, on a Sunday in March, April, October or November, *and* the following timestamps confirm that the clock keeps running from the earlier time. Durations then include the repeated hour, and all displayed times stay on the log's own clock.
     - **Clock going forward** ("may be a daylight-saving clock change") is only flagged, and only for a ~1h silence at night on a Sunday in March (northern hemisphere) or September/October (southern).

     A single line with an older timestamp, such as a replayed summary, is ignored like any out-of-order line. Mention a clock change when it affects the figures you quote.
   - **An empty log file** (0 bytes) is listed separately. Empty `externallink` or `linker` step logs are common and usually harmless.
   - **A log shown as N/A** has no line starting with a timestamp and is excluded from the total. This is normal for raw tool output bundled with the logs (CAST-Profiler, 7-Zip, file lists of excluded files); only worry if a real CAST step log is N/A.
   - **No `CARL Version:` line** in any log means the environment table is empty.
   - **An extension with several versions or version `unknown`** should be mentioned to the user.
   - **Several `0-analyze.log` files** means several runs are mixed in one folder. Ask which run to analyze, or analyze them separately with `--input`.

5. **Read the silence figures before talking about duration.** The report gives the **run-wide silent time** (periods when *no* log wrote anything) and the **time with log activity**. **Silence is not the same as idleness.** Before calling a silence a wait, read its "last line before" column:
   - **After an external command or plugin is launched**, the step is **waiting** for it, because it logs nothing until it finishes. Typical last lines are a DMT or Java command line, "Running …", "Starting command", and "Plugin Processing Started…", which starts a Universal Analyzer plugin (`launch.bat`) as a separate process. Report the silent share and the activity time, and name the waiting step. If the silence ends with a failure (for example "UA Plugin : Plugin operation failed"), say how long the step ran before failing: that time was lost as well as the plugin's results.
   - **After a file starts being analysed** (the last line names a source file: `.sql`, `.java`, `.php`, `.cs`…), the analyzer is **working** on that file without logging. That is processing time, not idleness: do not subtract it from the analysis time. Instead, name the slowest files, the ones with the longest silences in the per-log table; they explain where the time went.
   - **Anything else:** say what the last line shows, and don't guess.

   The per-log silent stretches show which step waited on what, but a step can be silent while another works, so do not add them up.

6. **Answer the user** with the key facts and point to the report. The key facts are the run status, the total duration, the silent share (described as waiting or as processing, per step 5), the longest steps, the CARL/CAIP version and the extension count. Do not paste the whole report into chat unless asked.

## What the script extracts, and from where

- **Report header.** The input folder is shown exactly as passed to `--input`, never as the analysis machine's absolute path.
- **Encodings.** UTF-8, UTF-16 (with or without a byte-order mark), Windows-1252 and code page 850 are detected automatically. Windows-1252 is the code page Windows tools often use on French and other Western European systems; code page 850 is the one console tools use there. The encoding is decided line by line, so files mixing them keep every accented character, and a byte-order mark at the start of any line (logs concatenated on Windows) is ignored. One limit: a code-page-850 line whose only accented letters are ambiguous with Windows-1252 punctuation (`voilà`) is read as Windows-1252.
- **Log formats.** Three layouts are read:
  - **CAST 9 / Imaging:** `2026-10-01 20:53:00 [INFO] message`.
  - **CAST 8.3 analyzer logs:** tab-separated, `2026-09-30 11:50:18.734869<TAB>Information<TAB>…<TAB>message<TAB>0 ; 0…`.
  - **Orchestration logs:** level first, `INF: 2026-09-26 00:59:46: message`.
- **Timeline.** For each log, the start and end come from the earliest and latest timestamps of lines **starting** with `YYYY-MM-DD HH:MM:SS` (optionally after `[`). Dates inside message text are ignored. Rows are sorted by start time.
- **Total execution time.** This is the earliest start to the latest end across logs that have timestamps. It is not the sum of durations, because CAST runs steps in parallel.
- **Run-wide silent periods.** These are periods of at least `--gap-minutes` in which no log has any line. They include waits *between* steps, when no log is open at all. Each period shows the last line before it and the first line after it, with their files.
- **Environment.** Each field is taken from the first log that has it.
  - **CAST 9 / Imaging** writes the fields in one block that starts with `CARL Version:`; the report names that log as the source.
  - **CAST 8.3** has no CARL version. Its CAIP version (`CAST 8.3.50 ( Build 10723 )`) is in a tab-separated analyzer log, and its connection appears as `-connectionProfile: <profile> on CastStorageService _ <host>:<port>`. That profile is used only when no log has a `Connection string:` line.

  Fields that appear in no log are shown as absent.
- **Extensions (CAST 8.3).** `0-analyze.log` lists none in this version. The extensions are then taken from three sources:
  - the versioned `Extensions\com.castsoftware.<name>.<version>` folders that analyzers load plugins from;
  - the install log's `name=version` lines;
  - the extensions' own log tags (`[com.castsoftware.php] …`), which give the name only.

  An archive with only the analysis phase may contain no plugin path at all. Its extensions are then listed with version `unknown`; the versions are in the install phase's logs. The install log's `name ( 1.0.0.0 - UpToDate )` lines are installed components with component versions, not extensions, and are ignored.
- **Extensions.** These come from `0-analyze.log`, in lines about downloading, installing, loading or using an extension. The version is split from ids like `com.castsoftware.sqlanalyzer.3.7.24-funcrel`, or taken from a following `1.2.3` or `(version: x)`. A `version x` phrase elsewhere on the line is used only when the line names a single extension. Names may contain dots and hyphens (`com.castsoftware.internal.platform`, `com.castsoftware.omg-ascqm-index`).

## Report layout

Every value taken from the logs (file names, messages, paths, versions, placeholders such as `<host>`) is in code formatting. The report therefore reads the same rendered (claude.ai, GitLab, VS Code preview) or as plain text: nothing is swallowed as an HTML tag, and `__init__.py` is not turned bold. Status messages are written as UTF-8, so non-Latin folder names work with any console encoding.

The report contains these sections, in order:
1. Run Status (Completed / Failed / Did not finish, the last tasks started if unfinished, and a table of every phase's result)
2. Environment Configuration
3. CAST Extensions Used (Extension | Version)
4. Execution Timeline (durations as `Xd Xh Xm Ys`)
5. Total execution time, silent time and activity time
6. Silent Periods, plus silent stretches inside individual logs
7. Notes and Warnings

## Maintenance

`tests/run_tests.py` holds regression tests for every bug found so far. Run `python3 tests/run_tests.py` after any change to the script; all tests must pass. The redaction code between the `shared-redaction` markers is deliberately identical in analyze-logs and analyze-tracebacks. Apply any change to both scripts, then update `SHARED_BLOCK_SHA` in both test files; the tests fail until you do. The fingerprint only proves that a skill's block hasn't changed since its own test was updated. Each skill installs separately and cannot see the other's code, so two different edits with both fingerprints updated would go unnoticed. Always edit the block in one place and copy it whole into the other script.
