---
name: analyze-cpp-warnings
description: Explains the WARNING lines of a CAST (AIP / Imaging) C / C++ analyzer log (com.castsoftware.cpp), which can reach millions. It finds the root causes behind them with counts and evidence, and writes a markdown report with a recommendation for each one - headers the preprocessor could not find (system headers and the target platform, for example QNX; third-party SDKs such as RTI Connext DDS), unknown macros and types that cascade into parser warnings, generated headers re-parsed for every source file, headers that exist in several folders, typedef redefinitions - and says whether the run reached its last source file. Use this skill whenever the user asks why a C or C++ analysis is slow, huge, cancelled or full of warnings, mentions "Preprocessor cannot find file", "Ignored token", "unknown compilation directive" or "several possibilities", sends a log named like "comcastsoftwarecpp-for-technology-cpp", or asks which include folders, SDK headers or macros are missing from a C/C++ analysis unit, even if they do not say "warnings".
compatibility: Python 3.8+ (standard library only). Works on Windows and Linux.
---

# Analyze CAST C/C++ Analyzer Warnings

All parsing is done by `scripts/analyze_cpp_warnings.py`. Your job is to run it, read the findings, and answer with the root causes in order of impact. A C/C++ log is mostly one problem repeated: the analyzer cannot find headers, so macros and types are unknown, and every unknown token makes the parser warn several times. The same generated header is then parsed again for every source file that includes it. The script streams the log (a 1.6 GB log with 4 million warnings takes about half a minute) and never loads it in memory.

## With the other skills

This skill covers the warnings of the C/C++ analyzer only. For a general request ("analyze these logs", "what happened in this run?"), also run **analyze-logs** (timing, run status, environment, extensions) and **analyze-tracebacks** (Python tracebacks, other warnings and errors) on the same input, with the same `--output` folder, and give one combined answer that starts with the run status. Run this one alone when the request is about the C/C++ warnings, include paths, missing headers or macros.

## Where things are

- **Scripts:** `scripts/` is relative to this skill's folder, the one containing this SKILL.md (e.g. `/mnt/skills/user/analyze-cpp-warnings/` in claude.ai). Call the script with its full path, from the folder that holds the logs.
- **Outputs:** in claude.ai, write them where the user can download them: pass `--output /mnt/user-data/outputs/<run-name>`, then present the report files. Elsewhere, the default `Output/` is fine.
- **Uploaded archives:** unzip them into a working folder first, and pass that folder as `--input`. Some exports (CAST 8.3 / AIP Console) contain **one zip per phase** (`analyze_logs.zip`, `snapshot_logs(1).zip`…) and no `.log` file at the top level. Extract each inner zip into its own folder named after the phase (`analyze`, `snapshot`…). Never extract them all into one folder: several phases contain files with the same name, which would overwrite each other.
- **Quoting log lines.** Reports are masked; raw log files are not. If you read logs directly (grep, head, a quick Python loop) and want to quote a line in your answer or in a support ticket, either take it from a generated report or pass it through the mask first:
  ```bash
  grep -rh --include='*.log' "connect" Input | python3 <skill-dir>/scripts/analyze_cpp_warnings.py --mask [--redact]
  ```
  Never paste unmasked raw lines into the chat: CAST logs contain credentials (for example `connectPassword="CRYPTED:…"` and `--password` on command lines).

## Steps

1. **Run the script.** The input defaults to `Input/` (recursive) and the output to `Output/`:
   ```bash
   python3 <skill-dir>/scripts/analyze_cpp_warnings.py --input Input --output Output
   ```
   On Windows use `py <skill-dir>\scripts\analyze_cpp_warnings.py ...` if `python3` is not on PATH. It writes two files:
   - `cpp_warnings_report.md`
   - `cpp_warnings.json`

   Exit code 2 means the run was refused and nothing was written: the input folder is missing, no log holds C/C++ analyzer output, or `--output` is the input folder (or contains it). The message on stderr says which. Logs that are not from the C/C++ analyzer are skipped and counted in "Logs scanned".

   Optional flags:
   - `--top N` sets how many rows each table shows (default 15).
   - `--redact` masks IPs, host names and non-CAST paths; `--redact-term TEXT` masks a customer or project name and can be repeated. Use these when the report will leave the company. Credentials are always masked, as lines are read, whatever the options.

2. **Read the verdict and the findings.** They are in order of impact. If the report says **the run probably did not finish**, say so first: the log ends before the last source file, so every count covers only the part that ran, and the log never says why it stopped (cancellation, time limit, crash). "Probably" because the log cannot show whether the analyzer skips some of the N items on purpose; the analyze-logs run status settles it. Do not guess a cause; point to the analyze-logs report and the job history.

3. **Answer the user**, with this shape. Keep the report out of the chat unless asked.
   - The scale: lines, warnings and their share of the log, whether the run finished.
   - Each root cause, with its number and the **recommendation**:
     1. *Third-party SDK headers not delivered* (the vendor is named when the headers are recognised): deliver them as an include folder of the analysis unit.
     2. *System include path missing*: configure the target platform's headers. Headers such as `sys/neutrino.h` mean QNX Neutrino, so the QNX SDP (or a matching environment profile) is needed; the report names the platform it recognised.
     3. *Unknown macros and types*: the top identifiers with their counts. Fixing the headers removes most of them; otherwise declare the macros in the analysis unit (empty for export macros, the real type for type aliases).
     4. *A few headers produce most warnings, each parsed again per source file*: fix these first, or exclude generated files that are not wanted in the results.
     5. *Same header name in several folders*: the analyzer chose the closest copy; check it is the intended one.
     6. *Typedef redefinitions*: informational; the analyzer skips the second definition.
     7. *The analyzer reports that the analysis stopped* (cancelled on user request, run-time or unknown exception, fatal error, paths of the configuration that no longer exist): quote the message and the resolution from the report. A crash ("please send the preprocessed file") goes to CAST Support with that file; a cancellation is restarted.
     8. *Messages the CAST documentation rates as errors* and logged at ERROR level (unable to open a file, invalid include path in an environment profile, parsing error, ...): their impact is that the results are corrupt or incomplete.
   - The **Documented log messages** section of the report lists every message of the CAST documentation that the log contains, with the level, impact and resolution the documentation gives. Use it to answer "what does this message mean?". A message the documentation rates as an error can be logged as a WARNING (for example the unknown compilation directive of the `[Configuration]` tag, which every C/C++ run has); say what the documentation says, but do not present it as a crash.
   - If the analysis ran out of memory (the documentation advises watching the process: above about 1.9 GB the analysis unit is too big), the fix is to split it into several smaller analysis units.
   - What improves once fixed: fewer warnings, a smaller log, and more accurate links, because types that are currently ignored (for example the application's own generated `*_t` types) become known objects.
   - Then: fix, rerun, and look for a time limit or operator action if the run stops again.

4. **Sanity-check** before answering:
   - The documented level, impact and resolution come from the CAST documentation (C and Cpp Analyzer 3.0, *Log messages*), not from this log. A message that is not in that section is not described there: do not invent a meaning for it.
   - Quote the numbers of the report, not your own recount. Warnings by source tag add up to the WARNING total (a few warnings have no tag).
   - A header is classified *Not recognised* when it is neither a system header nor a known SDK; say "project or third-party headers" for those, and never name a vendor the report did not name.
   - Per-file counts (*Where the warnings come from*) cover the warnings that name a file. A note appears in the report if a memory cap was hit, and the figures are then lower bounds.

## How the log is read (so you can explain results)

- **Line kinds.** `Preprocessor cannot find file 'x.h'. (file F, line N)` is a missing include. `[Parser] TOKEN: Ignored token 'TOKEN'.` means the parser skipped an identifier it does not know. `[Parser] ...: variable already has type MACRO.` and `Variable name expected` are follow-on messages, typically after an export macro in front of a declaration. `[Configuration] X: Unknown identifier 'X' is probably an unknown compilation directive` is the analyzer itself suspecting a missing macro. `Preprocessor has found several possibilities for h. Chose closest : path` is an ambiguous include. `Skipping illegal redefinition of typedef T` is a typedef defined twice.
- **Source files.** `Parsing file (k/N) path...` starts source file k of N. Warnings are attributed to the file named in the line (`[file '...'(line,col)]`, or `(file ..., line ...)`), and to the source file being parsed at that moment. A header's *Source files* count is how many parsed source files reported warnings for it, which is how many times it was parsed.
- **Header kinds.** *System* (C, POSIX, C++ standard library), *Platform SDK* (QNX Neutrino, Windows), *Third-party SDK* (RTI Connext DDS, Boost, Qt, OpenSSL, JNI, Google Test), *Not recognised* (anything else). The lists are in the script (`classify_header`); extend them there, with a test.
- **Layouts.** `<timestamp> [LEVEL] message` and the CAST 8.3 tab-separated layout; UTF-8, UTF-16 and Windows code pages are detected automatically.
- **Completion.** A log is complete when the last `Parsing file (k/N)` has k = N. The script knows no end-of-analysis line, so "complete" only means every source file was reached.

## Report layout

Every value taken from the logs is in code formatting, so the report reads the same rendered or as plain text. Sections, in order:
1. Header (date, C/C++ extension version, analysis units)
2. Verdict: run status, scale, table of findings
3. Findings: evidence and recommendation for each
4. Run overview: per log size, lines per level, start, end, duration, source files reached
5. Headers the preprocessor could not find (by kind, then per header with the file that includes it most)
6. Unknown identifiers
7. Where the warnings come from: files, source files with the most warnings, slowest source files
8. Ambiguous includes
9. Typedef redefinitions
10. Documented log messages (grouped like the CAST documentation: analysis stops prematurely, missing source code, configuration problems, ambiguous object names, other problems)
11. Warning patterns and error-level messages
12. Notes (memory caps, if hit)

## Maintenance

The catalogue of documented messages is `KNOWN_MESSAGES` in the script (id, documentation issue, regex tried on the lowercase message pattern, title, documented level, impact, resolution, whether the analysis ended). First match wins, so specific entries come first. When the documentation changes, edit it there and keep `DocumentedMessages.SAMPLES` in the tests complete: a test fails if an entry has no sample. Missing headers are counted apart from the patterns, so their line count is added to the catalogue separately.

`tests/run_tests.py` holds regression tests; run `python3 tests/run_tests.py` after any change, all must pass. The redaction code between the `shared-redaction` markers is deliberately identical in analyze-logs, analyze-tracebacks and this skill. Apply any change to all three scripts, then update `SHARED_BLOCK_SHA` in all three test files; each skill installs separately and cannot see the others' code, so always edit the block in one place and copy it whole into the others. The only masking logic added here is a memo that returns exactly what `mask_line` returns for the first identical line (the same line repeats once per including source file).
