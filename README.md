# CAST run inspector

A local web interface for the **analyze-logs** and **analyze-tracebacks** skills. Drop the zip of a CAST run's logs, or point to a folder. The inspector runs both analyses and shows the results: run status, timeline, errors, warnings, explanations, comparison between runs, and export.

The interface itself analyses nothing. It runs the two skill scripts and displays the JSON they write, so the results are exactly the skills' results.

## Start

You need Python 3.8 or later; nothing else is installed.

```bash
python3 server.py          # Linux / macOS
py server.py               # Windows
```

The browser opens at `http://127.0.0.1:8765/`. Stop the server with Ctrl+C.

Options:
- `--port 8765`: another port.
- `--workspace DIR`: where runs and reports are kept (default: `./workspace`).
- `--skills-dir DIR`: use other copies of the skills. This is the folder that contains `analyze-logs/` and `analyze-tracebacks/`; by default, the copies in `./skills` are used.
- `--max-upload-gb 4`: the largest archive accepted.
- `--max-extract-gb 20`: the largest total size an archive may unpack to, nested zips included. This guards against archives that expand to fill the disk.
- `--no-browser`: don't open the browser.

## Using it

1. **Add a run.** Drop a zip, or give a folder path (quotes from Windows' "Copy as path" are fine). Archives with one zip per phase (CAST 8.3 / AIP Console exports) are unpacked phase by phase, so identically named files don't overwrite each other. To keep your earlier explanations, give the `triggers.json` from a previous analysis of the same application.
2. **Overview.** The run status comes first: Completed, Failed or Did not finish. A completed run that logged ERROR lines reads "Completed, with N error lines" and names the logs that contain them. Then the timeline, the phases, the environment and the extensions.
   - **The timeline** shows each log as a bar. Hatched parts are silences; hover over one to see the last line before it. A silence after a source file starts is processing; after an external command or plugin starts, it is a wait.
3. **Tracebacks.** The Python tracebacks, grouped, each with its first traceback and its explanation.
4. **Explanations.** Write one or two sentences per traceback group. Saving updates the report and keeps a backup of the previous version.
5. **Warnings.** Every warning and error pattern, with the log that produced it. "Only errors and failure-like messages" shows the rare messages that are often the most important. Every column has its own filter (level, text, minimum count) and a click on a column title sorts by it (click again to reverse, a third time to clear). "Clear filters and sorting" resets them.
6. **Compare runs.** Step durations, error groups and warning patterns, side by side with another run.
7. **Export.**
   - **All reports:** for your own use. It includes the working `triggers.json`; keep it for the next analysis.
   - **Share pack:** only for runs analysed with masking. It contains the masked reports and `triggers.shared.json`, never the internal `triggers.json`.
8. **Analyse again.** On any run, re-run the analysis with other options (masking, thresholds) without uploading the logs again. The explanations already written are kept.

## Privacy and security

- **Local only.** The server listens on `127.0.0.1` only, and the page loads nothing from the internet: no fonts, no scripts.
- **Masking.** Credentials are always masked. With masking on, hosts, IP addresses, user names, customer paths and the names you list are masked too. Masking is done by the skill scripts, before anything is shown.
- **Other web pages are blocked.** Writing requests need a header that pages from other sites can't send, and requests addressed to any other host name are refused.
- **Archives can't write outside their folder.** Entries that would escape their folder are refused, and every value from the logs is displayed as text, never as HTML.
- **Your files stay untouched.** Deleting a run removes only its copy in the workspace; logs analysed from a folder are only read. Uploaded explanation files are only read, too.

## Updating the skills

Replace the two folders in `skills/` with the new versions; the interface needs no change. Check with:

```bash
python3 tests/run_tests.py                              # the interface
python3 skills/analyze-logs/tests/run_tests.py          # the skills
python3 skills/analyze-tracebacks/tests/run_tests.py
```
