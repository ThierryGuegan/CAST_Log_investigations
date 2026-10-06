# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this repo is

**CAST run inspector**: tools for analysing CAST (AIP / Imaging) deep-analysis logs.

- `skills/analyze-logs/`: timing, run status, environment (CARL/CAIP, LISA/LTSA, KB schema), extensions. Script: `scripts/analyze_logs.py`.
- `skills/analyze-tracebacks/`: Python tracebacks grouped by exception + message + raise site, plus WARNING/ERROR patterns and `triggers.json` explanations. Script: `scripts/analyze_tracebacks.py`.
- `server.py` + `index.html`: a local web GUI. It **analyses nothing**: it runs the two skill scripts and displays the JSON they write.

The two skills are also used as Claude skills (claude.ai, `~/.claude/skills`), so each `SKILL.md` is a user-facing contract, not just documentation.

## Commands

```bash
python3 server.py                                     # GUI on http://127.0.0.1:8765/ (Windows: py server.py)
python3 tests/run_tests.py                            # server / GUI
python3 skills/analyze-logs/tests/run_tests.py        # analyze-logs
python3 skills/analyze-tracebacks/tests/run_tests.py  # analyze-tracebacks
```

Run **all three** test suites before every commit. They must all pass.

## Hard rules

### Dependencies and portability
- **Standard library only**, everywhere (scripts, server, tests). Never add a pip dependency or a `requirements.txt`.
- Must work on **Windows and Linux**: use `pathlib`, no shell-specific calls, no hard-coded `/`.
- Minimum Python: 3.8 for the skills (see `compatibility:` in each SKILL.md). The README says 3.7 for the server; don't use anything newer than 3.8 without asking.
- Logs can be huge (multi-GB), UTF-16, one-line, out of order, with dates inside messages. Stream files; never load a whole log into memory.

### Where logic lives
- All parsing and analysis logic belongs in the **skill scripts**, never in `server.py` or `index.html`. A fix made in the GUI would not reach the skills or their tests.
- The server and the scripts communicate only through the output files (`OUTPUT_FILES` in `server.py`) and their JSON structure. If you change a JSON field or a file name, update the server, `index.html` and the tests together.
- Exit code **2** means "refused, nothing written" (missing input, output inside input, unreadable triggers file). Keep this contract.

### Security and privacy (non-negotiable)
- **Credentials are always masked**, in every output, as lines are read and before anything is derived from them. Never weaken a masking regex to make a test pass; never add an output path that bypasses masking.
- `--redact` / `--redact-term` masking must keep JSON valid (mask value by value) and never alter placeholders (`<host>`, `<path>`…).
- Never paste or quote raw log lines (in code comments, test fixtures, commit messages, answers). Use the reports or pipe through `--mask`. Test fixtures use invented values only.
- **Never commit real customer logs**, reports or `workspace/` content (it is in `.gitignore`).
- Server: listens on `127.0.0.1` only; writing requests require the `X-CAST-GUI` header; requests for other host names are refused. Keep all three.
- `index.html` loads **nothing from the internet** (no CDN, fonts or scripts). Every value coming from logs is inserted as text (`textContent`), never as HTML.
- Archive extraction refuses entries that escape their folder (zip-slip check). Per-phase zips (CAST 8.3 / AIP Console) are extracted into one folder per phase, never merged.
- Files given by the user (log folders, uploaded `triggers.json`) are **read only**. Deleting a run only removes its copy in the workspace.
- `triggers.json` is internal: the share pack contains only `triggers.shared.json` and masked reports.

## Tests

- Every test case comes from a real bug (audit or real CAST logs). **Every fix comes with a regression test** in the matching `run_tests.py`.
- Tests use `unittest` and temporary folders cleaned up at exit; they must not leave files behind.
- Don't delete or loosen an existing test to make a change pass. If a test seems wrong, stop and explain why.

## Keeping docs in sync

- The two `SKILL.md` files share whole sections (Running both skills, Where things are, credential masking). Edit them in both files identically.
- When a CLI flag, output file or behaviour changes, update the `SKILL.md` of the skill concerned, the script's docstring, and `README.md` if the GUI is affected.
- Bump nothing silently: describe user-visible changes in the commit message.

## Working style

- Small, focused commits with descriptive messages (what and why).
- Before a large change (new output format, change of grouping signature, which would invalidate existing `triggers.json` files), propose the plan first.
- Changing the traceback group signature breaks the explanations users keep across runs: avoid it, or provide a migration.
