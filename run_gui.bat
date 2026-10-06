@echo off
rem Starts the CAST run inspector GUI and opens it in the browser.
rem Needs Python 3.8 or later. Close this window (or press Ctrl+C) to stop the server.
rem Extra options are passed on, e.g.: run_gui.bat --port 9000 --no-browser
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py server.py %*
    goto :done
)
where python >nul 2>nul
if %errorlevel%==0 (
    python server.py %*
    goto :done
)
echo Python was not found. Install Python 3.8 or later from https://www.python.org/downloads/
echo and tick "Add python.exe to PATH" during setup.

:done
if errorlevel 1 pause
