@echo off
SET PORT=7474
echo Starting Cloud Space Guard on http://127.0.0.1:%PORT% ...
start "" "http://127.0.0.1:%PORT%"
python "%~dp0space_guard_agent.py" serve --port %PORT%
pause
