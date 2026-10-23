@echo off
cd /d "%~dp0"
py verify.py || (pause & exit /b 1)
py run.py --host 0.0.0.0 --port 7777
pause
