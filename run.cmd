@echo off
cd /d "%~dp0"
echo Open http://127.0.0.1:8765/ in your browser.
python app.py --serve
pause
