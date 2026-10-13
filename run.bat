@echo off
cd /d "%~dp0"
if not exist venv (echo Creating environment... & python -m venv venv)
call venv\Scripts\activate.bat
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo INSTALL FAILED - read the message above. A full disk shows "No space left on device".
  pause
  exit /b 1
)
if not exist .env (
  copy .env.example .env >nul
  echo Optional: add an AI key in the file that opens, save, and close Notepad.
  notepad .env
)
echo.
echo Open http://localhost:8000 in your browser. Press Ctrl+C to stop.
python -m uvicorn logsense.app:app --reload
pause
