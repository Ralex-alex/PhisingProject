@echo off
echo Starting PhishSentinel API Server...
echo.

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Start the API server
python api_server.py

REM Keep the window open if there's an error
pause 