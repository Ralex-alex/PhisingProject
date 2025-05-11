@echo off
title Phishing Detector Startup

echo Starting Phishing Detection System...
echo.

REM Create virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install requirements if needed
echo Checking dependencies...
pip install -r Requirements.txt

REM Generate icons
echo Generating icons...
python create_icon.py
python generate_extension_icons.py

REM Start API server
echo Starting API server...
start cmd /k "title Phishing Detection API Server && python api_server.py"

REM Wait for server to start
echo Waiting for API server to start...
timeout /t 5 /nobreak > nul

REM Start GUI application
echo Starting GUI application...
start pythonw phishing_detector_gui.py

echo.
echo Phishing Detection System started successfully!
echo.
echo Instructions:
echo - API server is running at http://localhost:8000
echo - GUI application is now open
echo - Browser extension can be loaded from the 'browser_extension' folder
echo.
echo Press any key to exit this window...
pause > nul 