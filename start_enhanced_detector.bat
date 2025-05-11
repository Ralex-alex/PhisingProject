@echo off
echo Starting PhishSentinel Advanced Phishing Detection System...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in PATH.
    echo Please install Python 3.8 or higher and try again.
    echo.
    pause
    exit /b 1
)

REM Check if virtual environment exists, create if not
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to create virtual environment.
        echo Please make sure venv module is available.
        echo.
        pause
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Check if requirements are installed
if not exist venv\Lib\site-packages\transformers (
    echo Installing required packages...
    pip install -r Requirements.txt
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to install required packages.
        echo Please check Requirements.txt and your internet connection.
        echo.
        pause
        exit /b 1
    )
)

REM Initialize the vector database with sample data
echo Initializing vector database...
python initialize_vector_db.py

REM Add enhanced training data to improve detection
echo Adding enhanced training data...
python enhanced_training_data.py

REM Start the application
echo Starting PhishSentinel GUI...
python enhanced_phishing_detector_gui.py

REM Deactivate virtual environment on exit
call venv\Scripts\deactivate.bat

echo.
echo PhishSentinel has been closed.
pause 