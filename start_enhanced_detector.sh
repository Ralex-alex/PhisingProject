#!/bin/bash

echo "Starting PhishSentinel Advanced Phishing Detection System..."
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed or not in PATH."
    echo "Please install Python 3.8 or higher and try again."
    echo
    read -p "Press Enter to exit..."
    exit 1
fi

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "Failed to create virtual environment."
        echo "Please make sure venv module is available."
        echo
        read -p "Press Enter to exit..."
        exit 1
    fi
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Check if requirements are installed
if [ ! -d "venv/lib/python3.8/site-packages/transformers" ] && [ ! -d "venv/lib/python3.9/site-packages/transformers" ] && [ ! -d "venv/lib/python3.10/site-packages/transformers" ]; then
    echo "Installing required packages..."
    pip install -r Requirements.txt
    if [ $? -ne 0 ]; then
        echo "Failed to install required packages."
        echo "Please check Requirements.txt and your internet connection."
        echo
        read -p "Press Enter to exit..."
        exit 1
    fi
fi

# Start the application
echo "Starting PhishSentinel GUI..."
python3 enhanced_phishing_detector_gui.py

# Deactivate virtual environment on exit
deactivate

echo
echo "PhishSentinel has been closed."
read -p "Press Enter to exit..." 