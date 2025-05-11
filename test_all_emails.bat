@echo off
echo PhishSentinel Test Suite
echo ======================
echo.

REM Create results directory if it doesn't exist
if not exist results mkdir results

REM Activate virtual environment
call venv\Scripts\activate.bat

echo Testing Phishing Example 1...
echo ----------------------------
python enhanced_phishing_detector.py --file phishing_example1.eml > results\phishing_example1_results.txt
type results\phishing_example1_results.txt
echo.
echo Results saved to results\phishing_example1_results.txt
echo.
echo.

echo Testing Phishing Example 2...
echo ----------------------------
python enhanced_phishing_detector.py --file phishing_example2.eml > results\phishing_example2_results.txt
type results\phishing_example2_results.txt
echo.
echo Results saved to results\phishing_example2_results.txt
echo.
echo.

echo Testing Legitimate Example 1...
echo -----------------------------
python enhanced_phishing_detector.py --file legitimate_example1.eml > results\legitimate_example1_results.txt
type results\legitimate_example1_results.txt
echo.
echo Results saved to results\legitimate_example1_results.txt
echo.
echo.

echo Testing Legitimate Example 2...
echo -----------------------------
python enhanced_phishing_detector.py --file legitimate_example2.eml > results\legitimate_example2_results.txt
type results\legitimate_example2_results.txt
echo.
echo Results saved to results\legitimate_example2_results.txt
echo.
echo.

echo Summary of Results:
echo ------------------
echo Phishing Example 1: 
findstr "Phishing detection result:" results\phishing_example1_results.txt
findstr "Confidence:" results\phishing_example1_results.txt
echo.
echo Phishing Example 2: 
findstr "Phishing detection result:" results\phishing_example2_results.txt
findstr "Confidence:" results\phishing_example2_results.txt
echo.
echo Legitimate Example 1: 
findstr "Phishing detection result:" results\legitimate_example1_results.txt
findstr "Confidence:" results\legitimate_example1_results.txt
echo.
echo Legitimate Example 2: 
findstr "Phishing detection result:" results\legitimate_example2_results.txt
findstr "Confidence:" results\legitimate_example2_results.txt
echo.

REM Deactivate virtual environment
call venv\Scripts\deactivate.bat

echo Testing complete.
pause 