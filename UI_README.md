# Phishing Detection User Interfaces

This project provides multiple user interfaces to check emails for phishing attempts:

## 1. Desktop Application

The desktop application provides a simple, user-friendly interface for checking emails.

### How to Use the Desktop App

1. **Start the application**:
   ```
   python phishing_detector_gui.py
   ```

2. **Enter email details**:
   - Type or paste the email subject in the "Subject" field
   - Type or paste the email body in the "Email Body" field

3. **Check the email**:
   - Click the "Check Email" button
   - Wait for the analysis to complete

4. **View the results**:
   - A clear verdict will be displayed: "LEGITIMATE EMAIL" or "PHISHING EMAIL DETECTED"
   - The confidence level of the prediction is shown as a percentage
   - For phishing emails, specific advice is provided

5. **Clear the form**:
   - Click the "Clear" button to reset the form for a new email

## 2. Browser Extension

The browser extension integrates directly with your webmail service (Gmail, Outlook) to check emails as you read them.

### Installing the Browser Extension

1. **Load the extension in Chrome**:
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode" (toggle in the top-right)
   - Click "Load unpacked" and select the `browser_extension` folder

2. **Load the extension in Firefox**:
   - Open Firefox and go to `about:debugging#/runtime/this-firefox`
   - Click "Load Temporary Add-on..."
   - Select any file in the `browser_extension` folder

### Using the Browser Extension

1. **From the toolbar**:
   - Click the extension icon in your browser toolbar
   - Enter the email subject and body
   - Click "Check Email"

2. **From webmail services**:
   - When viewing an email in Gmail or Outlook, a "Check for Phishing" button will appear
   - Click this button to analyze the current email
   - Results will appear as an overlay on the page

## 3. API Server

For developers or advanced users, you can use the API directly.

### Starting the API Server

```
python api_server.py
```

The server will start on http://localhost:8000

### API Endpoints

- **GET /health**: Check if the API is running
- **POST /predict**: Analyze a single email
- **POST /batch-predict**: Analyze multiple emails at once

### Example API Request

```python
import requests
import json

url = "http://localhost:8000/predict"
payload = {
    "subject": "Urgent: Account Verification Required",
    "body": "Dear User, Your account has been suspended. Click here to verify: http://suspicious-link.com",
    "sender": "security@bank-verify.com"
}

response = requests.post(url, json=payload)
print(json.dumps(response.json(), indent=2))
```

## Requirements

- All interfaces require the API server to be running
- The desktop application requires Python with Tkinter installed
- The browser extension requires Chrome or Firefox

## Troubleshooting

- If you see "Error connecting to phishing detection service", make sure the API server is running
- If the model is slow to load, be patient - it's loading a large language model
- If you encounter errors, check the console or terminal for detailed messages 