# Advanced Phishing Detection System

A comprehensive phishing detection system that combines traditional ML techniques with advanced LLM capabilities, multimodal analysis, and vector similarity search to identify sophisticated phishing attempts.

## Features

### Core Detection Capabilities
- **Machine Learning Classification**: Traditional ML models for baseline phishing detection
- **LLM-Enhanced Analysis**: Advanced language model integration for nuanced content analysis
- **Vector Similarity Search**: Find emails similar to known phishing attempts using FAISS
- **Real-time Feedback Loop**: User feedback improves detection over time

### Sender Analysis
- **Email Authentication**: SPF, DKIM, and DMARC verification
- **Domain Age Checking**: Detection of newly registered domains
- **Reputation Checking**: Domain reputation analysis
- **Typosquatting Detection**: Identify domains impersonating legitimate brands
- **Sender-Recipient Relationship History**: Analyze previous communication patterns

### URL Analysis
- **Domain Reputation**: Check URLs against reputation databases
- **Redirect Chain Analysis**: Follow URL redirects to identify cloaking
- **URL Shortener Detection**: Identify and expand shortened URLs
- **Visual vs Actual URL Comparison**: Detect misleading link text

### Image Analysis
- **Brand Logo Detection**: Identify legitimate and spoofed logos in images
- **OCR on Images**: Extract text from images to find hidden phishing content
- **URL Manipulation Detection**: Find URLs embedded in images
- **Visual Phishing Indicators**: Detect common visual phishing patterns

### Behavioral Analysis
- **Sending Time Analysis**: Flag emails sent at unusual hours
- **Geographic Origin Analysis**: Identify suspicious sending locations
- **Communication Pattern Analysis**: Detect deviations from normal patterns

### Browser Extension
- **Real-time Email Analysis**: Check emails directly in Gmail and Outlook
- **Visual Risk Indicators**: Clear visual feedback on phishing risk
- **User Feedback Collection**: Report false positives/negatives to improve the system

### API Server
- **RESTful API**: Integrate phishing detection into any application
- **Batch Processing**: Analyze multiple emails in one request
- **Component-Specific Endpoints**: Analyze just sender, URLs, or images

## System Architecture

```
┌─────────────────────┐     ┌──────────────────────┐
│                     │     │                      │
│  Browser Extension  │────▶│      API Server      │
│                     │     │                      │
└─────────────────────┘     └──────────┬───────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────┐
│                                                         │
│              Enhanced Phishing Detector                 │
│                                                         │
├─────────────┬─────────────┬─────────────┬──────────────┤
│             │             │             │              │
│   Sender    │    URL      │   Image     │  Behavioral  │
│  Analysis   │  Analysis   │  Analysis   │   Analysis   │
│             │             │             │              │
└─────────────┴─────────────┴─────────────┴──────────────┘
                                       │
                                       ▼
┌─────────────────────┐     ┌──────────────────────┐
│                     │     │                      │
│   Vector Database   │◀───▶│    LLM Analysis      │
│                     │     │                      │
└─────────────────────┘     └──────────────────────┘
```

## Installation

### Prerequisites
- Python 3.8+
- Node.js 14+ (for browser extension)
- FAISS library dependencies
- Tesseract OCR (for image text extraction)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/phishing-detection.git
cd phishing-detection
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r Requirements.txt
```

4. Install Tesseract OCR:
- On Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki
- On macOS: `brew install tesseract`
- On Linux: `sudo apt install tesseract-ocr`

5. Configure the system:
- Edit `phishing_detector_config.json` to customize settings

### Browser Extension Setup

1. Navigate to the browser extension directory:
```bash
cd browser_extension
```

2. Load the extension in Chrome:
- Open Chrome and go to `chrome://extensions/`
- Enable Developer Mode
- Click "Load unpacked" and select the `browser_extension` directory

## Usage

### Command Line Interface

Analyze a single email file:
```bash
python enhanced_phishing_detector.py --file path/to/email.eml
```

Train the vector database with a dataset:
```bash
python enhanced_phishing_detector.py --train-vector-db path/to/dataset.csv --content-column email_content --label-column is_phishing
```

### API Server

Start the API server:
```bash
python api_server.py
```

The API will be available at `http://localhost:8000` with the following endpoints:
- `/predict` - Analyze a single email
- `/batch-predict` - Analyze multiple emails
- `/analyze-sender` - Analyze just the sender
- `/analyze-image` - Analyze an image for phishing indicators
- `/find-similar` - Find similar known phishing emails
- `/feedback` - Submit feedback on detection results

### Browser Extension

Once installed, the extension will add a "Check for Phishing" button in Gmail and Outlook web interfaces. Click this button to analyze the currently open email.

## Development

### Adding New Features

The system is designed to be modular and extensible:

1. Create a new analysis component in a separate Python file
2. Implement the required interface methods
3. Import and integrate the component in `enhanced_phishing_detector.py`
4. Update the configuration in `phishing_detector_config.json`

### Training Custom Models

To train a custom model for the vector database:
```bash
python -c "from vector_db_integration import PhishingVectorDB; db = PhishingVectorDB(); db.import_from_csv('your_dataset.csv', 'content_column', 'label_column')"
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- FAISS library by Facebook Research
- Sentence Transformers by UKPLab
- Tesseract OCR by Google
- OpenAI for LLM capabilities 