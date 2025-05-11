# PhishSentinel: Advanced Phishing Detection System

This project implements a state-of-the-art phishing detection pipeline that leverages large language models (LLMs) to complement and enhance traditional spam filtering techniques.

## Features

### Core Detection Capabilities
- **Two-Stage Detection Pipeline**: Combines traditional ML with advanced LLM-based analysis
- **Multiple Feature Extraction**: Utilizes text-based features, URLs, custom indicators, and semantic embeddings
- **Enhanced Accuracy**: Improved detection rates over traditional spam filters
- **REST API**: Simple deployment as a service
- **Expandable Dataset**: Scripts to download and integrate additional public datasets
- **Privacy-Focused**: Can be run on-premises with no external dependencies

### Advanced Analysis Components
- **Sender Analysis**: Email authentication (SPF, DKIM, DMARC), domain age checking, reputation analysis, typosquatting detection
- **URL Analysis**: Domain reputation, redirect chain analysis, URL shortener detection, visual vs. actual URL comparison
- **Image Analysis**: Brand logo detection, OCR on images, URL manipulation detection, visual phishing indicators
- **Behavioral Analysis**: Sending time analysis, geographic origin analysis, communication pattern analysis

### Browser Extension
- **Real-time Email Analysis**: Check emails directly in Gmail and Outlook
- **Visual Risk Indicators**: Clear visual feedback on phishing risk
- **User Feedback Collection**: Report false positives/negatives to improve the system

## Getting Started

### Prerequisites

- Python 3.8+
- Pip package manager
- At least 4GB RAM (8GB+ recommended for training with larger datasets)
- GPU optional but recommended for faster training and inference
- Tesseract OCR (for image text extraction)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/Ralex-alex/PhisingProject.git
   cd PhisingProject
   ```

2. Create and activate a virtual environment:
   ```
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS/Linux
   python -m venv venv
   source venv/bin/activate
   ```

3. Install the required packages:
   ```
   pip install -r Requirements.txt
   ```

4. Install Tesseract OCR:
   - On Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki
   - On macOS: `brew install tesseract`
   - On Linux: `sudo apt install tesseract-ocr`

### Dataset Preparation

The project comes with a script to download and prepare additional datasets:

```
python expand_dataset.py
```

This will:
1. Download and process phishing URLs from PhishTank
2. Download a subset of legitimate emails from the Enron dataset
3. Generate synthetic phishing emails for training
4. Combine with the existing SpamAssassin dataset

All datasets will be saved in the `expanded_data` directory.

## Usage

### Running the System with Batch Files

The project includes several batch files for easy execution:

- **start_phishing_detector.bat**: Launches the basic phishing detection system
- **start_enhanced_detector.bat**: Launches the advanced phishing detection system with all components
- **start_api_server.bat**: Starts the REST API server for integrating with other applications
- **test_all_emails.bat**: Runs the detector against all test emails in the test folder

### Training the Models

```
python combined_pipeline.py
```

This will:
1. Load the dataset
2. Train the baseline models (Naive Bayes, Random Forest)
3. Train the LLM-based classifier
4. Evaluate the performance
5. Save the model to the `models` directory

### Enhanced Phishing Detector

The enhanced detector provides a more comprehensive analysis:

```
python enhanced_phishing_detector.py --file path/to/email.eml
```

Or use the GUI version:

```
python enhanced_phishing_detector_gui.py
```

The enhanced detector includes:
- Multi-factor analysis (sender, URL, content, images)
- Vector database for similarity matching
- Explainable results with highlighted indicators
- Integrated feedback loop

### Running the API Server

```
python api_server.py
```

This will start a FastAPI server on http://localhost:8000 with the following endpoints:

- `/predict` - Analyze a single email for phishing indicators
- `/batch-predict` - Analyze multiple emails in a single request
- `/analyze-sender` - Analyze just the sender information
- `/analyze-url` - Analyze URLs in isolation
- `/analyze-image` - Analyze images for phishing indicators  
- `/feedback` - Submit feedback to improve the model
- `/health` - Check if the API is healthy
- `/docs` - Swagger UI for API documentation

### Browser Extension

The project includes a browser extension for Chrome and Firefox that integrates with webmail services:

1. Navigate to the browser extension directory:
```
cd browser_extension
```

2. Load the extension in Chrome:
- Open Chrome and go to `chrome://extensions/`
- Enable Developer Mode
- Click "Load unpacked" and select the `browser_extension` directory

The extension adds a "Check for Phishing" button in Gmail and Outlook web interfaces to analyze the currently open email.

## Project Structure

- `combined_pipeline.py` - The main phishing detection pipeline implementation
- `enhanced_phishing_detector.py` - Advanced detector with multiple analysis components
- `enhanced_phishing_detector_gui.py` - GUI version of the enhanced detector
- `sender_analysis.py` - Email sender and domain analysis
- `url_analysis.py` - URL and link analysis
- `image_analysis.py` - Image-based phishing detection
- `behavioral_analysis.py` - User behavior and pattern analysis
- `vector_db_integration.py` - Vector similarity database implementation
- `api_server.py` - FastAPI server for deploying the model as a service
- `expand_dataset.py` - Scripts to download and integrate additional datasets
- `browser_extension/` - Chrome/Firefox extension for webmail integration
- `models/` - Directory for saved trained models
- `expanded_data/` - Directory for expanded datasets
- `results/` - Directory for analysis results
- `*.bat` & `*.sh` - Batch and shell scripts for easy execution

## Performance

The system achieves the following performance metrics on the test set:

- **Accuracy**: 98%
- **Precision (Phishing)**: 99%
- **Recall (Phishing)**: 96%
- **F1-Score (Phishing)**: 98%

## Customization

### Using a Different LLM

To use a different LLM, modify the `llm_model_name` parameter when initializing the `PhishingDetectionPipeline` class:

```python
pipeline = PhishingDetectionPipeline(llm_model_name="bert-base-uncased")
```

### Adjusting Detection Parameters

To customize the detection parameters, edit the `phishing_detector_config.json` file:

- Adjust detection thresholds
- Enable/disable specific analysis components
- Configure API settings
- Set feedback collection options

## Ethical Considerations

- The model should be regularly updated with new phishing examples
- Privacy is maintained by running all analysis on-premises
- User feedback should be incorporated to reduce false positives
- Consider the trade-offs between security and user experience

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- SpamAssassin corpus for initial training data
- PhishTank for phishing URL dataset
- Enron Email Dataset for legitimate email examples
- Hugging Face for transformer models
- Tesseract OCR by Google

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 