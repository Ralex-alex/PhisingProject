# Advanced Phishing Detection System

This project implements a state-of-the-art phishing detection pipeline that leverages large language models (LLMs) to complement and enhance traditional spam filtering techniques.

## Features

- **Two-Stage Detection Pipeline**: Combines traditional ML with advanced LLM-based analysis
- **Multiple Feature Extraction**: Utilizes text-based features, URLs, custom indicators, and semantic embeddings
- **Enhanced Accuracy**: Improved detection rates over traditional spam filters
- **REST API**: Simple deployment as a service
- **Expandable Dataset**: Scripts to download and integrate additional public datasets
- **Privacy-Focused**: Can be run on-premises with no external dependencies

## Getting Started

### Prerequisites

- Python 3.8+
- Pip package manager
- At least 4GB RAM (8GB+ recommended for training with larger datasets)
- GPU optional but recommended for faster training and inference

### Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd phishing-detection
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

### Training the Model

```
python combined_pipeline.py
```

This will:
1. Load the dataset
2. Train the baseline models (Naive Bayes, Random Forest)
3. Train the LLM-based classifier
4. Evaluate the performance
5. Save the model to the `models` directory

### Running the API Server

```
python api_server.py
```

This will start a FastAPI server on http://localhost:8000 with the following endpoints:

- `/predict` - Analyze a single email for phishing indicators
- `/batch-predict` - Analyze multiple emails in a single request
- `/feedback` - Submit feedback to improve the model
- `/health` - Check if the API is healthy
- `/docs` - Swagger UI for API documentation

### API Examples

#### Single Email Analysis

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

#### Batch Analysis

```python
import requests
import json

url = "http://localhost:8000/batch-predict"
payload = {
    "emails": [
        {
            "subject": "Urgent: Account Verification Required",
            "body": "Dear User, Your account has been suspended. Click here to verify: http://suspicious-link.com",
            "sender": "security@bank-verify.com"
        },
        {
            "subject": "Meeting notes from yesterday",
            "body": "Hi team, Attached are the notes from yesterday's meeting. Let me know if you have questions.",
            "sender": "colleague@company.com"
        }
    ]
}

response = requests.post(url, json=payload)
print(json.dumps(response.json(), indent=2))
```

## Project Structure

- `combined_pipeline.py` - The main phishing detection pipeline implementation
- `expand_dataset.py` - Scripts to download and integrate additional datasets
- `api_server.py` - FastAPI server for deploying the model as a service
- `models/` - Directory for saved trained models
- `expanded_data/` - Directory for expanded datasets
- `feedback/` - Directory for user feedback on predictions

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

### Adjusting Decision Thresholds

To adjust the sensitivity of the phishing detection, modify the threshold values in the `predict` method of the `PhishingDetectionPipeline` class.

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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 