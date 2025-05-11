import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from transformers import AutoTokenizer, AutoModel, BertTokenizer, BertModel
import torch
import re
import pickle
import os
import joblib
from urllib.parse import urlparse
from nltk.tokenize import word_tokenize
import nltk
import warnings
from tqdm import tqdm

# Silence non-critical warnings
warnings.filterwarnings('ignore')

# Download ALL required NLTK resources
try:
    print("Downloading required NLTK resources...")
    nltk.download('punkt')
    nltk.download('punkt_tab')
    nltk.download('averaged_perceptron_tagger')
    print("NLTK resources downloaded successfully")
except Exception as e:
    print(f"Warning: Error downloading NLTK resources: {e}")
    print("Proceeding with simple tokenization as fallback")

class PhishingDetectionPipeline:
    """
    A two-stage phishing detection pipeline combining traditional ML techniques
    with LLM embeddings for enhanced detection capabilities.
    """
    
    def __init__(self, llm_model_name="distilbert-base-uncased", batch_size=16, max_length=256):
        """
        Initialize the phishing detection pipeline.
        
        Args:
            llm_model_name (str): Name of the pretrained transformer model
            batch_size (int): Batch size for LLM processing
            max_length (int): Maximum token length for LLM processing
        """
        self.llm_model_name = llm_model_name
        self.batch_size = batch_size
        self.max_length = max_length
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Traditional features
        self.tfidf_vectorizer = TfidfVectorizer(max_features=10000, stop_words='english')
        self.count_vectorizer = CountVectorizer(max_features=10000, stop_words='english')
        
        # Models
        self.nb_model = MultinomialNB()
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.llm_clf = LogisticRegression(C=1.0, max_iter=1000)
        
        # LLM components
        self.tokenizer = None
        self.llm_model = None
        
        # Label mapping
        self.label_map = {'legitimate': 0, 'phishing': 1}
        self.inv_label_map = {0: 'legitimate', 1: 'phishing'}
        
        # Model performance metrics
        self.metrics = {}
    
    def extract_features(self, texts):
        """
        Extract handcrafted features that are useful for phishing detection.
        
        Args:
            texts (list): List of email texts
            
        Returns:
            np.array: Array of extracted features
        """
        features = []
        
        for text in texts:
            # Feature 1: Count of URLs
            url_count = len(re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text))
            
            # Feature 2: Count of suspicious words
            suspicious_words = ['urgent', 'verify', 'account', 'login', 'password', 
                               'click', 'confirm', 'update', 'suspend', 'bank',
                               'security', 'alert', 'immediately', 'restricted']
            
            # Use simple string operations as fallback if NLTK fails
            try:
                tokens = word_tokenize(text.lower())
            except:
                # Fallback to simple tokenization if NLTK fails
                tokens = text.lower().split()
                
            suspicious_word_count = sum(1 for word in tokens if word.lower() in suspicious_words)
            
            # Feature 3: Contains 'Re:' or 'Fwd:' in subject
            has_re_fwd = 1 if re.search(r'^(Subject: Re:|Subject: Fwd:)', text, re.IGNORECASE) else 0
            
            # Feature 4: Text length
            text_length = len(text)
            
            # Feature 5: Count of exclamation marks
            exclamation_count = text.count('!')
            
            # Feature 6: Count of dollar signs
            dollar_sign_count = text.count('$')
            
            # Feature 7: Presence of IP address instead of domain in URLs
            ip_in_url = 1 if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text) else 0
            
            # Feature 8: Link text vs URL mismatch indicators
            link_text_mismatch = 1 if re.search(r'\[.*\]\(https?://.*\)', text) else 0
            
            # Combine all features
            features.append([
                url_count, suspicious_word_count, has_re_fwd, text_length, 
                exclamation_count, dollar_sign_count, ip_in_url, link_text_mismatch
            ])
        
        return np.array(features)
    
    def initialize_llm(self):
        """Initialize the LLM model and tokenizer."""
        try:
            print(f"Initializing LLM model: {self.llm_model_name}")
            self.tokenizer = AutoTokenizer.from_pretrained(self.llm_model_name)
            self.llm_model = AutoModel.from_pretrained(self.llm_model_name)
            self.llm_model.to(self.device)
            print(f"LLM initialized successfully on {self.device}")
        except Exception as e:
            print(f"Error initializing LLM: {e}")
            # Fallback to a simpler model if the requested one fails
            print("Falling back to default BERT model...")
            self.llm_model_name = "bert-base-uncased"
            self.tokenizer = BertTokenizer.from_pretrained(self.llm_model_name)
            self.llm_model = BertModel.from_pretrained(self.llm_model_name)
            self.llm_model.to(self.device)
    
    def get_embeddings(self, texts):
        """
        Get embeddings for the input texts using the LLM model.
        
        Args:
            texts (list): List of text strings
            
        Returns:
            np.array: Array of embeddings
        """
        if self.tokenizer is None or self.llm_model is None:
            self.initialize_llm()
        
        all_embeddings = []
        
        # Process in batches to avoid memory issues
        for i in tqdm(range(0, len(texts), self.batch_size), desc="Getting embeddings"):
            batch_texts = texts[i:i+self.batch_size]
            
            # Tokenize and prepare for the model
            inputs = self.tokenizer(
                batch_texts, 
                return_tensors='pt', 
                padding=True, 
                truncation=True, 
                max_length=self.max_length
            ).to(self.device)
            
            # Get embeddings
            with torch.no_grad():
                outputs = self.llm_model(**inputs)
                # Mean pooling - take average of all token embeddings
                embeddings = outputs.last_hidden_state.mean(dim=1).cpu().numpy()
            
            all_embeddings.append(embeddings)
        
        # Combine all batches
        return np.vstack(all_embeddings)
    
    def prepare_data(self, data_path, test_size=0.2):
        """
        Prepare data for training and testing.
        
        Args:
            data_path (str): Path to the dataset
            test_size (float): Proportion of data to use for testing
            
        Returns:
            dict: Dictionary containing train and test data
        """
        print(f"Loading data from {data_path}")
        data = pd.read_csv(data_path)
        texts = data['text'].tolist()
        
        # Convert string labels to numeric
        if 'label' in data.columns:
            if data['label'].dtype == object:  # String labels
                labels = [self.label_map.get(l, 0) for l in data['label']]
            else:  # Already numeric
                labels = data['label'].tolist()
        else:
            raise ValueError("Data must contain a 'label' column")
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=test_size, random_state=42, stratify=labels
        )
        
        print(f"Data split: Train={len(X_train)}, Test={len(X_test)}")
        
        return {
            'X_train': X_train,
            'X_test': X_test,
            'y_train': y_train,
            'y_test': y_test
        }
    
    def train(self, data_dict):
        """
        Train all models in the pipeline.
        
        Args:
            data_dict (dict): Dictionary containing train and test data
            
        Returns:
            self: The trained pipeline instance
        """
        X_train, y_train = data_dict['X_train'], data_dict['y_train']
        
        print("Training traditional models...")
        
        # 1. TF-IDF features for Naive Bayes
        print("Extracting TF-IDF features...")
        X_train_tfidf = self.tfidf_vectorizer.fit_transform(X_train)
        
        # 2. Count Vector features for Random Forest
        print("Extracting Count Vector features...")
        X_train_counts = self.count_vectorizer.fit_transform(X_train)
        
        # 3. Custom features
        print("Extracting custom features...")
        X_train_custom = self.extract_features(X_train)
        
        # 4. LLM Embeddings for Logistic Regression
        print("Getting LLM embeddings...")
        X_train_emb = self.get_embeddings(X_train)
        
        # Train Naive Bayes on TF-IDF
        print("Training Naive Bayes...")
        self.nb_model.fit(X_train_tfidf, y_train)
        
        # Train Random Forest on Count Vectors
        print("Training Random Forest...")
        self.rf_model.fit(X_train_counts, y_train)
        
        # Train Logistic Regression on LLM embeddings
        print("Training Logistic Regression on LLM embeddings...")
        self.llm_clf.fit(X_train_emb, y_train)
        
        print("All models trained successfully")
        return self
    
    def predict(self, texts):
        """
        Predict labels for the given texts using the two-stage pipeline.
        
        Args:
            texts (list): List of text strings
            
        Returns:
            list: Predicted labels (0 for legitimate, 1 for phishing)
        """
        # Transform texts with all feature extractors
        X_tfidf = self.tfidf_vectorizer.transform(texts)
        X_counts = self.count_vectorizer.transform(texts)
        X_custom = self.extract_features(texts)
        X_emb = self.get_embeddings(texts)
        
        # Get predictions from all models
        nb_probs = self.nb_model.predict_proba(X_tfidf)
        rf_probs = self.rf_model.predict_proba(X_counts)
        llm_preds = self.llm_clf.predict(X_emb)
        
        # Two-stage decision process
        final_predictions = []
        
        for i, (nb_prob, rf_prob) in enumerate(zip(nb_probs, rf_probs)):
            # Extract phishing probabilities
            nb_phish_prob = nb_prob[1]
            rf_phish_prob = rf_prob[1]
            
            # Stage 1: High confidence traditional model predictions
            if nb_phish_prob > 0.9 and rf_phish_prob > 0.7:
                final_predictions.append(1)  # Confident phishing
            elif nb_phish_prob < 0.1 and rf_phish_prob < 0.3:
                final_predictions.append(0)  # Confident legitimate
            else:
                # Stage 2: Use LLM for borderline cases
                final_predictions.append(llm_preds[i])
        
        return final_predictions
    
    def evaluate(self, data_dict):
        """
        Evaluate the pipeline on test data.
        
        Args:
            data_dict (dict): Dictionary containing train and test data
            
        Returns:
            dict: Evaluation metrics
        """
        X_test, y_test = data_dict['X_test'], data_dict['y_test']
        
        # Get predictions
        y_pred = self.predict(X_test)
        
        # Calculate metrics
        report = classification_report(y_test, y_pred, 
                                       target_names=["legitimate", "phishing"],
                                       output_dict=True)
        
        confusion = confusion_matrix(y_test, y_pred)
        
        # Convert test predictions to probability estimates for ROC AUC
        X_test_tfidf = self.tfidf_vectorizer.transform(X_test)
        nb_probs = self.nb_model.predict_proba(X_test_tfidf)[:, 1]
        
        X_test_emb = self.get_embeddings(X_test)
        llm_probs = self.llm_clf.predict_proba(X_test_emb)[:, 1]
        
        # Calculate ROC AUC for different models
        nb_auc = roc_auc_score(y_test, nb_probs)
        llm_auc = roc_auc_score(y_test, llm_probs)
        combined_auc = roc_auc_score(y_test, y_pred)
        
        # Store all metrics
        self.metrics = {
            'classification_report': report,
            'confusion_matrix': confusion,
            'roc_auc': {
                'naive_bayes': nb_auc,
                'llm': llm_auc,
                'combined': combined_auc
            }
        }
        
        # Print performance summary
        print("Phishing Detection Pipeline Evaluation")
        print("-"*50)
        print(f"Accuracy: {report['accuracy']:.4f}")
        print(f"Phishing Precision: {report['phishing']['precision']:.4f}")
        print(f"Phishing Recall: {report['phishing']['recall']:.4f}")
        print(f"Phishing F1-Score: {report['phishing']['f1-score']:.4f}")
        print(f"Legitimate Precision: {report['legitimate']['precision']:.4f}")
        print(f"Legitimate Recall: {report['legitimate']['recall']:.4f}")
        print(f"Legitimate F1-Score: {report['legitimate']['f1-score']:.4f}")
        print("-"*50)
        print(f"ROC AUC (Naive Bayes): {nb_auc:.4f}")
        print(f"ROC AUC (LLM): {llm_auc:.4f}")
        print(f"ROC AUC (Combined): {combined_auc:.4f}")
        print("-"*50)
        print("Confusion Matrix:")
        print(confusion)
        
        return self.metrics
    
    def save(self, directory='models'):
        """
        Save all components of the pipeline to disk.
        
        Args:
            directory (str): Directory to save models
        """
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        # Save models
        joblib.dump(self.nb_model, os.path.join(directory, 'nb_model.pkl'))
        joblib.dump(self.rf_model, os.path.join(directory, 'rf_model.pkl'))
        joblib.dump(self.llm_clf, os.path.join(directory, 'llm_clf.pkl'))
        
        # Save vectorizers
        joblib.dump(self.tfidf_vectorizer, os.path.join(directory, 'tfidf_vectorizer.pkl'))
        joblib.dump(self.count_vectorizer, os.path.join(directory, 'count_vectorizer.pkl'))
        
        # Save metrics
        with open(os.path.join(directory, 'metrics.json'), 'w') as f:
            import json
            # Convert numpy arrays to lists for JSON serialization
            metrics_json = self.metrics.copy()
            if 'confusion_matrix' in metrics_json:
                metrics_json['confusion_matrix'] = metrics_json['confusion_matrix'].tolist()
            json.dump(metrics_json, f, indent=4)
        
        print(f"Model pipeline saved to {directory}")
    
    def load(self, directory='models'):
        """
        Load all components of the pipeline from disk.
        
        Args:
            directory (str): Directory to load models from
            
        Returns:
            self: The loaded pipeline instance
        """
        self.nb_model = joblib.load(os.path.join(directory, 'nb_model.pkl'))
        self.rf_model = joblib.load(os.path.join(directory, 'rf_model.pkl'))
        self.llm_clf = joblib.load(os.path.join(directory, 'llm_clf.pkl'))
        
        self.tfidf_vectorizer = joblib.load(os.path.join(directory, 'tfidf_vectorizer.pkl'))
        self.count_vectorizer = joblib.load(os.path.join(directory, 'count_vectorizer.pkl'))
        
        print(f"Model pipeline loaded from {directory}")
        return self


if __name__ == "__main__":
    # Create the pipeline
    pipeline = PhishingDetectionPipeline()
    
    # Load and prepare data
    data_dict = pipeline.prepare_data("emails_from_spamassassin.csv", test_size=0.3)
    
    # Train the pipeline
    pipeline.train(data_dict)
    
    # Evaluate the pipeline
    metrics = pipeline.evaluate(data_dict)
    
    # Save the pipeline
    pipeline.save()
