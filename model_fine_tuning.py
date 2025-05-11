import os
import sys
import json
import logging
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from transformers import (
    AutoTokenizer, 
    AutoModelForSequenceClassification,
    TrainingArguments, 
    Trainer,
    DataCollatorWithPadding
)
import torch
from datasets import Dataset
from typing import Dict, Any, List, Optional
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("model_fine_tuning.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("model_fine_tuning")

class ModelFineTuner:
    """
    Fine-tune transformer models for phishing detection using
    diverse training data.
    """
    
    def __init__(self, 
                 base_model: str = "microsoft/deberta-v3-base",
                 output_dir: str = "models/fine_tuned_phishing",
                 config_path: str = "phishing_detector_config.json"):
        """
        Initialize the model fine-tuner.
        
        Args:
            base_model (str): Base model to fine-tune
            output_dir (str): Directory to save the fine-tuned model
            config_path (str): Path to configuration file
        """
        self.base_model = base_model
        self.output_dir = output_dir
        self.config = self._load_config(config_path)
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize tokenizer and model
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(base_model)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                base_model, 
                num_labels=2
            )
            logger.info(f"Loaded base model: {base_model}")
        except Exception as e:
            logger.error(f"Error loading base model: {e}")
            self.tokenizer = None
            self.model = None
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from JSON file.
        
        Args:
            config_path (str): Path to configuration file
            
        Returns:
            dict: Configuration dictionary
        """
        default_config = {
            "model_settings": {
                "batch_size": 16,
                "learning_rate": 2e-5,
                "epochs": 3,
                "max_length": 512,
                "weight_decay": 0.01
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {config_path}")
                return config
            else:
                logger.warning(f"Configuration file not found: {config_path}")
                return default_config
                
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return default_config
    
    def preprocess_data(self, df: pd.DataFrame) -> Dataset:
        """
        Preprocess data for fine-tuning.
        
        Args:
            df (pd.DataFrame): DataFrame containing email data
            
        Returns:
            Dataset: HuggingFace dataset
        """
        # Combine subject and body for text classification
        texts = []
        labels = []
        
        for _, row in df.iterrows():
            subject = row.get('subject', '')
            body = row.get('body', '')
            
            # Combine subject and body
            if subject and body:
                text = f"Subject: {subject}\n\n{body}"
            elif subject:
                text = subject
            else:
                text = body
            
            texts.append(text)
            labels.append(int(row['is_phishing']))
        
        # Create dataset dictionary
        dataset_dict = {
            'text': texts,
            'label': labels
        }
        
        # Convert to HuggingFace Dataset
        dataset = Dataset.from_dict(dataset_dict)
        
        # Tokenize the dataset
        def tokenize_function(examples):
            return self.tokenizer(
                examples['text'],
                padding='max_length',
                truncation=True,
                max_length=self.config.get('model_settings', {}).get('max_length', 512)
            )
        
        tokenized_dataset = dataset.map(tokenize_function, batched=True)
        
        return tokenized_dataset
    
    def fine_tune(self, train_data_path: str, val_data_path: Optional[str] = None):
        """
        Fine-tune the model on the provided dataset.
        
        Args:
            train_data_path (str): Path to training data CSV
            val_data_path (str): Path to validation data CSV
            
        Returns:
            bool: Success or failure
        """
        if not self.tokenizer or not self.model:
            logger.error("Model or tokenizer not initialized")
            return False
        
        try:
            # Load training data
            train_df = pd.read_csv(train_data_path)
            logger.info(f"Loaded training data: {len(train_df)} samples")
            
            # Load or create validation data
            if val_data_path and os.path.exists(val_data_path):
                val_df = pd.read_csv(val_data_path)
                logger.info(f"Loaded validation data: {len(val_df)} samples")
            else:
                # Split training data for validation
                train_df, val_df = train_test_split(train_df, test_size=0.1, stratify=train_df['is_phishing'], random_state=42)
                logger.info(f"Split training data: {len(train_df)} train, {len(val_df)} validation samples")
            
            # Preprocess data
            train_dataset = self.preprocess_data(train_df)
            val_dataset = self.preprocess_data(val_df)
            
            # Get training arguments
            model_settings = self.config.get('model_settings', {})
            training_args = TrainingArguments(
                output_dir=self.output_dir,
                learning_rate=model_settings.get('learning_rate', 2e-5),
                per_device_train_batch_size=model_settings.get('batch_size', 16),
                per_device_eval_batch_size=model_settings.get('batch_size', 16),
                num_train_epochs=model_settings.get('epochs', 3),
                weight_decay=model_settings.get('weight_decay', 0.01),
                evaluation_strategy="epoch",
                save_strategy="epoch",
                load_best_model_at_end=True,
                metric_for_best_model="accuracy",
                push_to_hub=False,
                report_to="none"
            )
            
            # Create data collator
            data_collator = DataCollatorWithPadding(tokenizer=self.tokenizer)
            
            # Define compute metrics function
            def compute_metrics(eval_pred):
                logits, labels = eval_pred
                predictions = np.argmax(logits, axis=-1)
                
                # Calculate accuracy
                accuracy = np.mean(predictions == labels)
                
                # Calculate precision, recall, and F1 for phishing class (class 1)
                tp = np.sum((predictions == 1) & (labels == 1))
                fp = np.sum((predictions == 1) & (labels == 0))
                fn = np.sum((predictions == 0) & (labels == 1))
                
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
                
                return {
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1': f1
                }
            
            # Create trainer
            trainer = Trainer(
                model=self.model,
                args=training_args,
                train_dataset=train_dataset,
                eval_dataset=val_dataset,
                tokenizer=self.tokenizer,
                data_collator=data_collator,
                compute_metrics=compute_metrics
            )
            
            # Fine-tune the model
            logger.info("Starting fine-tuning...")
            trainer.train()
            
            # Evaluate the model
            eval_results = trainer.evaluate()
            logger.info(f"Evaluation results: {eval_results}")
            
            # Save the model
            trainer.save_model(self.output_dir)
            self.tokenizer.save_pretrained(self.output_dir)
            
            # Save evaluation results
            with open(os.path.join(self.output_dir, "eval_results.json"), "w") as f:
                json.dump(eval_results, f, indent=4)
            
            logger.info(f"Model fine-tuning complete. Model saved to {self.output_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Error during fine-tuning: {e}")
            return False
    
    def update_config_with_new_model(self):
        """
        Update the configuration file with the new fine-tuned model.
        
        Returns:
            bool: Success or failure
        """
        try:
            config_path = "phishing_detector_config.json"
            
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                # Update model settings
                if 'model_settings' not in config:
                    config['model_settings'] = {}
                
                config['model_settings']['llm_model'] = self.output_dir
                
                # Update LLM analysis settings
                if 'llm_analysis' not in config:
                    config['llm_analysis'] = {}
                
                config['llm_analysis']['model_name'] = self.output_dir
                
                # Save updated config
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=4)
                
                logger.info(f"Updated configuration with new model: {self.output_dir}")
                return True
            else:
                logger.error(f"Configuration file not found: {config_path}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating configuration: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Fine-tune a model for phishing detection')
    parser.add_argument('--base-model', type=str, default="microsoft/deberta-v3-base",
                        help='Base model to fine-tune')
    parser.add_argument('--train-data', type=str, required=True,
                        help='Path to training data CSV')
    parser.add_argument('--val-data', type=str, default=None,
                        help='Path to validation data CSV')
    parser.add_argument('--output-dir', type=str, default="models/fine_tuned_phishing",
                        help='Directory to save the fine-tuned model')
    parser.add_argument('--update-config', action='store_true',
                        help='Update the configuration file with the new model')
    
    args = parser.parse_args()
    
    # Initialize fine-tuner
    fine_tuner = ModelFineTuner(
        base_model=args.base_model,
        output_dir=args.output_dir
    )
    
    # Fine-tune the model
    success = fine_tuner.fine_tune(
        train_data_path=args.train_data,
        val_data_path=args.val_data
    )
    
    if success and args.update_config:
        fine_tuner.update_config_with_new_model()

if __name__ == "__main__":
    main() 