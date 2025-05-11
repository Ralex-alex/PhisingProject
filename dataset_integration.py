import os
import sys
import requests
import pandas as pd
import numpy as np
import zipfile
import tarfile
import logging
import re
import email
from email import policy
from email.parser import BytesParser
from tqdm import tqdm
from bs4 import BeautifulSoup
import urllib.request
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dataset_integration.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("dataset_integration")

class DatasetIntegrator:
    """
    Class to download, process and integrate multiple phishing email datasets
    into a unified format for training our phishing detection model.
    """
    
    def __init__(self, output_dir="datasets"):
        """
        Initialize the DatasetIntegrator.
        
        Args:
            output_dir (str): Directory to store downloaded and processed datasets
        """
        self.output_dir = output_dir
        self.datasets_dir = os.path.join(output_dir, "raw")
        self.processed_dir = os.path.join(output_dir, "processed")
        self.combined_dir = os.path.join(output_dir, "combined")
        
        # Create necessary directories
        os.makedirs(self.datasets_dir, exist_ok=True)
        os.makedirs(self.processed_dir, exist_ok=True)
        os.makedirs(self.combined_dir, exist_ok=True)
        
        # Dataset sources
        self.dataset_sources = {
            "monkey_org_phishing": {
                "url": "https://monkey.org/~jose/phishing/",
                "type": "mbox_collection",
                "is_phishing": True
            },
            "huggingface_phishing": {
                "url": "https://huggingface.co/datasets/ealvaradob/phishing-dataset",
                "type": "huggingface",
                "is_phishing": True
            },
            "enron_legitimate": {
                "url": "https://github.com/GilbertGuo/PhishingEmailDataset/raw/main/enron_benign.zip",
                "type": "zip",
                "is_phishing": False
            },
            "maximilian_phishing": {
                "url": "https://github.com/MaximilianMcDonough/Phishing-Emails/raw/main/Phishing_Legitimate_Training.csv",
                "type": "csv",
                "is_phishing": True
            }
        }
    
    def download_dataset(self, dataset_name):
        """
        Download a dataset from the specified source.
        
        Args:
            dataset_name (str): Name of the dataset to download
            
        Returns:
            bool: Success or failure
        """
        if dataset_name not in self.dataset_sources:
            logger.error(f"Dataset {dataset_name} not found in sources")
            return False
        
        dataset_info = self.dataset_sources[dataset_name]
        url = dataset_info["url"]
        dataset_type = dataset_info["type"]
        
        output_path = os.path.join(self.datasets_dir, f"{dataset_name}")
        os.makedirs(output_path, exist_ok=True)
        
        try:
            logger.info(f"Downloading {dataset_name} from {url}")
            
            if dataset_type == "mbox_collection":
                # For monkey.org phishing collection
                self._download_monkey_org_phishing(url, output_path)
            elif dataset_type == "huggingface":
                # For Hugging Face datasets
                self._download_huggingface_dataset(url, output_path)
            elif dataset_type == "zip":
                # For ZIP files
                zip_path = os.path.join(output_path, f"{dataset_name}.zip")
                urllib.request.urlretrieve(url, zip_path)
                
                # Extract the ZIP file
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(output_path)
                
                logger.info(f"Extracted {dataset_name} to {output_path}")
            elif dataset_type == "csv":
                # For CSV files
                csv_path = os.path.join(output_path, f"{dataset_name}.csv")
                urllib.request.urlretrieve(url, csv_path)
                logger.info(f"Downloaded {dataset_name} to {csv_path}")
            else:
                logger.error(f"Unsupported dataset type: {dataset_type}")
                return False
                
            logger.info(f"Successfully downloaded {dataset_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error downloading {dataset_name}: {e}")
            return False
    
    def _download_monkey_org_phishing(self, base_url, output_path):
        """
        Download phishing emails from monkey.org collection.
        
        Args:
            base_url (str): Base URL for the collection
            output_path (str): Path to save the downloaded files
        """
        # Get the index page
        response = requests.get(base_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all mbox files
        mbox_files = []
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and (href.endswith('.mbox') or 'phishing' in href and not href.startswith('?')):
                mbox_files.append(href)
        
        # Download each mbox file
        for mbox_file in mbox_files:
            file_url = base_url + mbox_file
            file_path = os.path.join(output_path, mbox_file)
            
            try:
                logger.info(f"Downloading {file_url}")
                urllib.request.urlretrieve(file_url, file_path)
                logger.info(f"Downloaded {mbox_file}")
            except Exception as e:
                logger.error(f"Error downloading {file_url}: {e}")
    
    def _download_huggingface_dataset(self, dataset_url, output_path):
        """
        Download dataset from Hugging Face.
        
        Args:
            dataset_url (str): URL of the Hugging Face dataset
            output_path (str): Path to save the downloaded files
        """
        try:
            from datasets import load_dataset
            
            # Extract dataset name from URL
            dataset_name = dataset_url.split('/')[-1]
            
            # Load dataset
            logger.info(f"Loading dataset {dataset_name} from Hugging Face")
            dataset = load_dataset(f"ealvaradob/{dataset_name}", "combined_reduced", trust_remote_code=True)
            
            # Save to CSV
            csv_path = os.path.join(output_path, f"{dataset_name}.csv")
            dataset['train'].to_csv(csv_path, index=False)
            logger.info(f"Saved dataset to {csv_path}")
            
        except Exception as e:
            logger.error(f"Error downloading from Hugging Face: {e}")
            logger.info("Trying alternative method...")
            
            # If Hugging Face API fails, try to download directly
            csv_path = os.path.join(output_path, f"{dataset_name}.csv")
            direct_url = f"{dataset_url}/raw/main/data/combined_reduced.csv"
            
            try:
                urllib.request.urlretrieve(direct_url, csv_path)
                logger.info(f"Downloaded dataset to {csv_path}")
            except Exception as e2:
                logger.error(f"Error with alternative download method: {e2}")
    
    def process_dataset(self, dataset_name):
        """
        Process a downloaded dataset into a standardized format.
        
        Args:
            dataset_name (str): Name of the dataset to process
            
        Returns:
            bool: Success or failure
        """
        if dataset_name not in self.dataset_sources:
            logger.error(f"Dataset {dataset_name} not found in sources")
            return False
        
        dataset_info = self.dataset_sources[dataset_name]
        dataset_type = dataset_info["type"]
        is_phishing = dataset_info["is_phishing"]
        
        input_path = os.path.join(self.datasets_dir, dataset_name)
        output_path = os.path.join(self.processed_dir, f"{dataset_name}.csv")
        
        try:
            logger.info(f"Processing {dataset_name}")
            
            if dataset_type == "mbox_collection":
                self._process_mbox_collection(input_path, output_path, is_phishing)
            elif dataset_type == "huggingface":
                self._process_huggingface_dataset(input_path, output_path, is_phishing)
            elif dataset_type == "zip":
                self._process_zip_dataset(input_path, output_path, is_phishing)
            elif dataset_type == "csv":
                self._process_csv_dataset(input_path, output_path, is_phishing)
            else:
                logger.error(f"Unsupported dataset type: {dataset_type}")
                return False
            
            logger.info(f"Successfully processed {dataset_name} to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error processing {dataset_name}: {e}")
            return False
    
    def _process_mbox_collection(self, input_path, output_path, is_phishing):
        """
        Process a collection of mbox files.
        
        Args:
            input_path (str): Path to the mbox files
            output_path (str): Path to save the processed CSV
            is_phishing (bool): Whether the emails are phishing or not
        """
        emails_data = []
        
        # Process each mbox file
        for file_name in os.listdir(input_path):
            if file_name.endswith('.mbox') or 'phishing' in file_name:
                file_path = os.path.join(input_path, file_name)
                
                try:
                    # Read the mbox file
                    with open(file_path, 'rb') as f:
                        mbox_content = f.read()
                    
                    # Split the mbox file into individual emails
                    email_separator = b'\nFrom '
                    email_parts = mbox_content.split(email_separator)
                    
                    # Process each email
                    for i, email_part in enumerate(email_parts):
                        if i == 0 and not email_part.startswith(b'From '):
                            email_part = b'From ' + email_part
                        
                        try:
                            # Parse the email
                            msg = BytesParser(policy=policy.default).parsebytes(email_part)
                            
                            # Extract email fields
                            subject = msg.get('Subject', '')
                            sender = msg.get('From', '')
                            recipient = msg.get('To', '')
                            date = msg.get('Date', '')
                            
                            # Extract email body
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    content_type = part.get_content_type()
                                    if content_type == "text/plain" or content_type == "text/html":
                                        try:
                                            part_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                            body += part_body + "\n"
                                        except:
                                            pass
                            else:
                                try:
                                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                                except:
                                    body = msg.get_payload(decode=False)
                            
                            # Clean the body text
                            if isinstance(body, str):
                                # Remove HTML tags
                                body = re.sub(r'<[^>]+>', ' ', body)
                                # Remove extra whitespace
                                body = re.sub(r'\s+', ' ', body).strip()
                            
                            # Add to emails data
                            emails_data.append({
                                'subject': subject,
                                'sender': sender,
                                'recipient': recipient,
                                'date': date,
                                'body': body,
                                'is_phishing': 1 if is_phishing else 0
                            })
                            
                        except Exception as e:
                            logger.warning(f"Error processing email in {file_name}: {e}")
                    
                except Exception as e:
                    logger.error(f"Error reading mbox file {file_path}: {e}")
        
        # Save to CSV
        df = pd.DataFrame(emails_data)
        df.to_csv(output_path, index=False)
        logger.info(f"Saved {len(emails_data)} emails to {output_path}")
    
    def _process_huggingface_dataset(self, input_path, output_path, is_phishing):
        """
        Process a Hugging Face dataset.
        
        Args:
            input_path (str): Path to the downloaded dataset
            output_path (str): Path to save the processed CSV
            is_phishing (bool): Whether the emails are phishing or not
        """
        # Find the CSV file
        csv_files = [f for f in os.listdir(input_path) if f.endswith('.csv')]
        
        if not csv_files:
            logger.error(f"No CSV files found in {input_path}")
            return
        
        # Read the CSV file
        csv_path = os.path.join(input_path, csv_files[0])
        df = pd.read_csv(csv_path)
        
        # Process the dataset
        emails_data = []
        
        for _, row in df.iterrows():
            text = row.get('text', '')
            label = row.get('label', 1 if is_phishing else 0)
            
            # Extract email parts if possible
            subject = ""
            sender = ""
            recipient = ""
            date = ""
            body = text
            
            # Try to extract email parts from the text
            subject_match = re.search(r'Subject:\s*(.+?)(?:\r?\n[^\s]|\r?\n\s*\r?\n|$)', text, re.IGNORECASE)
            if subject_match:
                subject = subject_match.group(1).strip()
            
            sender_match = re.search(r'From:\s*<?([^>\n]+)>?', text, re.IGNORECASE)
            if sender_match:
                sender = sender_match.group(1).strip()
            
            recipient_match = re.search(r'To:\s*<?([^>\n]+)>?', text, re.IGNORECASE)
            if recipient_match:
                recipient = recipient_match.group(1).strip()
            
            date_match = re.search(r'Date:\s*(.+?)(?:\r?\n[^\s]|\r?\n\s*\r?\n|$)', text, re.IGNORECASE)
            if date_match:
                date = date_match.group(1).strip()
            
            # Add to emails data
            emails_data.append({
                'subject': subject,
                'sender': sender,
                'recipient': recipient,
                'date': date,
                'body': body,
                'is_phishing': label
            })
        
        # Save to CSV
        output_df = pd.DataFrame(emails_data)
        output_df.to_csv(output_path, index=False)
        logger.info(f"Saved {len(emails_data)} emails to {output_path}")
    
    def _process_zip_dataset(self, input_path, output_path, is_phishing):
        """
        Process a dataset from a ZIP file.
        
        Args:
            input_path (str): Path to the extracted ZIP contents
            output_path (str): Path to save the processed CSV
            is_phishing (bool): Whether the emails are phishing or not
        """
        emails_data = []
        
        # Walk through the directory
        for root, _, files in os.walk(input_path):
            for file_name in files:
                if file_name.endswith('.txt') or file_name.endswith('.eml'):
                    file_path = os.path.join(root, file_name)
                    
                    try:
                        # Read the email file
                        with open(file_path, 'rb') as f:
                            email_content = f.read()
                        
                        # Parse the email
                        try:
                            msg = BytesParser(policy=policy.default).parsebytes(email_content)
                            
                            # Extract email fields
                            subject = msg.get('Subject', '')
                            sender = msg.get('From', '')
                            recipient = msg.get('To', '')
                            date = msg.get('Date', '')
                            
                            # Extract email body
                            body = ""
                            if msg.is_multipart():
                                for part in msg.walk():
                                    content_type = part.get_content_type()
                                    if content_type == "text/plain" or content_type == "text/html":
                                        try:
                                            part_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                            body += part_body + "\n"
                                        except:
                                            pass
                            else:
                                try:
                                    body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
                                except:
                                    body = msg.get_payload(decode=False)
                            
                            # Clean the body text
                            if isinstance(body, str):
                                # Remove HTML tags
                                body = re.sub(r'<[^>]+>', ' ', body)
                                # Remove extra whitespace
                                body = re.sub(r'\s+', ' ', body).strip()
                            
                            # Add to emails data
                            emails_data.append({
                                'subject': subject,
                                'sender': sender,
                                'recipient': recipient,
                                'date': date,
                                'body': body,
                                'is_phishing': 1 if is_phishing else 0
                            })
                            
                        except Exception as e:
                            logger.warning(f"Error parsing email {file_path}: {e}")
                            
                            # Try to extract text content directly
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                
                                emails_data.append({
                                    'subject': '',
                                    'sender': '',
                                    'recipient': '',
                                    'date': '',
                                    'body': content,
                                    'is_phishing': 1 if is_phishing else 0
                                })
                            except Exception as e2:
                                logger.error(f"Error reading file {file_path}: {e2}")
                    
                    except Exception as e:
                        logger.error(f"Error processing file {file_path}: {e}")
        
        # Save to CSV
        df = pd.DataFrame(emails_data)
        df.to_csv(output_path, index=False)
        logger.info(f"Saved {len(emails_data)} emails to {output_path}")
    
    def _process_csv_dataset(self, input_path, output_path, is_phishing):
        """
        Process a dataset from a CSV file.
        
        Args:
            input_path (str): Path to the directory containing the CSV
            output_path (str): Path to save the processed CSV
            is_phishing (bool): Whether the emails are phishing or not
        """
        # Find the CSV file
        csv_files = [f for f in os.listdir(input_path) if f.endswith('.csv')]
        
        if not csv_files:
            logger.error(f"No CSV files found in {input_path}")
            return
        
        # Read the CSV file
        csv_path = os.path.join(input_path, csv_files[0])
        df = pd.read_csv(csv_path)
        
        # Process the dataset
        emails_data = []
        
        # Check if the CSV has the expected columns
        if 'text' in df.columns and 'label' in df.columns:
            # Standard format
            for _, row in df.iterrows():
                text = row['text']
                label = row['label'] if not is_phishing else 1
                
                emails_data.append({
                    'subject': '',
                    'sender': '',
                    'recipient': '',
                    'date': '',
                    'body': text,
                    'is_phishing': label
                })
        else:
            # Try to infer the format
            for _, row in df.iterrows():
                # Try to extract relevant columns
                body = ''
                label = 1 if is_phishing else 0
                subject = ''
                sender = ''
                recipient = ''
                date = ''
                
                for col in df.columns:
                    col_lower = col.lower()
                    
                    if 'body' in col_lower or 'content' in col_lower or 'text' in col_lower:
                        body = row[col]
                    elif 'label' in col_lower or 'class' in col_lower or 'phishing' in col_lower:
                        label = row[col]
                    elif 'subject' in col_lower:
                        subject = row[col]
                    elif 'from' in col_lower or 'sender' in col_lower:
                        sender = row[col]
                    elif 'to' in col_lower or 'recipient' in col_lower:
                        recipient = row[col]
                    elif 'date' in col_lower:
                        date = row[col]
                
                # If no body found, use the first column
                if not body and len(df.columns) > 0:
                    body = row[df.columns[0]]
                
                emails_data.append({
                    'subject': subject,
                    'sender': sender,
                    'recipient': recipient,
                    'date': date,
                    'body': body,
                    'is_phishing': label
                })
        
        # Save to CSV
        output_df = pd.DataFrame(emails_data)
        output_df.to_csv(output_path, index=False)
        logger.info(f"Saved {len(emails_data)} emails to {output_path}")
    
    def combine_datasets(self):
        """
        Combine all processed datasets into a single dataset.
        
        Returns:
            str: Path to the combined dataset
        """
        combined_path = os.path.join(self.combined_dir, "combined_dataset.csv")
        
        # Get all processed datasets
        processed_files = [f for f in os.listdir(self.processed_dir) if f.endswith('.csv')]
        
        if not processed_files:
            logger.error("No processed datasets found")
            return None
        
        # Combine datasets
        combined_data = []
        
        for file_name in processed_files:
            file_path = os.path.join(self.processed_dir, file_name)
            
            try:
                df = pd.read_csv(file_path)
                combined_data.append(df)
                logger.info(f"Added {len(df)} emails from {file_name}")
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")
        
        if not combined_data:
            logger.error("No data to combine")
            return None
        
        # Concatenate all datasets
        combined_df = pd.concat(combined_data, ignore_index=True)
        
        # Remove duplicates
        combined_df.drop_duplicates(subset=['body'], keep='first', inplace=True)
        
        # Balance the dataset
        phishing_df = combined_df[combined_df['is_phishing'] == 1]
        non_phishing_df = combined_df[combined_df['is_phishing'] == 0]
        
        # Determine the target size for each class
        target_size = min(len(phishing_df), len(non_phishing_df))
        
        # Sample from each class
        if len(phishing_df) > target_size:
            phishing_df = phishing_df.sample(target_size, random_state=42)
        
        if len(non_phishing_df) > target_size:
            non_phishing_df = non_phishing_df.sample(target_size, random_state=42)
        
        # Combine the balanced classes
        balanced_df = pd.concat([phishing_df, non_phishing_df], ignore_index=True)
        
        # Shuffle the dataset
        balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save the combined dataset
        balanced_df.to_csv(combined_path, index=False)
        logger.info(f"Saved combined dataset with {len(balanced_df)} emails to {combined_path}")
        
        return combined_path
    
    def create_train_test_split(self, test_size=0.2, val_size=0.1):
        """
        Create train, test, and validation splits from the combined dataset.
        
        Args:
            test_size (float): Proportion of data to use for testing
            val_size (float): Proportion of data to use for validation
            
        Returns:
            tuple: Paths to the train, test, and validation datasets
        """
        combined_path = os.path.join(self.combined_dir, "combined_dataset.csv")
        
        if not os.path.exists(combined_path):
            logger.error(f"Combined dataset not found at {combined_path}")
            return None
        
        # Load the combined dataset
        df = pd.read_csv(combined_path)
        
        # Split the dataset
        from sklearn.model_selection import train_test_split
        
        # First split: train+val and test
        train_val_df, test_df = train_test_split(df, test_size=test_size, stratify=df['is_phishing'], random_state=42)
        
        # Second split: train and val
        train_df, val_df = train_test_split(train_val_df, test_size=val_size/(1-test_size), stratify=train_val_df['is_phishing'], random_state=42)
        
        # Save the splits
        train_path = os.path.join(self.combined_dir, "train_dataset.csv")
        test_path = os.path.join(self.combined_dir, "test_dataset.csv")
        val_path = os.path.join(self.combined_dir, "val_dataset.csv")
        
        train_df.to_csv(train_path, index=False)
        test_df.to_csv(test_path, index=False)
        val_df.to_csv(val_path, index=False)
        
        logger.info(f"Created train dataset with {len(train_df)} emails")
        logger.info(f"Created test dataset with {len(test_df)} emails")
        logger.info(f"Created validation dataset with {len(val_df)} emails")
        
        return train_path, test_path, val_path
    
    def run_full_pipeline(self):
        """
        Run the full pipeline: download, process, combine, and split datasets.
        
        Returns:
            tuple: Paths to the train, test, and validation datasets
        """
        # Download all datasets
        for dataset_name in self.dataset_sources.keys():
            self.download_dataset(dataset_name)
        
        # Process all datasets
        for dataset_name in self.dataset_sources.keys():
            self.process_dataset(dataset_name)
        
        # Combine datasets
        self.combine_datasets()
        
        # Create train/test/val splits
        return self.create_train_test_split()

if __name__ == "__main__":
    integrator = DatasetIntegrator()
    train_path, test_path, val_path = integrator.run_full_pipeline()
    
    logger.info(f"Pipeline complete!")
    logger.info(f"Train dataset: {train_path}")
    logger.info(f"Test dataset: {test_path}")
    logger.info(f"Validation dataset: {val_path}") 