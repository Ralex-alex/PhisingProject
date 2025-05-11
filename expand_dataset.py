import os
import pandas as pd
import requests
from tqdm import tqdm
import zipfile
import io
import email
import re
import glob
from urllib.parse import urlparse
import random

class DatasetExpander:
    """
    Class to download and integrate publicly available phishing datasets
    to enhance the training data for phishing detection.
    """
    
    def __init__(self, output_dir="expanded_data"):
        """
        Initialize the dataset expander.
        
        Args:
            output_dir (str): Directory to store downloaded and processed datasets
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Track download status for each dataset
        self.downloaded_datasets = {}
        
    def download_file(self, url, local_filename=None):
        """
        Download a file from a URL with progress bar.
        
        Args:
            url (str): URL to download
            local_filename (str, optional): Local filename to save to
            
        Returns:
            str: Path to downloaded file
        """
        if local_filename is None:
            # Extract filename from URL
            parsed_url = urlparse(url)
            local_filename = os.path.join(self.output_dir, os.path.basename(parsed_url.path))
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(local_filename), exist_ok=True)
        
        print(f"Downloading {url} to {local_filename}")
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # Get file size for progress bar
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024  # 1 KB
        
        with open(local_filename, 'wb') as f:
            with tqdm(total=total_size, unit='B', unit_scale=True, desc=os.path.basename(local_filename)) as pbar:
                for data in response.iter_content(block_size):
                    f.write(data)
                    pbar.update(len(data))
        
        return local_filename
    
    def process_phishtank_data(self):
        """
        Download and process PhishTank dataset.
        
        Returns:
            pd.DataFrame: Processed PhishTank data
        """
        print("Processing PhishTank dataset...")
        
        phishtank_url = "https://data.phishtank.com/data/online-valid.csv"
        
        try:
            # Download the dataset
            local_file = self.download_file(phishtank_url, 
                                           os.path.join(self.output_dir, "phishtank_data.csv"))
            
            # Read the dataset
            df = pd.read_csv(local_file)
            
            # Extract relevant information (URL and additional details)
            phishing_emails = []
            
            for _, row in tqdm(df.iterrows(), total=len(df), desc="Processing PhishTank entries"):
                # Create a synthetic email-like format with the phishing URL
                url = row['url']
                phish_id = row['phish_id']
                
                # Create a simple email-like structure
                email_text = f"Subject: Important Information\n\n"
                email_text += f"Dear User,\n\n"
                email_text += f"Please click on the following link to update your information:\n"
                email_text += f"{url}\n\n"
                email_text += f"Regards,\nThe Team"
                
                phishing_emails.append({"text": email_text, "label": "phishing"})
            
            # Create DataFrame
            phishtank_df = pd.DataFrame(phishing_emails)
            self.downloaded_datasets["phishtank"] = True
            
            print(f"Processed {len(phishtank_df)} PhishTank entries")
            return phishtank_df
            
        except Exception as e:
            print(f"Error processing PhishTank data: {e}")
            self.downloaded_datasets["phishtank"] = False
            return pd.DataFrame(columns=["text", "label"])
    
    def process_enron_data(self, max_emails=5000):
        """
        Download and process Enron email dataset (legitimate emails).
        
        Args:
            max_emails (int): Maximum number of emails to process
            
        Returns:
            pd.DataFrame: Processed Enron data
        """
        print("Processing Enron dataset for legitimate emails...")
        
        enron_url = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
        local_file = os.path.join(self.output_dir, "enron_mail.tar.gz")
        
        try:
            # Check if already downloaded
            if not os.path.exists(local_file):
                # This is a large file (~423 MB), so we'll inform the user
                print(f"Downloading Enron dataset (~423 MB). This may take a while...")
                local_file = self.download_file(enron_url, local_file)
            
            # We'll use a more selective approach - just extract and process a subset
            import tarfile
            
            legitimate_emails = []
            
            # Extract emails from the archive
            with tarfile.open(local_file, "r:gz") as tar:
                # Get list of all .txt files in the archive
                email_files = [f for f in tar.getnames() if f.endswith(".txt")]
                
                # Randomly sample from the email files
                sampled_files = random.sample(email_files, min(max_emails, len(email_files)))
                
                for file_path in tqdm(sampled_files, desc="Processing Enron emails"):
                    try:
                        file_obj = tar.extractfile(file_path)
                        if file_obj:
                            raw_email = file_obj.read().decode(errors='replace')
                            
                            # Parse email
                            msg = email.message_from_string(raw_email)
                            
                            # Extract subject and body
                            subject = msg["Subject"] if msg["Subject"] else ""
                            body = ""
                            
                            if msg.is_multipart():
                                for part in msg.walk():
                                    if part.get_content_type() == "text/plain":
                                        body_part = part.get_payload(decode=True)
                                        if body_part:
                                            body += body_part.decode(errors='replace')
                            else:
                                payload = msg.get_payload(decode=True)
                                if payload:
                                    body = payload.decode(errors='replace')
                            
                            # Combine subject and body
                            email_text = f"Subject: {subject}\n\n{body}"
                            
                            legitimate_emails.append({"text": email_text, "label": "legitimate"})
                    except Exception as inner_e:
                        print(f"Error processing Enron email file {file_path}: {inner_e}")
            
            # Create DataFrame
            enron_df = pd.DataFrame(legitimate_emails)
            self.downloaded_datasets["enron"] = True
            
            print(f"Processed {len(enron_df)} Enron legitimate emails")
            return enron_df
            
        except Exception as e:
            print(f"Error processing Enron data: {e}")
            self.downloaded_datasets["enron"] = False
            return pd.DataFrame(columns=["text", "label"])
    
    def download_nazario_corpus(self):
        """
        Attempt to download the Nazario Phishing Corpus.
        This is for illustrative purposes - access to this corpus typically requires registration.
        
        Returns:
            pd.DataFrame: Processed Nazario corpus data or empty DataFrame if download fails
        """
        print("Note: The Nazario Phishing Corpus typically requires registration.")
        print("This example shows how you would process it if you had access.")
        
        # If you have access to the corpus, you'd download and process it here
        # For demonstration, we'll generate a placeholder message
        
        self.downloaded_datasets["nazario"] = False
        
        # Return empty DataFrame as we don't have direct access
        return pd.DataFrame(columns=["text", "label"])
    
    def generate_synthetic_phishing(self, n_samples=1000):
        """
        Generate synthetic phishing emails using templates.
        
        Args:
            n_samples (int): Number of synthetic phishing emails to generate
            
        Returns:
            pd.DataFrame: Synthetic phishing data
        """
        print(f"Generating {n_samples} synthetic phishing emails...")
        
        # Phishing email templates
        templates = [
            {
                "subject": "Your account has been suspended",
                "body": "Dear {user},\n\nYour account has been suspended due to suspicious activity. Please click the link below to verify your identity:\n\n{url}\n\nRegards,\n{company} Team"
            },
            {
                "subject": "Security Alert: Unusual Sign-In Attempt",
                "body": "Dear {user},\n\nWe detected an unusual sign-in attempt to your account. If this wasn't you, please secure your account immediately:\n\n{url}\n\nSecurity Team,\n{company}"
            },
            {
                "subject": "Action Required: Update Your Payment Information",
                "body": "Dear {user},\n\nYour payment information needs to be updated to continue your service. Please update your details here:\n\n{url}\n\nThank you,\n{company} Billing"
            },
            {
                "subject": "Your package is waiting for delivery",
                "body": "Hello {user},\n\nYour package with tracking #{tracking} could not be delivered. Please confirm your address:\n\n{url}\n\nShipping Department,\n{company}"
            },
            {
                "subject": "Tax Refund Notification",
                "body": "Dear {user},\n\nYou have a tax refund of ${amount} waiting to be processed. Please submit your details to claim it:\n\n{url}\n\nTax Department,\n{company}"
            }
        ]
        
        # Placeholders for variable content
        users = ["Customer", "User", "Member", "Valued Customer", "Client"]
        companies = ["Bank of America", "PayPal", "Amazon", "Apple", "Microsoft", "Netflix", "USPS", "FedEx", "IRS", "DocuSign"]
        urls = [
            "http://secure-login-verify.com/account",
            "https://verification-secure.net/auth",
            "http://accountprotection.org/verify",
            "https://security-check.info/protect",
            "http://payment-update.net/billing",
            "https://tracking-status.co/package",
            "http://refund-process.com/claim",
            "https://document-sign.org/view"
        ]
        
        tracking_numbers = [f"{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}" for _ in range(20)]
        amounts = [f"{random.randint(100, 999)}.{random.randint(10, 99)}" for _ in range(20)]
        
        synthetic_phishing = []
        
        for _ in tqdm(range(n_samples), desc="Generating synthetic phishing"):
            template = random.choice(templates)
            user = random.choice(users)
            company = random.choice(companies)
            url = random.choice(urls)
            tracking = random.choice(tracking_numbers)
            amount = random.choice(amounts)
            
            subject = template["subject"]
            body = template["body"].format(
                user=user,
                company=company,
                url=url,
                tracking=tracking,
                amount=amount
            )
            
            email_text = f"Subject: {subject}\n\n{body}"
            synthetic_phishing.append({"text": email_text, "label": "phishing"})
        
        # Create DataFrame
        synthetic_df = pd.DataFrame(synthetic_phishing)
        self.downloaded_datasets["synthetic"] = True
        
        print(f"Generated {len(synthetic_df)} synthetic phishing emails")
        return synthetic_df
    
    def combine_datasets(self, output_file="combined_dataset.csv"):
        """
        Combine all the datasets into a single file.
        
        Args:
            output_file (str): Output file path
            
        Returns:
            pd.DataFrame: Combined dataset
        """
        print("Combining datasets...")
        
        # Initialize with existing datasets
        try:
            existing_data = pd.read_csv("emails_from_spamassassin.csv")
            print(f"Loaded {len(existing_data)} existing emails from SpamAssassin")
        except Exception as e:
            print(f"Error loading existing data: {e}")
            existing_data = pd.DataFrame(columns=["text", "label"])
        
        # Download and process PhishTank data
        phishtank_df = self.process_phishtank_data()
        
        # Download and process Enron data
        enron_df = self.process_enron_data(max_emails=3000)
        
        # Generate synthetic phishing emails
        synthetic_df = self.generate_synthetic_phishing(n_samples=2000)
        
        # Combine all datasets
        combined_df = pd.concat([
            existing_data,
            phishtank_df,
            enron_df,
            synthetic_df
        ], ignore_index=True)
        
        # Remove duplicates
        combined_df.drop_duplicates(subset=["text"], inplace=True)
        
        # Save combined dataset
        output_path = os.path.join(self.output_dir, output_file)
        combined_df.to_csv(output_path, index=False)
        
        print(f"Combined dataset saved to {output_path}")
        print(f"Total emails: {len(combined_df)}")
        print(f"Legitimate emails: {len(combined_df[combined_df['label'] == 'legitimate'])}")
        print(f"Phishing emails: {len(combined_df[combined_df['label'] == 'phishing'])}")
        
        return combined_df

if __name__ == "__main__":
    # Initialize the dataset expander
    expander = DatasetExpander()
    
    # Combine all datasets
    combined_df = expander.combine_datasets() 