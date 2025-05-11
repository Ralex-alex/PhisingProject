import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import pytz
import re
import logging
import ipaddress
from collections import Counter
import json
from typing import Dict, List, Any, Tuple, Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("behavioral_analysis")

class BehavioralAnalyzer:
    """
    Class to analyze behavioral patterns in emails for phishing detection,
    such as unusual sending times, geographic origins, and communication history.
    """
    
    def __init__(self, history_db_path=None):
        """
        Initialize the behavioral analyzer.
        
        Args:
            history_db_path (str): Path to a CSV file containing email history data
        """
        self.history_db = None
        self.history_db_path = history_db_path
        if history_db_path:
            try:
                self.history_db = pd.read_csv(history_db_path)
                logger.info(f"Loaded history database with {len(self.history_db)} entries")
            except Exception as e:
                logger.warning(f"Could not load history database: {e}")
                # Create an empty history database
                self.history_db = pd.DataFrame(columns=[
                    'sender', 'recipient', 'timestamp', 'subject', 
                    'is_phishing', 'origin_ip', 'origin_country'
                ])
    
    def extract_email_metadata(self, email_headers):
        """
        Extract metadata from email headers.
        
        Args:
            email_headers (str): Raw email headers
            
        Returns:
            dict: Extracted metadata
        """
        metadata = {
            "date": None,
            "time": None,
            "timezone": None,
            "datetime_obj": None,
            "received_count": 0,
            "received_ips": [],
            "received_domains": [],
            "origin_ip": None,
            "origin_country": None,
            "return_path": None,
            "reply_to": None,
            "x_mailer": None
        }
        
        try:
            # Extract date and time
            date_pattern = r'Date:\s*([A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{1,2}:\d{1,2}:\d{1,2}\s+[+-]\d{4})'
            date_match = re.search(date_pattern, email_headers)
            
            if date_match:
                date_str = date_match.group(1)
                try:
                    # Parse the date string
                    dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")
                    metadata["date"] = dt.strftime("%Y-%m-%d")
                    metadata["time"] = dt.strftime("%H:%M:%S")
                    metadata["timezone"] = dt.strftime("%z")
                    metadata["datetime_obj"] = dt
                except Exception as e:
                    logger.warning(f"Failed to parse date: {e}")
            
            # Extract Received headers
            received_pattern = r'Received:\s+from\s+([^\s\[\]]+)(?:\s+\[([^\]]+)\])?'
            received_matches = re.finditer(received_pattern, email_headers)
            
            for match in received_matches:
                metadata["received_count"] += 1
                domain = match.group(1)
                ip = match.group(2) if match.group(2) else None
                
                if domain:
                    metadata["received_domains"].append(domain)
                
                if ip:
                    metadata["received_ips"].append(ip)
            
            # The last IP in the chain is usually the origin
            if metadata["received_ips"]:
                metadata["origin_ip"] = metadata["received_ips"][0]
            
            # Extract Return-Path
            return_path_pattern = r'Return-Path:\s*<([^>]+)>'
            return_path_match = re.search(return_path_pattern, email_headers)
            if return_path_match:
                metadata["return_path"] = return_path_match.group(1)
            
            # Extract Reply-To
            reply_to_pattern = r'Reply-To:\s*<?([^>\s]+)>?'
            reply_to_match = re.search(reply_to_pattern, email_headers)
            if reply_to_match:
                metadata["reply_to"] = reply_to_match.group(1)
            
            # Extract X-Mailer
            x_mailer_pattern = r'X-Mailer:\s*(.+)'
            x_mailer_match = re.search(x_mailer_pattern, email_headers)
            if x_mailer_match:
                metadata["x_mailer"] = x_mailer_match.group(1).strip()
        
        except Exception as e:
            logger.error(f"Error extracting email metadata: {e}")
        
        return metadata
    
    def check_unusual_sending_time(self, timestamp, sender):
        """
        Check if the email was sent at an unusual time.
        
        Args:
            timestamp (datetime): Email timestamp
            sender (str): Email sender
            
        Returns:
            dict: Analysis results
        """
        result = {
            "is_unusual_time": False,
            "reason": None,
            "risk_score": 0.0
        }
        
        try:
            # Check if timestamp is during typical business hours (9 AM - 6 PM)
            hour = timestamp.hour
            
            # Check if it's a weekend
            is_weekend = timestamp.weekday() >= 5  # 5 = Saturday, 6 = Sunday
            
            # Check if it's very late at night or very early morning
            is_late_night = hour >= 22 or hour <= 5
            
            if is_late_night:
                result["is_unusual_time"] = True
                result["reason"] = "Late night/early morning"
                result["risk_score"] = 0.7
            elif is_weekend:
                result["is_unusual_time"] = True
                result["reason"] = "Weekend"
                result["risk_score"] = 0.5
            
            # If we have history data, check if this sender typically sends at this time
            if self.history_db is not None and not result["is_unusual_time"]:
                sender_history = self.history_db[self.history_db['sender'] == sender]
                
                if not sender_history.empty:
                    # Convert timestamps to datetime objects
                    timestamps = pd.to_datetime(sender_history['timestamp'])
                    
                    # Extract hours
                    hours = [ts.hour for ts in timestamps]
                    
                    # Calculate the frequency of each hour
                    hour_counts = Counter(hours)
                    
                    # Check if the current hour is unusual for this sender
                    if hour not in hour_counts or hour_counts[hour] < 2:
                        result["is_unusual_time"] = True
                        result["reason"] = "Unusual time for this sender"
                        result["risk_score"] = 0.6
        
        except Exception as e:
            logger.error(f"Error checking unusual sending time: {e}")
        
        return result
    
    def check_geographic_origin(self, ip_address):
        """
        Check the geographic origin of an email based on IP address.
        
        Args:
            ip_address (str): IP address to check
            
        Returns:
            dict: Analysis results
        """
        result = {
            "is_suspicious": False,
            "country": None,
            "city": None,
            "risk_score": 0.0
        }
        
        try:
            if not ip_address:
                return result
            
            # Check if it's a valid IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                return result
            
            # In a real implementation, you would use a geolocation API or database
            # This is a placeholder for demonstration purposes
            logger.info(f"Would check geolocation for IP: {ip_address}")
            
            # For demonstration, we'll just assign a random country
            # In a real implementation, use a proper IP geolocation service
            import random
            countries = ["United States", "Russia", "China", "Nigeria", "United Kingdom", "Germany"]
            result["country"] = random.choice(countries)
            
            # Assign risk score based on country
            high_risk_countries = ["Russia", "China", "Nigeria"]
            if result["country"] in high_risk_countries:
                result["is_suspicious"] = True
                result["risk_score"] = 0.8
            
        except Exception as e:
            logger.error(f"Error checking geographic origin: {e}")
        
        return result
    
    def check_sender_history(self, sender, recipient):
        """
        Check the communication history between sender and recipient.
        
        Args:
            sender (str): Email sender
            recipient (str): Email recipient
            
        Returns:
            dict: Analysis results
        """
        result = {
            "is_first_contact": True,
            "previous_communications": 0,
            "average_interval_days": None,
            "risk_score": 0.0
        }
        
        try:
            if self.history_db is None:
                # No history data available
                result["risk_score"] = 0.5
                return result
            
            # Filter history for this sender-recipient pair
            history = self.history_db[
                (self.history_db['sender'] == sender) & 
                (self.history_db['recipient'] == recipient)
            ]
            
            result["previous_communications"] = len(history)
            
            if result["previous_communications"] > 0:
                result["is_first_contact"] = False
                
                # Calculate average interval between communications
                if result["previous_communications"] > 1:
                    timestamps = pd.to_datetime(history['timestamp']).sort_values()
                    intervals = [(timestamps.iloc[i] - timestamps.iloc[i-1]).days 
                                for i in range(1, len(timestamps))]
                    result["average_interval_days"] = sum(intervals) / len(intervals)
                
                # Check if any previous communications were marked as phishing
                phishing_count = sum(history['is_phishing'])
                
                if phishing_count > 0:
                    result["risk_score"] = 0.9
                else:
                    # Lower risk for established communication patterns
                    result["risk_score"] = max(0.1, 0.5 - (0.1 * min(result["previous_communications"], 4)))
            else:
                # First contact is slightly risky
                result["risk_score"] = 0.6
        
        except Exception as e:
            logger.error(f"Error checking sender history: {e}")
            result["risk_score"] = 0.5
        
        return result
    
    def check_header_consistency(self, headers):
        """
        Check for inconsistencies in email headers.
        
        Args:
            headers (str): Email headers
            
        Returns:
            dict: Analysis results
        """
        result = {
            "is_consistent": True,
            "inconsistencies": [],
            "risk_score": 0.0
        }
        
        try:
            # Extract key fields
            from_pattern = r'From:\s*(?:"?([^"<]+)"?\s+)?<?([^>]+)>?'
            return_path_pattern = r'Return-Path:\s*<([^>]+)>'
            reply_to_pattern = r'Reply-To:\s*<?([^>\s]+)>?'
            
            from_match = re.search(from_pattern, headers)
            return_path_match = re.search(return_path_pattern, headers)
            reply_to_match = re.search(reply_to_pattern, headers)
            
            from_email = from_match.group(2) if from_match else None
            return_path = return_path_match.group(1) if return_path_match else None
            reply_to = reply_to_match.group(1) if reply_to_match else None
            
            # Check for mismatches
            if from_email and return_path and from_email != return_path:
                result["is_consistent"] = False
                result["inconsistencies"].append(f"From ({from_email}) doesn't match Return-Path ({return_path})")
                result["risk_score"] = max(result["risk_score"], 0.7)
            
            if from_email and reply_to and from_email != reply_to:
                result["is_consistent"] = False
                result["inconsistencies"].append(f"From ({from_email}) doesn't match Reply-To ({reply_to})")
                result["risk_score"] = max(result["risk_score"], 0.8)
            
            # Check for unusual Received chain length
            received_headers = re.findall(r'Received:', headers)
            if len(received_headers) > 7:  # Unusually long chain
                result["is_consistent"] = False
                result["inconsistencies"].append(f"Unusually long Received chain ({len(received_headers)} hops)")
                result["risk_score"] = max(result["risk_score"], 0.6)
            
        except Exception as e:
            logger.error(f"Error checking header consistency: {e}")
            result["risk_score"] = 0.5
        
        return result
    
    def analyze_behavior(self, email_content, sender, recipient):
        """
        Analyze behavioral patterns in an email.
        
        Args:
            email_content (str): Raw email content
            sender (str): Email sender
            recipient (str): Email recipient
            
        Returns:
            dict: Analysis results
        """
        result = {
            "is_suspicious": False,
            "risk_score": 0.0,
            "analysis_details": {}
        }
        
        try:
            # Split headers and body
            parts = email_content.split("\n\n", 1)
            headers = parts[0] if len(parts) > 0 else email_content
            
            # Extract metadata
            metadata = self.extract_email_metadata(headers)
            result["metadata"] = metadata
            
            # Check for unusual sending time
            if metadata["datetime_obj"]:
                time_analysis = self.check_unusual_sending_time(
                    metadata["datetime_obj"], sender
                )
                result["analysis_details"]["sending_time"] = time_analysis
            
            # Check geographic origin
            geo_analysis = self.check_geographic_origin(metadata["origin_ip"])
            result["analysis_details"]["geographic_origin"] = geo_analysis
            
            # Check sender history
            history_analysis = self.check_sender_history(sender, recipient)
            result["analysis_details"]["sender_history"] = history_analysis
            
            # Check header consistency
            consistency_analysis = self.check_header_consistency(headers)
            result["analysis_details"]["header_consistency"] = consistency_analysis
            
            # Calculate overall risk score (weighted average)
            weights = {
                "sending_time": 0.2,
                "geographic_origin": 0.3,
                "sender_history": 0.3,
                "header_consistency": 0.2
            }
            
            risk_scores = {
                "sending_time": time_analysis["risk_score"] if metadata["datetime_obj"] else 0.0,
                "geographic_origin": geo_analysis["risk_score"],
                "sender_history": history_analysis["risk_score"],
                "header_consistency": consistency_analysis["risk_score"]
            }
            
            total_weight = sum(
                weights[k] for k in weights.keys() 
                if k == "sending_time" and metadata["datetime_obj"] or k != "sending_time"
            )
            
            weighted_score = sum(
                weights[k] * risk_scores[k] for k in weights.keys()
                if k == "sending_time" and metadata["datetime_obj"] or k != "sending_time"
            ) / total_weight if total_weight > 0 else 0.0
            
            result["risk_score"] = min(1.0, weighted_score)
            result["is_suspicious"] = result["risk_score"] > 0.6
            
            # Update history database with this email
            self._update_history(sender, recipient, metadata)
            
        except Exception as e:
            logger.error(f"Error in behavioral analysis: {e}")
            result["risk_score"] = 0.5
        
        return result
    
    def _update_history(self, sender, recipient, metadata):
        """
        Update the history database with a new email.
        
        Args:
            sender (str): Email sender
            recipient (str): Email recipient
            metadata (dict): Email metadata
        """
        if self.history_db is None:
            # Create a new history database
            self.history_db = pd.DataFrame(columns=[
                'sender', 'recipient', 'timestamp', 'subject', 
                'is_phishing', 'origin_ip', 'origin_country'
            ])
        
        # Create a new entry
        new_entry = {
            'sender': sender,
            'recipient': recipient,
            'timestamp': metadata["datetime_obj"].isoformat() if metadata["datetime_obj"] else datetime.now().isoformat(),
            'subject': None,  # Would extract from headers
            'is_phishing': False,  # Default assumption
            'origin_ip': metadata["origin_ip"],
            'origin_country': metadata.get("origin_country")
        }
        
        # Append to history database
        self.history_db = pd.concat([
            self.history_db, 
            pd.DataFrame([new_entry])
        ], ignore_index=True)
    
    def save_history(self, path: Optional[str] = None) -> bool:
        """
        Save the history database to a CSV file.
        
        Args:
            path (str): Path to save the history database
            
        Returns:
            bool: Success or failure
        """
        try:
            if self.history_db is None:
                logger.warning("No history database to save")
                return False
            
            save_path = path or self.history_db_path
            
            if not save_path:
                logger.warning("No path specified for saving history database")
                return False
            
            self.history_db.to_csv(save_path, index=False)
            logger.info(f"Saved history database with {len(self.history_db)} entries to {save_path}")
            
            return True
        
        except Exception as e:
            logger.error(f"Error saving history database: {e}")
            return False

# Example usage
if __name__ == "__main__":
    analyzer = BehavioralAnalyzer()
    
    # Example email content
    email_content = """From: sender@example.com
To: recipient@example.com
Date: Mon, 15 May 2023 03:45:22 +0000
Subject: Urgent Action Required
Received: from mail.example.com ([192.168.1.1]) by server.example.com
Received: from external.sender.com ([203.0.113.17]) by mail.example.com

This is the email body content.
"""
    
    result = analyzer.analyze_behavior(
        email_content, 
        "sender@example.com", 
        "recipient@example.com"
    )
    
    print(json.dumps(result, indent=2, default=str)) 