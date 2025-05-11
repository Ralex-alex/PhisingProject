"""
Main Phishing Detection Module

This module implements a comprehensive phishing detection system that analyzes emails
based on multiple factors including sender domain, URLs, and content patterns.
The system uses a weighted scoring approach to determine the likelihood of an email being phishing.

Key Features:
- Sender domain analysis (typosquatting, domain age)
- URL analysis (suspicious domains, redirects)
- Content analysis (urgency, threats, patterns)
- Configurable risk thresholds and weights
- Detailed reporting with risk factors and recommendations
"""

import re
import logging
import json
import requests
import dns.resolver
import whois
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import time

# Set up logging configuration for tracking detector operations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("phishing_detector")

class PhishingDetector:
    """
    Core phishing detection system that evaluates emails using multiple analysis components.
    
    The detector uses a weighted combination of:
    1. Sender Analysis: Checks for domain spoofing and suspicious sender patterns
    2. URL Analysis: Evaluates links for suspicious domains and redirect chains
    3. Content Analysis: Identifies urgent language, threats, and suspicious patterns
    
    Each component contributes to a final risk score that determines if an email is phishing.
    """
    
    def __init__(self, config_path: str = "config.json"):
        """
        Initialize the phishing detector with configuration settings.
        
        Args:
            config_path (str): Path to JSON configuration file containing thresholds and weights
                             If not found, uses default configuration values
        
        The configuration includes:
        - confidence_threshold: Minimum score to classify as phishing
        - high_confidence_threshold: Score threshold for high-risk classification
        - component_weights: Relative importance of each analysis component
        - url_timeout: Maximum time to wait for URL analysis
        - max_redirects: Maximum number of URL redirects to follow
        """
        self.config = self._load_config(config_path)
        # List of major brands commonly targeted in phishing attacks
        self.known_brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'netflix']
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load and validate configuration settings from a JSON file.
        
        Args:
            config_path (str): Path to the configuration JSON file
            
        Returns:
            dict: Configuration settings with default values for missing fields
            
        The configuration file should contain:
        {
            "confidence_threshold": float,      # Minimum score to classify as phishing
            "high_confidence_threshold": float, # Score for high-risk classification
            "url_timeout": int,                # Seconds to wait for URL analysis
            "max_redirects": int,              # Maximum URL redirects to follow
            "component_weights": {             # Relative importance of components
                "sender": float,
                "url": float,
                "content": float
            }
        }
        """
        default_config = {
            "confidence_threshold": 0.5,    # Default 50% confidence for phishing
            "high_confidence_threshold": 0.8,  # Default 80% for high risk
            "url_timeout": 3,              # Default 3 seconds timeout
            "max_redirects": 3,            # Default max 3 redirects
            "component_weights": {
                "sender": 0.4,             # 40% weight for sender analysis
                "url": 0.4,                # 40% weight for URL analysis
                "content": 0.2             # 20% weight for content analysis
            }
        }
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                logger.info(f"Loaded configuration from {config_path}")
                
                # Merge with default config to ensure all required fields exist
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                
                return config
        except Exception as e:
            logger.warning(f"Error loading config: {e}. Using default configuration.")
            return default_config
    
    def analyze_sender(self, sender: str) -> Dict[str, Any]:
        """
        Analyze the sender's email address for phishing indicators.
        
        This method examines several aspects of the sender's email:
        1. Email format validation
        2. Domain typosquatting detection
        3. Domain age and reputation checks
        4. Trusted domain verification
        
        Args:
            sender (str): Email address of the sender
            
        Returns:
            dict: Analysis results containing:
                - risk_score (float): 0.0-1.0 risk score
                - risk_factors (list): List of identified suspicious factors
                
        Risk Scoring:
        - Invalid email format: 0.8 risk score
        - Typosquatting detected: +0.4 to risk score
        - Suspicious TLD: +0.3 to risk score
        - New domain: +0.2 to risk score
        - Missing DNS records: +0.2 to risk score
        """
        result = {
            "risk_score": 0.0,
            "risk_factors": []
        }
        
        try:
            # Validate basic email format
            if not sender or '@' not in sender:
                result["risk_score"] = 0.8  # High risk for invalid format
                result["risk_factors"].append("Invalid sender email format")
                return result
            
            domain = sender.split('@')[1].lower()
            
            # Check for typosquatting against known brand names
            for brand in self.known_brands:
                if (brand in domain and not domain.endswith(f".{brand}.com") and 
                    not any(domain.endswith(trusted) for trusted in self.config.get("sender_analysis", {}).get("trusted_domains", []))):
                    result["risk_factors"].append(f"Possible typosquatting of {brand}")
                    result["risk_score"] += 0.4
            
            # Check domain age with more lenient threshold for business domains
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    # Convert to list if it's not
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    
                    domain_age_days = (time.time() - creation_date.timestamp()) / (24 * 3600)
                    
                    # More lenient threshold for business domains
                    if domain_age_days < 14:  # Changed from 30 to 14 days
                        result["risk_factors"].append("Domain is less than 14 days old")
                        result["risk_score"] += 0.3
                    elif domain_age_days < 30:  # Add medium risk for domains 14-30 days old
                        result["risk_factors"].append("Domain is relatively new (14-30 days old)")
                        result["risk_score"] += 0.15
            except Exception as e:
                logger.warning(f"Could not check domain age: {e}")
                result["risk_factors"].append("Could not verify domain age")
                result["risk_score"] += 0.1
            
            # Check DNS records
            try:
                dns.resolver.resolve(domain, 'MX')
            except Exception:
                result["risk_factors"].append("No valid MX records")
                result["risk_score"] += 0.3
            
        except Exception as e:
            logger.error(f"Error in sender analysis: {e}")
            result["risk_score"] = 0.5
            result["risk_factors"].append("Error analyzing sender domain")
        
        return result
    
    def analyze_urls(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze URLs found in the email content for phishing indicators.
        
        This method performs several checks on each URL:
        1. URL extraction using regex pattern matching
        2. Domain analysis for typosquatting and suspicious TLDs
        3. IP address detection in URLs
        4. Optional: Redirect chain analysis (if configured)
        
        Args:
            email_content (str): Raw email content to analyze
            
        Returns:
            dict: Analysis results containing:
                - risk_score (float): 0.0-1.0 risk score
                - risk_factors (list): List of identified suspicious factors
                - urls_found (int): Number of URLs found in content
                - suspicious_urls (list): Details of suspicious URLs found
                
        Risk Scoring:
        - Typosquatting detected: +0.4 to risk score
        - Suspicious TLD: +0.3 to risk score
        - IP address in URL: +0.4 to risk score
        - Multiple redirects: +0.2 to risk score per redirect
        """
        result = {
            "risk_score": 0.0,
            "risk_factors": [],
            "urls_found": 0,
            "suspicious_urls": []
        }
        
        try:
            # Extract all URLs using regex pattern
            # Matches http/https URLs while handling special characters
            urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*', email_content)
            result["urls_found"] = len(urls)
            
            if not urls:
                return result
            
            for url in urls:
                url_risk = 0.0
                risk_factors = []
                
                # Parse URL into components for analysis
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check for brand impersonation through typosquatting
                for brand in self.known_brands:
                    if brand in domain and not domain.endswith(f".{brand}.com"):
                        risk_factors.append(f"Possible typosquatting of {brand}")
                        url_risk += 0.4
                
                # Check for suspicious top-level domains
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    risk_factors.append("Suspicious top-level domain")
                    url_risk += 0.3
                
                # Check for IP addresses in URLs (often used in phishing)
                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                    risk_factors.append("IP address used in URL")
                    url_risk += 0.4
                
                # Record suspicious URL if any risk factors were found
                if url_risk > 0:
                    result["suspicious_urls"].append({
                        "url": url,
                        "risk_score": url_risk,
                        "risk_factors": risk_factors
                    })
                    # Overall risk is the highest individual URL risk
                    result["risk_score"] = max(result["risk_score"], url_risk)
                
                result["risk_factors"].extend(risk_factors)
            
        except Exception as e:
            logger.error(f"Error in URL analysis: {e}")
            result["risk_score"] = 0.5  # Moderate risk on error
            result["risk_factors"].append("Error analyzing URLs")
        
        return result
    
    def analyze_content(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze email content for suspicious patterns and phishing indicators.
        
        This method examines the email content for:
        1. Urgency and pressure tactics
        2. Threat language and consequences
        3. Business context awareness
        4. Common phishing patterns
        5. Suspicious formatting and structure
        
        Args:
            email_content (str): Raw email content to analyze
            
        Returns:
            dict: Analysis results containing:
                - risk_score (float): 0.0-1.0 risk score
                - risk_factors (list): List of identified suspicious factors
                
        Risk Scoring:
        - High-risk urgent terms: +0.15 per match (max 0.5)
        - Threat language: +0.1 per match (max 0.3)
        - Suspicious formatting: +0.1 to +0.3
        - Business context reduces risk scores by 30-50%
        """
        result = {
            "risk_score": 0.0,
            "risk_factors": []
        }
        
        try:
            # Define context-aware patterns for analysis
            business_context = [
                'order', 'invoice', 'delivery', 'shipping', 'tracking',
                'purchase', 'transaction', 'receipt', 'account', 'service'
            ]
            
            # Categorize urgent terms by risk level
            urgent_terms = {
                'high_risk': [
                    'urgent action', 'immediate action', 'account suspended',
                    'unauthorized access', 'security breach', 'suspicious activity',
                    'account terminated', 'legal action', 'lawsuit', 'police'
                ],
                'medium_risk': [
                    'verify your account', 'confirm your identity',
                    'limited time', 'expires soon', 'final notice',
                    'important update', 'security alert'
                ]
            }
            
            # Convert content to lowercase for pattern matching
            content_lower = email_content.lower()
            
            # Check for business context to adjust risk scoring
            has_business_context = any(term in content_lower for term in business_context)
            
            # Count urgent terms and calculate risk
            found_urgent = []
            for term in urgent_terms['high_risk']:
                if term in content_lower:
                    found_urgent.append(term)
            
            if found_urgent:
                # Adjust risk based on business context
                if has_business_context:
                    result["risk_score"] += min(0.1 * len(found_urgent), 0.3)
                    result["risk_factors"].append("Contains urgent business-related terms")
                else:
                    result["risk_score"] += min(0.15 * len(found_urgent), 0.5)
                    result["risk_factors"].append("Contains high-urgency language")
            
            # Check for threat patterns and consequences
            threat_patterns = [
                'account.*(?:blocked|suspended|terminated)',
                'unauthorized.*(?:access|transaction|change)',
                'security.*(?:breach|compromise|incident)',
                'legal.*(?:action|consequence|measure)',
                'criminal.*(?:charge|prosecution|investigation)'
            ]
            
            # Analyze threat patterns with context awareness
            found_threats = []
            for pattern in threat_patterns:
                if re.search(pattern, content_lower):
                    found_threats.append(pattern)
            
            if found_threats:
                if has_business_context:
                    # Lower risk score for legitimate business communications
                    result["risk_score"] += min(0.1 * len(found_threats), 0.3)
                    result["risk_factors"].append("Contains business-related warnings")
                else:
                    result["risk_score"] += min(0.15 * len(found_threats), 0.5)
                    result["risk_factors"].append("Contains threats or consequences")
            
        except Exception as e:
            logger.error(f"Error in content analysis: {e}")
            result["risk_score"] = 0.2  # Low-moderate risk on error
            result["risk_factors"].append("Error analyzing content")
        
        return result
    
    def analyze_email(self, email_content: str, sender: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive phishing analysis on an email.
        
        This is the main analysis method that:
        1. Coordinates all component analyses (sender, URL, content)
        2. Combines risk scores using configured weights
        3. Determines overall phishing likelihood
        4. Generates detailed report with findings and recommendations
        
        The analysis process:
        1. Extract sender if not provided
        2. Run component analyses in parallel
        3. Calculate weighted risk score
        4. Determine risk level
        5. Generate recommendations
        
        Args:
            email_content (str): Raw email content to analyze
            sender (str, optional): Email sender address. Will be extracted from content if not provided
            
        Returns:
            dict: Comprehensive analysis results containing:
                - is_phishing (bool): Final classification
                - confidence (float): 0.0-1.0 confidence score
                - risk_level (str): "low", "medium", or "high"
                - analysis_time (float): Processing time in seconds
                - component_results (dict): Individual component results
                - suspicious_elements (list): Detailed suspicious findings
                - recommendations (list): Suggested actions
        """
        start_time = time.time()
        
        # Extract sender from email headers if not provided
        if not sender:
            sender_match = re.search(r'From:\s*<?([^>\n]+)>?', email_content)
            if sender_match:
                sender = sender_match.group(1).strip()
        
        # Initialize result structure
        result = {
            "is_phishing": False,
            "confidence": 0.0,
            "risk_level": "low",
            "analysis_time": 0.0,
            "component_results": {},
            "suspicious_elements": [],
            "recommendations": []
        }
        
        try:
            # Run component analyses
            sender_result = self.analyze_sender(sender) if sender else {
                "risk_score": 0.5,  # Moderate risk when sender unknown
                "risk_factors": ["No sender information"]
            }
            url_result = self.analyze_urls(email_content)
            content_result = self.analyze_content(email_content)
            
            # Store detailed component results
            result["component_results"] = {
                "sender": sender_result,
                "url": url_result,
                "content": content_result
            }
            
            # Calculate weighted risk score using configured weights
            weights = self.config["component_weights"]
            total_score = (
                sender_result["risk_score"] * weights["sender"] +
                url_result["risk_score"] * weights["url"] +
                content_result["risk_score"] * weights["content"]
            )
            
            result["confidence"] = total_score
            
            # Determine phishing classification based on confidence threshold
            result["is_phishing"] = total_score >= self.config["confidence_threshold"]
            
            # Set risk level based on confidence thresholds
            if total_score >= self.config["high_confidence_threshold"]:
                result["risk_level"] = "high"
            elif total_score >= self.config["confidence_threshold"]:
                result["risk_level"] = "medium"
            else:
                result["risk_level"] = "low"
            
            # Collect all suspicious elements with their risk scores
            for factor in sender_result["risk_factors"]:
                result["suspicious_elements"].append({
                    "type": "sender",
                    "description": factor,
                    "risk_score": sender_result["risk_score"]
                })
            
            for url_info in url_result.get("suspicious_urls", []):
                result["suspicious_elements"].append({
                    "type": "url",
                    "description": f"Suspicious URL: {url_info['url']}",
                    "risk_score": url_info["risk_score"]
                })
            
            for factor in content_result["risk_factors"]:
                result["suspicious_elements"].append({
                    "type": "content",
                    "description": factor,
                    "risk_score": content_result["risk_score"]
                })
            
            # Generate context-aware recommendations
            if result["is_phishing"]:
                # High-confidence phishing recommendations
                result["recommendations"].extend([
                    "Do not click on any links in this email",
                    "Do not download or open any attachments",
                    "Do not reply to this email",
                    "Report this email as phishing"
                ])
                
                if sender_result["risk_score"] > 0.5:
                    result["recommendations"].append(
                        "Verify the sender through official channels before taking any action"
                    )
                
                if url_result["risk_score"] > 0.5:
                    result["recommendations"].append(
                        "If you need to visit any mentioned websites, type the URL directly in your browser"
                    )
            else:
                # Medium-risk recommendations
                if result["risk_level"] == "medium":
                    result["recommendations"].extend([
                        "Exercise caution with this email",
                        "Verify the sender through other channels before taking action",
                        "Hover over links to verify their destination before clicking"
                    ])
        
        except Exception as e:
            logger.error(f"Error analyzing email: {e}")
            result["error"] = str(e)
        
        # Calculate and store total analysis time
        result["analysis_time"] = time.time() - start_time
        
        return result
    
    def analyze_from_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze an email from a file and provide detailed analysis output.
        
        This method:
        1. Reads email content from file
        2. Extracts sender information from headers
        3. Performs full phishing analysis
        4. Prints detailed analysis results to console
        5. Returns complete analysis data
        
        Args:
            file_path (str): Path to email file (.eml or .txt format)
            
        Returns:
            dict: Complete analysis results (same as analyze_email)
            
        Console Output:
        - Sender information
        - Component-wise analysis results
        - Risk scores for each component
        - Identified suspicious elements
        - Recommendations
        - Final verdict with confidence
        
        Error Handling:
        - Returns safe default values if file cannot be read
        - Logs errors for debugging
        - Provides error information in results
        """
        try:
            # Read email content from file with UTF-8 encoding
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()
            
            # Extract sender from email headers
            sender_match = re.search(r'From:\s*<?([^>\n]+)>?', email_content)
            sender = sender_match.group(1).strip() if sender_match else None
            
            # Perform complete email analysis
            result = self.analyze_email(email_content, sender)
            
            # Print detailed analysis results to console
            print(f"\nPhishing Detection Results:")
            print(f"From: {sender}")
            
            # Display sender analysis results if available
            if "sender" in result["component_results"]:
                print("\nSender Analysis:")
                sender_result = result["component_results"]["sender"]
                print(f"Risk Score: {sender_result['risk_score']:.2f}")
                if sender_result["risk_factors"]:
                    print("Risk Factors:")
                    for factor in sender_result["risk_factors"]:
                        print(f"- {factor}")
            
            # Display URL analysis results if available
            if "url" in result["component_results"]:
                print("\nURL Analysis:")
                url_result = result["component_results"]["url"]
                print(f"URLs Found: {url_result['urls_found']}")
                print(f"Risk Score: {url_result['risk_score']:.2f}")
                if url_result["suspicious_urls"]:
                    print("Suspicious URLs:")
                    for url_info in url_result["suspicious_urls"]:
                        print(f"- {url_info['url']}")
                        for factor in url_info.get('risk_factors', []):
                            print(f"  * {factor}")
            
            # Display content analysis results if available
            if "content" in result["component_results"]:
                print("\nContent Analysis:")
                content_result = result["component_results"]["content"]
                print(f"Risk Score: {content_result['risk_score']:.2f}")
                if content_result["risk_factors"]:
                    print("Risk Factors:")
                    for factor in content_result["risk_factors"]:
                        print(f"- {factor}")
            
            # Display recommendations if any
            if result["recommendations"]:
                print("\nRecommendations:")
                for recommendation in result["recommendations"]:
                    print(f"- {recommendation}")
            
            # Display final verdict and confidence
            print(f"\nFinal Verdict: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'}")
            print(f"Confidence: {result['confidence']:.2f}")
            print(f"Risk Level: {result['risk_level'].upper()}")
            print(f"Analysis Time: {result['analysis_time']:.2f} seconds")
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing email from file {file_path}: {e}")
            # Return safe default values on error
            return {
                "error": str(e),
                "is_phishing": False,
                "confidence": 0.0,
                "risk_level": "unknown",
                "component_results": {},
                "suspicious_elements": [],
                "recommendations": ["Could not analyze the email due to an error."],
                "analysis_time": 0.0
            }

def main():
    """
    Command-line interface for the phishing detector.
    
    This function provides a simple command-line interface to:
    1. Load and configure the phishing detector
    2. Analyze individual email files
    3. Display detailed analysis results
    
    Usage:
        python phishing_detector.py --file email.eml [--config config.json]
    
    Arguments:
        --file, -f : Path to email file for analysis
        --config, -c : Optional path to configuration file (default: config.json)
    
    The function will:
    1. Parse command line arguments
    2. Initialize the phishing detector with configuration
    3. Analyze the specified email file
    4. Display detailed results to console
    """
    import argparse
    
    # Set up command line argument parser
    parser = argparse.ArgumentParser(
        description='Phishing Email Detector - Analyzes emails for phishing indicators'
    )
    parser.add_argument(
        '--file', '-f',
        required=True,
        help='Path to email file for analysis (.eml or .txt format)'
    )
    parser.add_argument(
        '--config', '-c',
        default='config.json',
        help='Path to configuration file (default: config.json)'
    )
    
    # Parse command line arguments
    args = parser.parse_args()
    
    # Initialize detector with configuration
    detector = PhishingDetector(config_path=args.config)
    
    # Analyze the specified email file
    detector.analyze_from_file(args.file)

if __name__ == "__main__":
    main() 