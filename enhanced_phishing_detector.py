import os
import sys
import json
import logging
import argparse
import pandas as pd
import numpy as np
import re
from typing import Dict, Any, List, Optional, Union
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set a fixed random seed for reproducibility
np.random.seed(42)

# Import all the analysis components
try:
    from sender_analysis import SenderAnalyzer
    from image_analysis import ImageAnalyzer
    from behavioral_analysis import BehavioralAnalyzer
    from url_analysis import URLAnalyzer
    from advanced_llm_analysis import AdvancedLLMAnalyzer
    from vector_db_integration import PhishingVectorDBManager, find_similar_phishing_emails, record_email_feedback
except ImportError as e:
    print(f"Error importing analysis components: {e}")
    print("Make sure all required modules are installed and in the correct path.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("phishing_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("enhanced_phishing_detector")

class EnhancedPhishingDetector:
    """
    Comprehensive phishing detection system that integrates multiple analysis components:
    - Sender analysis (domain reputation, SPF/DKIM/DMARC)
    - Image analysis (logo detection, manipulation detection)
    - Behavioral analysis (sending time, geographic origin, communication history)
    - URL analysis (domain analysis, redirect chains)
    - Advanced LLM analysis for complex cases
    - Vector database for finding similar known phishing attempts
    """
    
    def __init__(self, 
                 config_path: str = "phishing_detector_config.json",
                 history_db_path: str = "email_history.csv",
                 examples_path: str = "phishing_examples.json",
                 logo_db_path: str = "logo_database",
                 openai_api_key: Optional[str] = None,
                 llm_model_name: str = "sentence-transformers/all-mpnet-base-v2",
                 use_openai: bool = False):
        """
        Initialize the enhanced phishing detector.
        
        Args:
            config_path (str): Path to configuration file
            history_db_path (str): Path to email history database
            examples_path (str): Path to phishing examples database
            logo_db_path (str): Path to logo database directory
            openai_api_key (str): OpenAI API key for advanced LLM analysis
            llm_model_name (str): Name of the LLM model to use
            use_openai (bool): Whether to use OpenAI API for analysis
        """
        self.config = self._load_config(config_path)
        
        # Initialize analysis components
        logger.info("Initializing analysis components...")
        
        # Create necessary directories
        os.makedirs(logo_db_path, exist_ok=True)
        os.makedirs("models", exist_ok=True)
        
        # Initialize components with error handling
        try:
            self.sender_analyzer = SenderAnalyzer()
            logger.info("Sender analyzer initialized")
        except Exception as e:
            logger.error(f"Error initializing sender analyzer: {e}")
            self.sender_analyzer = None
        
        try:
            self.image_analyzer = ImageAnalyzer(logo_db_path=logo_db_path)
            logger.info("Image analyzer initialized")
        except Exception as e:
            logger.error(f"Error initializing image analyzer: {e}")
            self.image_analyzer = None
        
        try:
            self.behavioral_analyzer = BehavioralAnalyzer(history_db_path=history_db_path)
            logger.info("Behavioral analyzer initialized")
        except Exception as e:
            logger.error(f"Error initializing behavioral analyzer: {e}")
            self.behavioral_analyzer = None
        
        try:
            self.url_analyzer = URLAnalyzer(
                max_redirects=self.config.get("max_redirects", 5),
                timeout=self.config.get("url_timeout", 3)
            )
            logger.info("URL analyzer initialized")
        except Exception as e:
            logger.error(f"Error initializing URL analyzer: {e}")
            self.url_analyzer = None
        
        try:
            self.llm_analyzer = AdvancedLLMAnalyzer(
                model_name=llm_model_name,
                api_key=openai_api_key,
                examples_path=examples_path,
                use_openai=use_openai
            )
            logger.info("LLM analyzer initialized")
        except Exception as e:
            logger.error(f"Error initializing LLM analyzer: {e}")
            self.llm_analyzer = None
        
        try:
            self.vector_db_manager = PhishingVectorDBManager.get_instance(
                model_name=llm_model_name
            )
            logger.info("Vector database initialized")
        except Exception as e:
            logger.error(f"Error initializing vector database: {e}")
            self.vector_db_manager = None
        
        # Set thresholds from config
        self.confidence_threshold = self.config.get("confidence_threshold", 0.5)
        self.llm_threshold = self.config.get("llm_threshold", 0.3)
        self.high_confidence_threshold = self.config.get("high_confidence_threshold", 0.8)
        self.vector_similarity_threshold = self.config.get("vector_similarity_threshold", 0.7)
        
        # Check if at least basic components are available
        if not (self.sender_analyzer and self.url_analyzer):
            logger.warning("Basic analysis components (sender, URL) failed to initialize")
        else:
            logger.info("Enhanced phishing detector initialized successfully")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from JSON file.
        
        Args:
            config_path (str): Path to configuration file
            
        Returns:
            dict: Configuration dictionary
        """
        default_config = {
            "confidence_threshold": 0.5,
            "llm_threshold": 0.3,
            "high_confidence_threshold": 0.8,
            "vector_similarity_threshold": 0.7,
            "max_redirects": 5,
            "url_timeout": 3,
            "parallel_analysis": True,
            "save_history": True,
            "component_weights": {
                "sender": 0.25,
                "image": 0.15,
                "behavioral": 0.2,
                "url": 0.25,
                "llm": 0.1,
                "vector_similarity": 0.05
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {config_path}")
                
                # Merge with default config to ensure all keys exist
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                
                return config
            else:
                logger.warning(f"Configuration file not found: {config_path}")
                logger.info("Using default configuration")
                return default_config
                
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return default_config
    
    def analyze_email(self, 
                     email_content: str, 
                     sender: Optional[str] = None,
                     recipient: Optional[str] = None,
                     extract_sender: bool = True) -> Dict[str, Any]:
        """
        Analyze an email for phishing indicators.
        
        Args:
            email_content (str): Raw email content
            sender (str): Email sender (optional, will be extracted if not provided)
            recipient (str): Email recipient (optional)
            extract_sender (bool): Whether to extract sender from email content
            
        Returns:
            dict: Analysis results
        """
        start_time = time.time()
        
        # Extract sender from email content if not provided
        if not sender and extract_sender:
            sender_match = re.search(r'From:\s*<?([^>\n]+)>?', email_content)
            if sender_match:
                sender = sender_match.group(1).strip()
        
        # Initialize result dictionary
        result = {
            "is_phishing": False,
            "confidence": 0.0,
            "analysis_time": 0.0,
            "risk_level": "low",
            "component_results": {},
            "suspicious_elements": [],
            "recommendations": [],
            "similar_phishing_emails": []
        }
        
        try:
            # Run analysis components in parallel if enabled
            if self.config.get("parallel_analysis", True):
                component_results = self._parallel_analysis(email_content, sender, recipient)
            else:
                component_results = self._sequential_analysis(email_content, sender, recipient)
            
            # Store component results
            result["component_results"] = component_results
            
            # Calculate overall phishing probability (weighted average)
            weights = self.config.get("component_weights", {
                "sender": 0.25,
                "image": 0.15,
                "behavioral": 0.2,
                "url": 0.25,
                "llm": 0.1,
                "vector_similarity": 0.05
            })
            
            # Extract risk scores from each component
            component_scores = {}
            
            # Only include scores from components that were successfully initialized and analyzed
            if "sender" in component_results and self.sender_analyzer:
                component_scores["sender"] = component_results["sender"].get("risk_score", 0.0)
                
            if "image" in component_results and self.image_analyzer:
                component_scores["image"] = component_results["image"].get("overall_risk_score", 0.0)
                
            if "behavioral" in component_results and self.behavioral_analyzer:
                component_scores["behavioral"] = component_results["behavioral"].get("risk_score", 0.0)
                
            if "url" in component_results and self.url_analyzer:
                component_scores["url"] = component_results["url"].get("overall_risk_score", 0.0)
            
            # First-stage analysis (without LLM)
            weighted_score = 0.0
            total_weight = 0.0
            
            for component, score in component_scores.items():
                if component in weights:
                    weighted_score += score * weights[component]
                    total_weight += weights[component]
            
            if total_weight > 0:
                first_stage_score = weighted_score / total_weight
            else:
                first_stage_score = 0.5  # Default if no components available
            
            # Determine if we need LLM analysis (borderline cases)
            need_llm = (
                abs(first_stage_score - 0.5) < self.llm_threshold and
                self.llm_analyzer is not None
            )
            
            # Run LLM analysis if needed and available
            if need_llm and self.llm_analyzer:
                try:
                    llm_result = self.llm_analyzer.analyze_email(email_content)
                    component_results["llm"] = llm_result
                    
                    # Add LLM score to component scores
                    if "phishing_probability" in llm_result:
                        component_scores["llm"] = llm_result["phishing_probability"]
                except Exception as e:
                    logger.error(f"Error in LLM analysis: {e}")
            
            # Check for similar phishing emails if vector database is available
            if self.vector_db_manager:
                try:
                    similar_emails = find_similar_phishing_emails(
                        email_content, 
                        k=5, 
                        threshold=self.vector_similarity_threshold
                    )
                    
                    # Add similarity score if we found similar phishing emails
                    if similar_emails and isinstance(similar_emails, list) and len(similar_emails) > 0:
                        # Convert any non-list results to a list
                        if not isinstance(similar_emails, list):
                            similar_emails = [similar_emails]
                        
                        # Extract similarity scores safely
                        similarities = []
                        for email in similar_emails:
                            if isinstance(email, dict) and 'similarity' in email:
                                similarities.append(email['similarity'])
                        
                        if similarities:
                            max_similarity = max(similarities)
                            component_scores["vector_similarity"] = max_similarity
                            result["similar_phishing_emails"] = similar_emails
                except Exception as e:
                    logger.error(f"Error in vector similarity analysis: {e}")
            
            # Recalculate overall score with all available components
            weighted_score = 0.0
            total_weight = 0.0
            
            for component, score in component_scores.items():
                if component in weights and isinstance(score, (int, float)):
                    weighted_score += score * weights[component]
                    total_weight += weights[component]
            
            if total_weight > 0:
                result["confidence"] = weighted_score / total_weight
            else:
                result["confidence"] = first_stage_score
            
            # Determine if the email is phishing based on confidence
            result["is_phishing"] = result["confidence"] >= self.confidence_threshold
            
            # Determine risk level
            if result["confidence"] >= self.high_confidence_threshold:
                result["risk_level"] = "high"
            elif result["confidence"] >= self.confidence_threshold:
                result["risk_level"] = "medium"
            else:
                result["risk_level"] = "low"
            
            # Collect suspicious elements from available components
            suspicious_elements = []
            
            # From sender analysis
            if "sender" in component_results and "risk_factors" in component_results["sender"]:
                risk_factors = component_results["sender"]["risk_factors"]
                if isinstance(risk_factors, list):
                    for factor in risk_factors:
                        suspicious_elements.append({
                            "type": "sender",
                            "description": factor,
                            "risk_score": component_results["sender"].get("risk_score", 0.0)
                        })
            
            # From URL analysis
            if "url" in component_results and "suspicious_urls" in component_results["url"]:
                suspicious_urls = component_results["url"]["suspicious_urls"]
                if isinstance(suspicious_urls, list):
                    for url_info in suspicious_urls:
                        if isinstance(url_info, dict):
                            suspicious_elements.append({
                                "type": "url",
                                "description": f"Suspicious URL: {url_info.get('url', 'unknown')}",
                                "risk_score": url_info.get("risk_score", 0.7)
                            })
            
            # Sort suspicious elements by risk score
            suspicious_elements.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
            result["suspicious_elements"] = suspicious_elements
            
            # Generate recommendations
            result["recommendations"] = self._generate_recommendations(result, component_results)
            
        except Exception as e:
            logger.error(f"Error analyzing email: {e}")
            result["error"] = str(e)
        
        # Calculate analysis time
        result["analysis_time"] = time.time() - start_time
        
        return result
    
    def _parallel_analysis(self, 
                          email_content: str, 
                          sender: Optional[str], 
                          recipient: Optional[str]) -> Dict[str, Any]:
        """
        Run analysis components in parallel using ThreadPoolExecutor.
        
        Args:
            email_content (str): Email content
            sender (str): Email sender
            recipient (str): Email recipient
            
        Returns:
            dict: Component results
        """
        component_results = {}
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            
            # Submit tasks only for initialized components
            if self.sender_analyzer and sender:
                futures['sender'] = executor.submit(
                    self.sender_analyzer.analyze_sender,
                    sender,
                    email_content
                )
            
            if self.image_analyzer:
                futures['image'] = executor.submit(
                    self.image_analyzer.analyze_email_images,
                    email_content
                )
            
            if self.behavioral_analyzer and sender and recipient:
                futures['behavioral'] = executor.submit(
                    self.behavioral_analyzer.analyze_behavior,
                    email_content,
                    sender,
                    recipient
                )
            
            if self.url_analyzer:
                futures['url'] = executor.submit(
                    self.url_analyzer.analyze_email_urls,
                    email_content
                )
            
            # Collect results as they complete
            for component, future in futures.items():
                try:
                    component_results[component] = future.result()
                except Exception as e:
                    logger.error(f"Error in {component} analysis: {e}")
                    # Provide default result structure for failed components
                    if component == 'sender':
                        component_results[component] = {
                            "risk_score": 0.5,
                            "risk_factors": [f"Analysis failed: {str(e)}"],
                            "authentication": {"status": "unknown"}
                        }
                    elif component == 'url':
                        component_results[component] = {
                            "urls_found": 0,
                            "overall_risk_score": 0.5,
                            "suspicious_urls": []
                        }
                    elif component == 'image':
                        component_results[component] = {
                            "overall_risk_score": 0.0,
                            "risk_factors": [],
                            "images_found": 0
                        }
                    elif component == 'behavioral':
                        component_results[component] = {
                            "risk_score": 0.5,
                            "risk_factors": [],
                            "anomalies": []
                        }
        
        return component_results
    
    def _sequential_analysis(self, 
                            email_content: str, 
                            sender: Optional[str], 
                            recipient: Optional[str]) -> Dict[str, Any]:
        """
        Run analysis components sequentially.
        
        Args:
            email_content (str): Email content
            sender (str): Email sender
            recipient (str): Email recipient
            
        Returns:
            dict: Component results
        """
        component_results = {}
        
        # Sender analysis
        if sender:
            try:
                component_results["sender"] = self.sender_analyzer.analyze_sender(sender, email_content)
            except Exception as e:
                logger.error(f"Error in sender analysis: {e}")
        
        # Image analysis
        try:
            component_results["image"] = self.image_analyzer.analyze_email_images(email_content)
        except Exception as e:
            logger.error(f"Error in image analysis: {e}")
        
        # Behavioral analysis
        if sender and recipient:
            try:
                component_results["behavioral"] = self.behavioral_analyzer.analyze_behavior(
                    email_content, sender, recipient
                )
            except Exception as e:
                logger.error(f"Error in behavioral analysis: {e}")
        
        # URL analysis
        try:
            component_results["url"] = self.url_analyzer.analyze_email_urls(email_content)
        except Exception as e:
            logger.error(f"Error in URL analysis: {e}")
        
        return component_results
    
    def _generate_recommendations(self, 
                                result: Dict[str, Any], 
                                component_results: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations based on analysis results.
        
        Args:
            result (dict): Overall analysis result
            component_results (dict): Component results
            
        Returns:
            list: Recommendations
        """
        recommendations = []
        
        # If phishing is detected, add general recommendations
        if result["is_phishing"]:
            recommendations.append("Do not click on any links in this email")
            recommendations.append("Do not download or open any attachments")
            recommendations.append("Do not reply to this email")
            
            # Add specific recommendations based on components
            
            # Sender recommendations
            if "sender" in component_results:
                sender_result = component_results["sender"]
                
                if "domain_age" in sender_result and sender_result["domain_age"].get("is_new_domain", False):
                    recommendations.append("This email is from a newly registered domain, which is suspicious")
                
                if "authentication" in sender_result and sender_result["authentication"].get("authentication_status") == "fail":
                    recommendations.append("This email failed authentication checks (SPF/DKIM/DMARC)")
            
            # URL recommendations
            if "url" in component_results and component_results["url"].get("has_suspicious_urls", False):
                recommendations.append("Verify any mentioned organizations through official channels, not through links in this email")
            
            # Similar phishing recommendations
            if result["similar_phishing_emails"]:
                recommendations.append("This email is similar to known phishing attempts in our database")
        else:
            # Low risk but still some concerns
            if result["risk_level"] == "medium":
                recommendations.append("Exercise caution with this email")
                recommendations.append("Verify the sender through other channels before taking action")
            
            # Specific recommendations for legitimate but potentially concerning emails
            if "url" in component_results and component_results["url"].get("url_count", 0) > 0:
                recommendations.append("Hover over links to verify their destination before clicking")
        
        return recommendations
    
    def _update_history(self, 
                       email_content: str, 
                       sender: str, 
                       recipient: str, 
                       is_phishing: bool):
        """
        Update email history database.
        
        Args:
            email_content (str): Email content
            sender (str): Email sender
            recipient (str): Email recipient
            is_phishing (bool): Whether the email is phishing
        """
        try:
            # Extract metadata from email
            headers_match = re.search(r'^(.*?)\r?\n\r?\n', email_content, re.DOTALL)
            headers = headers_match.group(1) if headers_match else ""
            
            # Extract subject
            subject_match = re.search(r'Subject:\s*(.+)(?:\r?\n[^\s]|\r?\n\s*\r?\n|$)', headers)
            subject = subject_match.group(1) if subject_match else ""
            
            # Extract timestamp
            date_match = re.search(r'Date:\s*(.+)(?:\r?\n[^\s]|\r?\n\s*\r?\n|$)', headers)
            timestamp = date_match.group(1) if date_match else time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Update behavioral analyzer history
            self.behavioral_analyzer._update_history(
                sender=sender,
                recipient=recipient,
                metadata={
                    "subject": subject,
                    "timestamp": timestamp,
                    "is_phishing": is_phishing
                }
            )
            
            # Save history to disk
            self.behavioral_analyzer.save_history("email_history.csv")
        
        except Exception as e:
            logger.error(f"Error updating history: {e}")
    
    def analyze_from_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze an email from a file.
        
        Args:
            file_path (str): Path to email file
            
        Returns:
            dict: Analysis results
        """
        try:
            # Read email from file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()
            
            # Extract sender and recipient from email content
            sender_match = re.search(r'From:\s*<?([^>\n]+)>?', email_content)
            sender = sender_match.group(1).strip() if sender_match else None
            
            recipient_match = re.search(r'To:\s*<?([^>\n]+)>?', email_content)
            recipient = recipient_match.group(1).strip() if recipient_match else None
            
            # Analyze the email
            result = self.analyze_email(
                email_content=email_content,
                sender=sender,
                recipient=recipient,
                extract_sender=False
            )
            
            # Print detailed analysis results
            print(f"\nDetailed Analysis Results:")
            print(f"From: {sender}")
            if recipient:
                print(f"To: {recipient}")
            
            if "component_results" in result:
                if "sender" in result["component_results"]:
                    print("\nSender Analysis:")
                    sender_result = result["component_results"]["sender"]
                    print(f"Risk Score: {sender_result.get('risk_score', 0.0):.2f}")
                    if "risk_factors" in sender_result:
                        print("Risk Factors:")
                        for factor in sender_result["risk_factors"]:
                            print(f"- {factor}")
                
                if "url" in result["component_results"]:
                    print("\nURL Analysis:")
                    url_result = result["component_results"]["url"]
                    print(f"URLs Found: {url_result.get('urls_found', 0)}")
                    print(f"Risk Score: {url_result.get('overall_risk_score', 0.0):.2f}")
                    if "suspicious_urls" in url_result:
                        print("Suspicious URLs:")
                        for url_info in url_result["suspicious_urls"]:
                            print(f"- {url_info.get('url', 'Unknown URL')}")
            
            if result["suspicious_elements"]:
                print("\nSuspicious Elements:")
                for element in result["suspicious_elements"]:
                    print(f"- {element['description']} (Risk: {element['risk_score']:.2f})")
            
            if result["recommendations"]:
                print("\nRecommendations:")
                for recommendation in result["recommendations"]:
                    print(f"- {recommendation}")
            
            print(f"\nFinal Verdict: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'}")
            print(f"Confidence: {result['confidence']:.2f}")
            print(f"Risk Level: {result['risk_level'].upper()}")
            print(f"Analysis Time: {result['analysis_time']:.2f} seconds")
            
            return result
        
        except Exception as e:
            logger.error(f"Error analyzing email from file {file_path}: {e}")
            # Return a default result in case of error
            return {
                "error": str(e),
                "is_phishing": False,
                "confidence": 0.0,
                "risk_level": "unknown",
                "component_results": {},
                "suspicious_elements": [],
                "recommendations": ["Could not analyze the email due to an error."],
                "similar_phishing_emails": [],
                "analysis_time": 0.0
            }
    
    def analyze_batch(self, 
                     emails: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Analyze a batch of emails.
        
        Args:
            emails (list): List of email dictionaries with 'content', 'sender', and 'recipient'
            
        Returns:
            list: List of analysis results
        """
        results = []
        
        for email in emails:
            content = email.get('content', '')
            sender = email.get('sender')
            recipient = email.get('recipient')
            
            result = self.analyze_email(
                email_content=content,
                sender=sender,
                recipient=recipient
            )
            
            results.append(result)
        
        return results
    
    def train_vector_database(self, csv_path: str, content_column: str, label_column: str) -> bool:
        """
        Train the vector database with a dataset of emails.
        
        Args:
            csv_path (str): Path to CSV file
            content_column (str): Name of column containing email content
            label_column (str): Name of column containing phishing labels (1=phishing, 0=legitimate)
            
        Returns:
            bool: Success or failure
        """
        try:
            # Get vector database instance
            db_manager = PhishingVectorDBManager.get_instance()
            
            # Import emails from CSV
            successful, total = db_manager.db.import_from_csv(
                csv_path=csv_path,
                content_column=content_column,
                label_column=label_column
            )
            
            logger.info(f"Imported {successful}/{total} emails to vector database")
            return successful > 0
        except Exception as e:
            logger.error(f"Error training vector database: {e}")
            return False

def main():
    """
    Main function for command-line usage.
    """
    parser = argparse.ArgumentParser(description='Enhanced Phishing Email Detector')
    
    parser.add_argument('--file', '-f', help='Path to email file for analysis')
    parser.add_argument('--config', '-c', default='phishing_detector_config.json', help='Path to configuration file')
    parser.add_argument('--history', default='email_history.csv', help='Path to email history database')
    parser.add_argument('--examples', default='phishing_examples.json', help='Path to phishing examples database')
    parser.add_argument('--logos', default='logo_database', help='Path to logo database directory')
    parser.add_argument('--api-key', help='OpenAI API key for advanced LLM analysis')
    parser.add_argument('--model', default='sentence-transformers/all-mpnet-base-v2', help='Name of the LLM model to use')
    parser.add_argument('--use-openai', action='store_true', help='Whether to use OpenAI API for analysis')
    parser.add_argument('--train-vector-db', help='Train vector database with CSV file')
    parser.add_argument('--content-column', default='content', help='Name of column containing email content')
    parser.add_argument('--label-column', default='is_phishing', help='Name of column containing phishing labels')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = EnhancedPhishingDetector(
        config_path=args.config,
        history_db_path=args.history,
        examples_path=args.examples,
        logo_db_path=args.logos,
        openai_api_key=args.api_key,
        llm_model_name=args.model,
        use_openai=args.use_openai
    )
    
    # Train vector database if requested
    if args.train_vector_db:
        success = detector.train_vector_database(
            csv_path=args.train_vector_db,
            content_column=args.content_column,
            label_column=args.label_column
        )
        
        if success:
            print("Vector database training completed successfully")
        else:
            print("Vector database training failed")
        
        return
    
    # Analyze email file if provided
    if args.file:
        result = detector.analyze_from_file(args.file)
        
        # Print result
        print(f"Phishing detection result: {'PHISHING' if result['is_phishing'] else 'LEGITIMATE'}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Risk level: {result['risk_level'].upper()}")
        print(f"Analysis time: {result['analysis_time']:.2f} seconds")
        
        if result["suspicious_elements"]:
            print("\nSuspicious elements:")
            for element in result["suspicious_elements"]:
                print(f"- {element['description']} (Risk: {element['risk_score']:.2f})")
        
        if result["recommendations"]:
            print("\nRecommendations:")
            for recommendation in result["recommendations"]:
                print(f"- {recommendation}")
        
        if result["similar_phishing_emails"]:
            print("\nSimilar known phishing emails:")
            for email in result["similar_phishing_emails"]:
                print(f"- Similarity: {email['similarity']:.2f}")
                print(f"  Preview: {email['content_preview']}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 