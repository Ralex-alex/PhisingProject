import os
import json
import logging
import re
import numpy as np
from typing import Dict, List, Any, Optional
from sentence_transformers import SentenceTransformer

# Set random seed for reproducibility
np.random.seed(42)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("advanced_llm_analysis")

class AdvancedLLMAnalyzer:
    """
    Class for advanced phishing detection using language models.
    Uses sentence transformers for semantic understanding of email content.
    """
    
    def __init__(self, 
                 model_name: str = "sentence-transformers/all-mpnet-base-v2",
                 api_key: Optional[str] = None,
                 examples_path: Optional[str] = None,
                 use_openai: bool = False):
        """
        Initialize the advanced LLM analyzer.
        
        Args:
            model_name (str): Name of the sentence transformer model to use
            api_key (str): API key for OpenAI (if using OpenAI)
            examples_path (str): Path to phishing examples file
            use_openai (bool): Whether to use OpenAI API
        """
        self.model_name = model_name
        self.api_key = api_key
        self.use_openai = use_openai
        
        # Load phishing examples
        self.examples = []
        if examples_path and os.path.exists(examples_path):
            try:
                with open(examples_path, 'r') as f:
                    examples_data = json.load(f)
                    self.examples = examples_data.get('examples', [])
                logger.info(f"Loaded {len(self.examples)} phishing examples")
            except Exception as e:
                logger.error(f"Error loading phishing examples: {e}")
        
        # Initialize sentence transformer model
        try:
            self.model = SentenceTransformer(model_name)
            logger.info(f"Loaded sentence transformer model: {model_name}")
        except Exception as e:
            logger.error(f"Error loading sentence transformer model: {e}")
            self.model = None
    
    def extract_email_content(self, email_raw: str) -> Dict[str, str]:
        """
        Extract subject and body from raw email content.
        
        Args:
            email_raw (str): Raw email content
            
        Returns:
            dict: Extracted subject and body
        """
        result = {
            "subject": "",
            "body": email_raw
        }
        
        try:
            # Extract subject
            subject_match = re.search(r'Subject:\s*(.+?)(?:\r?\n[^\s]|\r?\n\s*\r?\n|$)', email_raw)
            if subject_match:
                result["subject"] = subject_match.group(1).strip()
            
            # Extract body
            body_parts = email_raw.split("\n\n", 1)
            if len(body_parts) > 1:
                result["body"] = body_parts[1].strip()
        
        except Exception as e:
            logger.error(f"Error extracting email content: {e}")
        
        return result
    
    def analyze_with_sentence_transformer(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze email content using sentence transformers.
        
        Args:
            email_content (str): Email content to analyze
            
        Returns:
            dict: Analysis results
        """
        result = {
            "phishing_probability": 0.5,
            "confidence": 0.0,
            "similar_examples": []
        }
        
        try:
            if not self.model or not self.examples:
                return result
            
            # Extract email content
            extracted = self.extract_email_content(email_content)
            
            # Create a combined representation of the email
            email_text = f"{extracted['subject']} {extracted['body']}"
            
            # Encode the email text
            email_embedding = self.model.encode(email_text)
            
            # Compare with examples
            similarities = []
            for example in self.examples:
                example_embedding = self.model.encode(example["content"])
                
                # Calculate cosine similarity
                similarity = self._cosine_similarity(email_embedding, example_embedding)
                
                similarities.append({
                    "content": example["content"],
                    "is_phishing": example["is_phishing"],
                    "similarity": float(similarity),
                    "explanation": example.get("explanation", "")
                })
            
            # Sort by similarity
            similarities.sort(key=lambda x: x["similarity"], reverse=True)
            
            # Get top 3 similar examples
            top_examples = similarities[:3]
            result["similar_examples"] = top_examples
            
            # Calculate phishing probability based on similar examples
            if top_examples:
                # Weighted average based on similarity
                total_weight = 0
                weighted_sum = 0
                
                for example in top_examples:
                    weight = example["similarity"]
                    is_phishing = 1.0 if example["is_phishing"] else 0.0
                    
                    weighted_sum += weight * is_phishing
                    total_weight += weight
                
                if total_weight > 0:
                    result["phishing_probability"] = weighted_sum / total_weight
                
                # Calculate confidence based on similarity of top example
                result["confidence"] = top_examples[0]["similarity"]
        
        except Exception as e:
            logger.error(f"Error analyzing with sentence transformer: {e}")
        
        return result
    
    def _cosine_similarity(self, vec1, vec2):
        """
        Calculate cosine similarity between two vectors.
        
        Args:
            vec1: First vector
            vec2: Second vector
            
        Returns:
            float: Cosine similarity
        """
        import numpy as np
        dot = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0
        
        return float(dot / (norm1 * norm2))  # Convert to float for consistency
    
    def analyze_email(self, email_content: str) -> Dict[str, Any]:
        """
        Comprehensive analysis of an email using LLM.
        
        Args:
            email_content (str): Email content to analyze
            
        Returns:
            dict: Analysis results
        """
        # Use sentence transformer analysis
        result = self.analyze_with_sentence_transformer(email_content)
        
        # Extract phishing indicators from content
        indicators = self._extract_phishing_indicators(email_content)
        
        # Add indicators to result
        result["indicators"] = indicators
        
        # Adjust probability based on indicators
        if indicators:
            # Calculate indicator score based on number and types of indicators
            base_score = min(0.9, len(indicators) * 0.08)  # Cap at 0.9
            
            # Increase score for certain high-risk indicators
            high_risk_count = sum(1 for ind in indicators if 
                               any(phrase in ind.lower() for phrase in 
                                  ['suspicious url', 'verify', 'urgent', 'account', 'password', 'click', 'threat']))
            
            indicator_score = min(0.95, base_score + (high_risk_count * 0.05))
            
            # Blend the scores, giving more weight to indicators if there are many
            weight_factor = min(0.8, len(indicators) * 0.1)  # Cap at 0.8
            result["phishing_probability"] = (result["phishing_probability"] * (1 - weight_factor)) + (indicator_score * weight_factor)
        
        return result
    
    def _extract_phishing_indicators(self, email_content: str) -> List[str]:
        """
        Extract common phishing indicators from email content.
        
        Args:
            email_content (str): Email content
            
        Returns:
            list: Phishing indicators
        """
        indicators = []
        
        # Common phishing phrases - expanded list
        phishing_phrases = [
            r'verify your account',
            r'confirm your (?:identity|account|password)',
            r'your account (?:has been|will be) (?:suspended|limited|restricted)',
            r'unusual activity',
            r'security alert',
            r'click (?:here|the link|below) to (?:verify|confirm)',
            r'limited access',
            r'urgent action required',
            r'failure to (?:verify|confirm|respond)',
            r'your account will be (?:terminated|suspended|closed)',
            r'update (?:your|payment|billing) (?:information|details|method)',
            r'we were unable to process your (?:payment|transaction)',
            r'you have won',
            r'congratulations',
            r'claim your (?:prize|reward|gift)',
            r'suspicious (?:login|activity|sign-in)',
            r'security breach',
            r'unauthorized access',
            r'restore (?:access|account)',
            r'secure your account',
            r'we detected',
            r'we have detected',
            r'we noticed',
            r'immediate(?:ly)? (?:verify|confirm|update)',
            r'account (?:compromised|hacked|at risk)',
            r'personal (?:details|information) (?:required|needed)',
            r'validate your (?:account|information)'
        ]
        
        # Check for phishing phrases
        for phrase in phishing_phrases:
            if re.search(phrase, email_content, re.IGNORECASE):
                indicators.append(f"Contains phishing phrase: '{phrase}'")
        
        # Check for urgency indicators
        urgency_phrases = [
            r'immediate(?:ly)?',
            r'urgent(?:ly)?',
            r'within 24 hours',
            r'within 48 hours',
            r'as soon as possible',
            r'failure to comply',
            r'will result in',
            r'account (?:suspension|termination)',
            r'time(?:-|\s)?sensitive',
            r'expires (?:soon|today|tomorrow)',
            r'limited time',
            r'act now',
            r'immediate attention',
            r'promptly',
            r'without delay',
            r'deadline',
            r'last chance',
            r'final notice',
            r'warning'
        ]
        
        for phrase in urgency_phrases:
            if re.search(phrase, email_content, re.IGNORECASE):
                indicators.append(f"Creates urgency: '{phrase}'")
        
        # Check for suspicious requests
        request_phrases = [
            r'(?:update|confirm) your (?:personal|account) (?:information|details)',
            r'(?:enter|provide|verify) your (?:password|credentials)',
            r'click (?:the|this) link',
            r'download (?:the|this) attachment',
            r'reply with your',
            r'send (?:us|back) your',
            r'fill (?:out|in) the form',
            r'login to your account',
            r'sign in to your account',
            r'verify your identity',
            r'update your payment method',
            r'confirm your billing information',
            r'update your credit card',
            r'provide your (?:social security|tax) number',
            r'enter your (?:PIN|CVV|security code)',
            r'submit your information'
        ]
        
        for phrase in request_phrases:
            if re.search(phrase, email_content, re.IGNORECASE):
                indicators.append(f"Suspicious request: '{phrase}'")
        
        # Check for suspicious URLs
        url_patterns = [
            r'http://(?!www\.)[a-zA-Z0-9-]+\.[a-z]{2,}',  # Non-www domains
            r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',   # IP addresses
            r'https?://.*?\.(?:tk|ga|cf|ml|gq|xyz|top|club)\b',  # Suspicious TLDs
            r'https?://.*?(?:secure|login|account|verify|confirm|update|banking)\.[a-zA-Z0-9-]+\.[a-z]{2,}',  # Suspicious subdomains
            r'https?://.*?(?:verify|confirm|secure|login|account|update|auth|banking)(?:-|_)[a-zA-Z0-9-]+\.[a-z]{2,}'  # Suspicious domain parts
        ]
        
        for pattern in url_patterns:
            urls = re.findall(pattern, email_content, re.IGNORECASE)
            for url in urls:
                indicators.append(f"Suspicious URL: '{url}'")
        
        # Check for poor grammar and spelling (simplified approach)
        grammar_issues = [
            r'\b(?:i|we) (?:is|are|was|were) going\b',
            r'\byou (?:is|am|was) going\b',
            r'\bthey is\b',
            r'\bhe are\b',
            r'\bshe are\b',
            r'\bkindly\b.*\b(?:do|proceed|provide|verify)\b',  # Unusual phrasing common in phishing
            r'\brespond back\b',  # Redundant phrasing
            r'\brevert back\b',   # Redundant phrasing
            r'\bdear (?:valued|esteemed) customer\b',  # Generic greeting
            r'\bdear user\b',     # Generic greeting
            r'\bhello (?:customer|user|client|member)\b'  # Generic greeting
        ]
        
        for issue in grammar_issues:
            if re.search(issue, email_content, re.IGNORECASE):
                indicators.append(f"Poor grammar/phrasing: '{issue}'")
        
        # Check for threats or consequences
        threat_phrases = [
            r'will be (?:suspended|terminated|closed|locked|blocked)',
            r'will (?:lose|restrict) access',
            r'account will be (?:closed|suspended)',
            r'service will be (?:interrupted|suspended|terminated)',
            r'failure to',
            r'if you (?:fail|don\'t|do not) (?:respond|reply|verify|confirm|update)',
            r'avoid (?:suspension|termination|interruption)',
            r'prevent (?:suspension|termination|interruption)',
            r'or (?:else|otherwise)'
        ]
        
        for phrase in threat_phrases:
            if re.search(phrase, email_content, re.IGNORECASE):
                indicators.append(f"Contains threat: '{phrase}'")
                
        # Check for excessive capitalization
        caps_count = len(re.findall(r'\b[A-Z]{2,}\b', email_content))
        if caps_count > 3:
            indicators.append(f"Excessive capitalization: {caps_count} instances")
            
        # Check for excessive exclamation marks
        exclamation_count = email_content.count('!')
        if exclamation_count > 3:
            indicators.append(f"Excessive exclamation marks: {exclamation_count} instances")
        
        return indicators

# Example usage
if __name__ == "__main__":
    analyzer = AdvancedLLMAnalyzer(examples_path="phishing_examples.json")
    
    # Test with a phishing email
    phishing_email = """
    Subject: Urgent: Your Account Will Be Suspended
    
    Dear Customer,
    
    We have detected unusual activity on your account. Your account will be suspended within 24 hours if you do not verify your identity.
    
    Please click the following link to verify your account: http://secure-bank-verification.com
    
    Thank you,
    Security Team
    """
    
    result = analyzer.analyze_email(phishing_email)
    print(f"Phishing probability: {result['phishing_probability']:.2f}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Indicators: {result['indicators']}") 