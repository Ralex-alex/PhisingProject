import sys
import logging
import re
from advanced_llm_analysis import AdvancedLLMAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("simple_test")

def analyze_email_content(email_file):
    """
    Simple function to analyze email content with the LLM analyzer
    """
    try:
        # Read email content
        with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
            email_content = f.read()
        
        # Initialize the LLM analyzer
        analyzer = AdvancedLLMAnalyzer()
        
        # Analyze the email
        result = analyzer.analyze_email(email_content)
        
        # Print results
        print(f"\nAnalysis Results for {email_file}:")
        print(f"Phishing Probability: {result['phishing_probability']:.2f}")
        print(f"Confidence: {result['confidence']:.2f}")
        
        if 'indicators' in result and result['indicators']:
            print("\nPhishing Indicators:")
            for indicator in result['indicators']:
                print(f"- {indicator}")
        
        # Make a verdict with a higher threshold
        threshold = 0.60  # Increased threshold to reduce false positives
        verdict = "PHISHING" if result['phishing_probability'] >= threshold else "LEGITIMATE"
        print(f"\nVerdict: {verdict}")
        
        return result
    
    except Exception as e:
        logger.error(f"Error analyzing email: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python simple_test.py <email_file>")
        sys.exit(1)
    
    email_file = sys.argv[1]
    analyze_email_content(email_file) 