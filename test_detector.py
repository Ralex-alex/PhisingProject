from enhanced_phishing_detector import EnhancedPhishingDetector

def main():
    # Initialize the detector with minimal configuration
    detector = EnhancedPhishingDetector(
        config_path="phishing_detector_config.json",
        history_db_path="email_history.csv",
        examples_path="phishing_examples.json"
    )
    
    # Read the test email
    with open("test_email.eml", 'r', encoding='utf-8', errors='ignore') as f:
        email_content = f.read()
    
    # Extract sender and recipient
    import re
    sender_match = re.search(r'From:\s*<?([^>\n]+)>?', email_content)
    sender = sender_match.group(1).strip() if sender_match else None
    
    recipient_match = re.search(r'To:\s*<?([^>\n]+)>?', email_content)
    recipient = recipient_match.group(1).strip() if recipient_match else None
    
    print(f"Analyzing email from: {sender} to: {recipient}")
    
    # Analyze just the sender
    sender_result = detector.sender_analyzer.analyze_sender(sender, email_content)
    print("\nSender Analysis:")
    print(f"Risk score: {sender_result['risk_score']:.2f}")
    if 'risk_factors' in sender_result:
        print("Risk factors:")
        for factor in sender_result['risk_factors']:
            print(f"- {factor}")
    
    # Analyze URLs
    url_result = detector.url_analyzer.analyze_email_urls(email_content)
    print("\nURL Analysis:")
    print(f"URLs found: {url_result.get('urls_found', 0)}")
    print(f"Risk score: {url_result.get('overall_risk_score', 0):.2f}")
    
    # Print overall assessment
    print("\nOverall Assessment:")
    if sender_result['risk_score'] > 0.5 or url_result.get('overall_risk_score', 0) > 0.5:
        print("This email is likely PHISHING")
    else:
        print("This email appears to be legitimate")

if __name__ == "__main__":
    main() 