import unittest
import time
import json
import os
from pathlib import Path
from enhanced_phishing_detector import EnhancedPhishingDetector
from sender_analysis import SenderAnalyzer
from url_analysis import URLAnalyzer
from behavioral_analysis import BehavioralAnalyzer
from image_analysis import ImageAnalyzer

class TestPhishingDetector(unittest.TestCase):
    """Comprehensive test suite for the phishing detection system"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment once before all tests"""
        cls.detector = EnhancedPhishingDetector(
            config_path="phishing_detector_config.json",
            history_db_path="email_history.csv",
            examples_path="phishing_examples.json"
        )
        
        # Create test data directory if it doesn't exist
        Path("test_data").mkdir(exist_ok=True)
        
        # Generate test emails if they don't exist
        cls._generate_test_data()
    
    @classmethod
    def _generate_test_data(cls):
        """Generate test email data"""
        test_emails = {
            "legitimate_1.eml": {
                "sender": "support@amazon.com",
                "recipient": "user@example.com",
                "subject": "Your Amazon.com order #123-4567890-1234567",
                "body": "Thank you for your order. Your package will arrive tomorrow."
            },
            "phishing_1.eml": {
                "sender": "security@arnaz0n.com",
                "recipient": "user@example.com",
                "subject": "Account Security Alert - Action Required",
                "body": "Your account has been compromised. Click here to verify: http://suspicious-link.com"
            }
        }
        
        for filename, content in test_emails.items():
            path = Path("test_data") / filename
            if not path.exists():
                with open(path, 'w') as f:
                    f.write(f"From: {content['sender']}\n")
                    f.write(f"To: {content['recipient']}\n")
                    f.write(f"Subject: {content['subject']}\n\n")
                    f.write(content['body'])
    
    def setUp(self):
        """Set up test fixtures before each test"""
        self.start_time = time.time()
    
    def tearDown(self):
        """Clean up after each test"""
        elapsed = time.time() - self.start_time
        print(f"{self.id()}: {elapsed:.3f}s")
    
    def test_sender_analysis(self):
        """Test sender analysis component"""
        # Test legitimate sender
        result = self.detector.sender_analyzer.analyze_sender(
            "support@amazon.com",
            "Legitimate email content from Amazon"
        )
        self.assertLess(result['risk_score'], 0.5)
        
        # Test suspicious sender
        result = self.detector.sender_analyzer.analyze_sender(
            "security@arnaz0n.com",
            "Suspicious email content"
        )
        self.assertGreater(result['risk_score'], 0.5)
    
    def test_url_analysis(self):
        """Test URL analysis component"""
        # Test legitimate URLs
        content = "Check your order at https://www.amazon.com/orders"
        result = self.detector.url_analyzer.analyze_email_urls(content)
        self.assertLess(result['overall_risk_score'], 0.5)
        
        # Test suspicious URLs
        content = "Verify account: http://amaz0n-security.com/verify"
        result = self.detector.url_analyzer.analyze_email_urls(content)
        self.assertGreater(result['overall_risk_score'], 0.5)
    
    def test_behavioral_analysis(self):
        """Test behavioral analysis component"""
        # Test non-urgent content
        content = "Your monthly statement is ready for review."
        result = self.detector.behavioral_analyzer.analyze_behavior(content)
        self.assertLess(result['urgency_score'], 0.5)
        
        # Test urgent content
        content = "URGENT: Your account will be suspended in 24 hours!"
        result = self.detector.behavioral_analyzer.analyze_behavior(content)
        self.assertGreater(result['urgency_score'], 0.5)
    
    def test_full_email_analysis(self):
        """Test complete email analysis pipeline"""
        # Test legitimate email
        with open("test_data/legitimate_1.eml", 'r') as f:
            content = f.read()
        result = self.detector.analyze_email(content)
        self.assertLess(result['risk_score'], 0.5)
        
        # Test phishing email
        with open("test_data/phishing_1.eml", 'r') as f:
            content = f.read()
        result = self.detector.analyze_email(content)
        self.assertGreater(result['risk_score'], 0.5)
    
    def test_performance(self):
        """Test performance benchmarks"""
        results = {}
        
        # Test analysis speed
        start = time.time()
        for _ in range(10):
            with open("test_data/legitimate_1.eml", 'r') as f:
                self.detector.analyze_email(f.read())
        avg_time = (time.time() - start) / 10
        
        results['avg_analysis_time'] = avg_time
        self.assertLess(avg_time, 2.0)  # Should complete within 2 seconds
        
        # Save benchmark results
        with open("test_results/performance.json", 'w') as f:
            json.dump(results, f, indent=4)
    
    def test_error_handling(self):
        """Test error handling capabilities"""
        # Test with invalid email format
        with self.assertRaises(ValueError):
            self.detector.analyze_email("Invalid email content")
        
        # Test with empty content
        with self.assertRaises(ValueError):
            self.detector.analyze_email("")
        
        # Test with missing sender
        with self.assertRaises(ValueError):
            self.detector.sender_analyzer.analyze_sender("", "Some content")

def generate_test_report():
    """Generate HTML test report"""
    import HtmlTestRunner
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPhishingDetector)
    
    # Create output directory
    os.makedirs("test_results", exist_ok=True)
    
    # Run tests with HTML report
    runner = HtmlTestRunner.HTMLTestRunner(
        output="test_results",
        report_name="phishing_detector_test_report",
        combine_reports=True,
        add_timestamp=True
    )
    runner.run(suite)

if __name__ == '__main__':
    # Run tests and generate report
    generate_test_report() 