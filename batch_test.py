import os
import json
import csv
import time
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from enhanced_phishing_detector import EnhancedPhishingDetector

class BatchTester:
    """Batch testing utility for the phishing detection system"""
    
    def __init__(self, test_dir="test_data", results_dir="test_results/batch"):
        self.test_dir = Path(test_dir)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize detector
        self.detector = EnhancedPhishingDetector(
            config_path="phishing_detector_config.json",
            history_db_path="email_history.csv",
            examples_path="phishing_examples.json"
        )
        
        # Initialize results storage
        self.results = {
            'summary': {
                'total_emails': 0,
                'phishing_detected': 0,
                'legitimate_detected': 0,
                'avg_processing_time': 0,
                'timestamp': datetime.now().isoformat()
            },
            'detailed_results': []
        }
    
    def analyze_email(self, email_path):
        """Analyze a single email file"""
        try:
            start_time = time.time()
            
            with open(email_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Run analysis
            result = self.detector.analyze_email(content)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Extract email metadata
            sender = None
            subject = None
            for line in content.split('\n'):
                if line.startswith('From:'):
                    sender = line[5:].strip()
                elif line.startswith('Subject:'):
                    subject = line[8:].strip()
                if sender and subject:
                    break
            
            # Compile detailed result
            detailed_result = {
                'filename': email_path.name,
                'sender': sender,
                'subject': subject,
                'risk_score': result['risk_score'],
                'verdict': 'phishing' if result['risk_score'] > 0.5 else 'legitimate',
                'processing_time': processing_time,
                'risk_factors': result.get('risk_factors', []),
                'confidence': result.get('confidence', None)
            }
            
            return detailed_result
            
        except Exception as e:
            return {
                'filename': email_path.name,
                'error': str(e),
                'status': 'failed'
            }
    
    def run_batch_test(self, max_workers=4):
        """Run batch testing on all emails in the test directory"""
        email_files = list(self.test_dir.glob('*.eml'))
        total_time = 0
        
        print(f"Starting batch analysis of {len(email_files)} emails...")
        
        # Process emails in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(self.analyze_email, email_files))
        
        # Compile results
        for result in results:
            self.results['detailed_results'].append(result)
            
            if 'error' not in result:
                self.results['summary']['total_emails'] += 1
                if result['verdict'] == 'phishing':
                    self.results['summary']['phishing_detected'] += 1
                else:
                    self.results['summary']['legitimate_detected'] += 1
                total_time += result['processing_time']
        
        # Calculate average processing time
        if self.results['summary']['total_emails'] > 0:
            self.results['summary']['avg_processing_time'] = (
                total_time / self.results['summary']['total_emails']
            )
        
        # Generate reports
        self._generate_reports()
    
    def _generate_reports(self):
        """Generate detailed reports from the test results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save full JSON report
        json_path = self.results_dir / f"batch_results_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=4)
        
        # Save CSV summary
        csv_path = self.results_dir / f"batch_results_{timestamp}.csv"
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Filename', 'Sender', 'Subject', 'Risk Score',
                'Verdict', 'Processing Time', 'Risk Factors', 'Confidence'
            ])
            
            for result in self.results['detailed_results']:
                if 'error' not in result:
                    writer.writerow([
                        result['filename'],
                        result['sender'],
                        result['subject'],
                        result['risk_score'],
                        result['verdict'],
                        f"{result['processing_time']:.3f}",
                        '; '.join(result['risk_factors']),
                        result['confidence']
                    ])
        
        # Generate HTML report
        self._generate_html_report(timestamp)
        
        print(f"\nBatch testing completed!")
        print(f"Total emails processed: {self.results['summary']['total_emails']}")
        print(f"Phishing emails detected: {self.results['summary']['phishing_detected']}")
        print(f"Legitimate emails detected: {self.results['summary']['legitimate_detected']}")
        print(f"Average processing time: {self.results['summary']['avg_processing_time']:.3f} seconds")
        print(f"\nReports generated:")
        print(f"- JSON: {json_path}")
        print(f"- CSV: {csv_path}")
        print(f"- HTML: {self.results_dir}/batch_results_{timestamp}.html")
    
    def _generate_html_report(self, timestamp):
        """Generate an HTML report with charts and detailed results"""
        html_path = self.results_dir / f"batch_results_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Phishing Detection Batch Test Results</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                .chart {{ margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Phishing Detection Batch Test Results</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p>Total emails processed: {self.results['summary']['total_emails']}</p>
                    <p>Phishing emails detected: {self.results['summary']['phishing_detected']}</p>
                    <p>Legitimate emails detected: {self.results['summary']['legitimate_detected']}</p>
                    <p>Average processing time: {self.results['summary']['avg_processing_time']:.3f} seconds</p>
                    <p>Test completed: {self.results['summary']['timestamp']}</p>
                </div>
                
                <div id="riskScoreChart" class="chart"></div>
                <div id="processingTimeChart" class="chart"></div>
                
                <h2>Detailed Results</h2>
                <table>
                    <tr>
                        <th>Filename</th>
                        <th>Sender</th>
                        <th>Subject</th>
                        <th>Risk Score</th>
                        <th>Verdict</th>
                        <th>Processing Time</th>
                        <th>Confidence</th>
                    </tr>
        """
        
        # Add table rows
        for result in self.results['detailed_results']:
            if 'error' not in result:
                html_content += f"""
                    <tr>
                        <td>{result['filename']}</td>
                        <td>{result['sender']}</td>
                        <td>{result['subject']}</td>
                        <td>{result['risk_score']:.3f}</td>
                        <td>{result['verdict']}</td>
                        <td>{result['processing_time']:.3f}s</td>
                        <td>{result['confidence']}</td>
                    </tr>
                """
        
        # Add charts and close HTML
        html_content += """
                </table>
                
                <script>
                    // Create risk score distribution chart
                    var riskScores = {
                        x: RISK_SCORES_PLACEHOLDER,
                        type: 'histogram',
                        name: 'Risk Score Distribution'
                    };
                    
                    Plotly.newPlot('riskScoreChart', [riskScores], {
                        title: 'Risk Score Distribution',
                        xaxis: { title: 'Risk Score' },
                        yaxis: { title: 'Count' }
                    });
                    
                    // Create processing time chart
                    var processingTimes = {
                        x: PROCESSING_TIMES_PLACEHOLDER,
                        type: 'histogram',
                        name: 'Processing Time Distribution'
                    };
                    
                    Plotly.newPlot('processingTimeChart', [processingTimes], {
                        title: 'Processing Time Distribution',
                        xaxis: { title: 'Processing Time (s)' },
                        yaxis: { title: 'Count' }
                    });
                </script>
            </div>
        </body>
        </html>
        """
        
        # Replace placeholders with actual data
        risk_scores = [r['risk_score'] for r in self.results['detailed_results'] if 'error' not in r]
        processing_times = [r['processing_time'] for r in self.results['detailed_results'] if 'error' not in r]
        
        html_content = html_content.replace('RISK_SCORES_PLACEHOLDER', str(risk_scores))
        html_content = html_content.replace('PROCESSING_TIMES_PLACEHOLDER', str(processing_times))
        
        with open(html_path, 'w') as f:
            f.write(html_content)

def main():
    """Main function to run batch testing"""
    # Create batch tester
    tester = BatchTester()
    
    # Run batch test
    tester.run_batch_test()

if __name__ == '__main__':
    main() 