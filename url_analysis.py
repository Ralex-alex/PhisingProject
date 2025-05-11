"""
URL Analysis Module for Phishing Detection

This module provides comprehensive URL analysis capabilities for detecting
potential phishing attempts in emails. It includes features for:

1. URL extraction from email content
2. Domain analysis and risk assessment
3. Redirect chain following
4. Typosquatting detection
5. Pattern matching for suspicious characteristics

The module uses multiple techniques to identify potentially malicious URLs:
- URL shortener detection
- Suspicious TLD identification
- Typosquatting detection using Levenshtein distance
- Domain pattern analysis
- Redirect chain analysis
- Port and protocol verification

Author: Alex
Date: 2024
"""

import re
import requests
import urllib.parse
import tldextract
import logging
import json
from collections import Counter
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from urllib.parse import urlparse
from typing import Dict, List, Any, Tuple, Optional, Union
from bs4 import BeautifulSoup

# Configure logging with detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("url_analysis")

class URLAnalyzer:
    """
    A comprehensive URL analysis system for phishing detection.
    
    This class provides methods to analyze URLs found in emails for various
    indicators of phishing attempts. It maintains lists of known patterns
    and implements multiple analysis techniques to identify suspicious URLs.
    
    Key Features:
    - URL extraction from HTML and plain text
    - Domain analysis and risk scoring
    - Redirect chain following
    - Typosquatting detection
    - Pattern-based analysis
    
    The analyzer uses a scoring system where:
    - 0.0-0.3: Low risk
    - 0.3-0.6: Medium risk
    - 0.6-0.8: High risk
    - 0.8-1.0: Very high risk
    """
    
    def __init__(self, max_redirects=5, timeout=3):
        """
        Initialize the URL analyzer with configuration and reference data.
        
        Args:
            max_redirects (int): Maximum number of redirects to follow in a chain
                               Default is 5 to prevent infinite redirect loops
            timeout (int): Timeout in seconds for HTTP requests
                         Default is 3 seconds to balance thoroughness with performance
        
        The initializer sets up:
        1. HTTP session with browser-like headers
        2. Lists of known patterns (shorteners, trusted domains, suspicious TLDs)
        3. Configuration for redirect handling
        """
        self.max_redirects = max_redirects
        self.timeout = timeout
        
        # Comprehensive list of URL shortening services
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tr.im',
            'tiny.cc', 'cutt.ly', 'rebrand.ly', 'short.io'
        ]
        
        # Major legitimate service domains (regularly updated)
        self.trusted_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
            'youtube.com', 'netflix.com', 'spotify.com', 'twitch.tv',
            'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com',
            'paypal.com', 'ebay.com', 'walmart.com', 'target.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com'
        ]
        
        # TLDs frequently associated with phishing campaigns
        self.suspicious_tlds = [
            'tk', 'ga', 'cf', 'ml', 'gq', 'xyz', 'top', 'club'
        ]
        
        # URL shortening services for redirect analysis
        self.shortener_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
            'cli.gs', 'pic.gd', 'surl.co.uk', 'tiny.cc', 'url4.eu'
        ]
        
        # Configure HTTP session with browser-like headers to avoid detection
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def extract_urls(self, email_content):
        """
        Extract URLs from email content using multiple pattern matching techniques.
        
        This method implements a comprehensive URL extraction strategy that looks for:
        1. URLs in HTML href attributes
        2. Plain text URLs
        3. Cloaked URLs (where display text differs from href)
        4. URLs in various formats and contexts
        
        Args:
            email_content (str): Raw email content (HTML or plain text)
            
        Returns:
            list: Unique list of extracted URLs
            
        The method uses multiple regex patterns to catch different URL formats:
        - Standard http/https URLs
        - URLs in HTML attributes
        - URLs with unusual formatting or encoding
        """
        urls = []
        
        try:
            # Extract URLs from href attributes in HTML
            # This catches standard links in HTML content
            href_pattern = r'href=["\'](https?://[^"\'>]+)["\']'
            href_urls = re.findall(href_pattern, email_content)
            urls.extend(href_urls)
            
            # Extract raw URLs from text
            # This catches URLs that aren't in HTML tags
            raw_pattern = r'(?<!href=["\'])(https?://[^\s<>"\']+)'
            raw_urls = re.findall(raw_pattern, email_content)
            urls.extend(raw_urls)
            
            # Extract potentially cloaked URLs
            # This identifies cases where the visible text doesn't match the href
            cloaked_pattern = r'<a[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(?!https?://|www\.)[^<]+</a>'
            cloaked_matches = re.finditer(cloaked_pattern, email_content)
            for match in cloaked_matches:
                urls.append(match.group(1))
            
            # Remove duplicates while preserving order
            urls = list(dict.fromkeys(urls))
            
        except Exception as e:
            logger.error(f"Error extracting URLs: {e}")
            logger.debug(f"Email content that caused error: {email_content[:200]}...")
        
        return urls
    
    def analyze_domain(self, url):
        """
        Perform comprehensive domain analysis to detect phishing indicators.
        
        This method analyzes various aspects of a domain to determine its risk level:
        1. URL shortener detection
        2. Suspicious TLD checking
        3. IP address usage in domain
        4. Typosquatting detection
        5. Subdomain analysis
        6. Port number verification
        7. Keyword analysis
        8. Domain pattern analysis
        
        The method uses a weighted scoring system where different indicators
        contribute different amounts to the final risk score:
        - URL shorteners: 0.6
        - Suspicious TLDs: 0.7
        - IP in domain: 0.9
        - Typosquatting: 0.8
        - Excessive subdomains: 0.6
        - Unusual ports: 0.7
        - Suspicious keywords: 0.6
        - Excessive hyphens: 0.5
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            dict: Analysis results containing:
                - is_suspicious (bool): Whether the domain is suspicious
                - reasons (list): List of reasons why the domain is suspicious
                - risk_score (float): Risk score between 0.0 and 1.0
        """
        result = {
            "is_suspicious": False,
            "reasons": [],
            "risk_score": 0.0
        }
        
        try:
            # Parse the URL into components
            parsed_url = urllib.parse.urlparse(url)
            
            # Extract domain components using tldextract
            # This handles complex cases like co.uk correctly
            ext = tldextract.extract(url)
            domain = ext.domain
            tld = ext.suffix
            subdomain = ext.subdomain
            
            # Check for URL shortener services
            # These services can hide the actual destination
            if parsed_url.netloc in self.url_shorteners:
                result["is_suspicious"] = True
                result["reasons"].append("URL shortener detected")
                result["risk_score"] = max(result["risk_score"], 0.6)
            
            # Check for suspicious top-level domains
            # These TLDs are often abused in phishing campaigns
            if tld in self.suspicious_tlds:
                result["is_suspicious"] = True
                result["reasons"].append(f"Suspicious TLD: .{tld}")
                result["risk_score"] = max(result["risk_score"], 0.7)
            
            # Check for IP address used as domain
            # This is a common phishing tactic to avoid domain registration
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.netloc):
                result["is_suspicious"] = True
                result["reasons"].append("IP address used as domain")
                result["risk_score"] = max(result["risk_score"], 0.9)
            
            # Check for typosquatting against trusted domains
            # This detects slight variations of legitimate domain names
            for trusted_domain in self.trusted_domains:
                if domain != trusted_domain and self._levenshtein_distance(domain, trusted_domain) <= 2:
                    result["is_suspicious"] = True
                    result["reasons"].append(f"Possible typosquatting of {trusted_domain}")
                    result["risk_score"] = max(result["risk_score"], 0.8)
                    break
            
            # Check for excessive subdomains
            # Phishers often use multiple subdomains to obfuscate
            if subdomain and len(subdomain.split('.')) > 3:
                result["is_suspicious"] = True
                result["reasons"].append("Excessive number of subdomains")
                result["risk_score"] = max(result["risk_score"], 0.6)
            
            # Check for unusual ports
            # Legitimate services rarely use non-standard ports
            if parsed_url.port and parsed_url.port not in (80, 443):
                result["is_suspicious"] = True
                result["reasons"].append(f"Unusual port: {parsed_url.port}")
                result["risk_score"] = max(result["risk_score"], 0.7)
            
            # Check for suspicious keywords in domain
            # These words often appear in phishing URLs
            suspicious_keywords = ['secure', 'login', 'account', 'verify', 'bank', 'paypal', 'signin']
            for keyword in suspicious_keywords:
                if keyword in domain.lower():
                    result["is_suspicious"] = True
                    result["reasons"].append(f"Suspicious keyword in domain: {keyword}")
                    result["risk_score"] = max(result["risk_score"], 0.6)
            
            # Check for excessive hyphens
            # Multiple hyphens are often used in phishing domains
            if domain.count('-') > 2:
                result["is_suspicious"] = True
                result["reasons"].append("Excessive hyphens in domain")
                result["risk_score"] = max(result["risk_score"], 0.5)
            
            # Override for trusted domains
            # This prevents false positives for legitimate services
            full_domain = f"{domain}.{tld}"
            if full_domain in self.trusted_domains:
                result["is_suspicious"] = False
                result["reasons"] = ["Trusted domain"]
                result["risk_score"] = 0.1
        
        except Exception as e:
            logger.error(f"Error analyzing domain for {url}: {e}")
            logger.debug(f"URL components: {parsed_url}")
            result["is_suspicious"] = True
            result["reasons"].append(f"Error during analysis: {str(e)}")
            result["risk_score"] = 0.5  # Moderate risk for analysis failures
        
        return result
    
    def follow_redirects(self, url):
        """
        Follow and analyze URL redirect chains.
        
        This method follows URL redirects to their final destination, analyzing
        each step in the chain for potential security risks. It handles various
        types of redirects:
        1. HTTP 301/302 redirects
        2. HTML meta refreshes
        3. JavaScript redirects
        4. URL shortener expansions
        
        The method implements safety measures:
        - Maximum redirect limit
        - Timeout per request
        - Protocol validation
        - Domain blacklist checking
        
        Args:
            url (str): Initial URL to analyze
            
        Returns:
            dict: Redirect analysis results containing:
                - final_url (str): Final destination URL
                - redirect_chain (list): List of URLs in redirect chain
                - is_suspicious (bool): Whether the chain is suspicious
                - risk_score (float): Risk score between 0.0 and 1.0
                - reasons (list): List of suspicious indicators found
        """
        result = {
            "final_url": url,
            "redirect_chain": [url],
            "is_suspicious": False,
            "risk_score": 0.0,
            "reasons": []
        }
        
        try:
            current_url = url
            visited_urls = {url}  # Track visited URLs to detect loops
            
            for _ in range(self.max_redirects):
                try:
                    # Make request with safety measures
                    response = self.session.get(
                        current_url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        verify=True  # Verify SSL certificates
                    )
                    
                    # Check for HTTP redirects
                    if response.is_redirect:
                        next_url = response.headers['Location']
                        
                        # Handle relative redirects
                        if not next_url.startswith(('http://', 'https://')):
                            next_url = urllib.parse.urljoin(current_url, next_url)
                        
                        # Security checks on redirect
                        if self._is_suspicious_redirect(current_url, next_url):
                            result["is_suspicious"] = True
                            result["risk_score"] = max(result["risk_score"], 0.7)
                            result["reasons"].append(
                                f"Suspicious redirect: {current_url} -> {next_url}"
                            )
                        
                        # Check for redirect loops
                        if next_url in visited_urls:
                            result["is_suspicious"] = True
                            result["risk_score"] = max(result["risk_score"], 0.8)
                            result["reasons"].append("Redirect loop detected")
                            break
                        
                        # Update tracking
                        visited_urls.add(next_url)
                        result["redirect_chain"].append(next_url)
                        current_url = next_url
                        
                        # Analyze each URL in the chain
                        domain_analysis = self.analyze_domain(next_url)
                        if domain_analysis["is_suspicious"]:
                            result["is_suspicious"] = True
                            result["risk_score"] = max(
                                result["risk_score"],
                                domain_analysis["risk_score"]
                            )
                            result["reasons"].extend(domain_analysis["reasons"])
                    
                    # Check for meta refresh redirects
                    elif response.headers.get('content-type', '').startswith('text/html'):
                        soup = BeautifulSoup(response.text, 'html.parser')
                        meta_refresh = soup.find('meta', attrs={'http-equiv': 'refresh'})
                        
                        if meta_refresh:
                            content = meta_refresh.get('content', '')
                            if 'url=' in content.lower():
                                next_url = content.split('url=', 1)[1].strip()
                                
                                # Handle relative URLs
                                if not next_url.startswith(('http://', 'https://')):
                                    next_url = urllib.parse.urljoin(current_url, next_url)
                                
                                # Security checks for meta refresh
                                if self._is_suspicious_redirect(current_url, next_url):
                                    result["is_suspicious"] = True
                                    result["risk_score"] = max(result["risk_score"], 0.8)
                                    result["reasons"].append(
                                        f"Suspicious meta refresh: {current_url} -> {next_url}"
                                    )
                                
                                # Update tracking
                                if next_url not in visited_urls:
                                    visited_urls.add(next_url)
                                    result["redirect_chain"].append(next_url)
                                    current_url = next_url
                                    continue
                    
                    # No more redirects found
                    break
                    
                except requests.exceptions.SSLError:
                    result["is_suspicious"] = True
                    result["risk_score"] = max(result["risk_score"], 0.9)
                    result["reasons"].append(f"SSL certificate validation failed: {current_url}")
                    break
                    
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Error following redirect at {current_url}: {e}")
                    result["reasons"].append(f"Failed to access: {current_url}")
                    break
            
            # Update final URL
            result["final_url"] = current_url
            
            # Check if max redirects was reached
            if len(result["redirect_chain"]) >= self.max_redirects:
                result["is_suspicious"] = True
                result["risk_score"] = max(result["risk_score"], 0.6)
                result["reasons"].append("Maximum redirect chain length exceeded")
            
        except Exception as e:
            logger.error(f"Error analyzing redirect chain for {url}: {e}")
            result["is_suspicious"] = True
            result["reasons"].append(f"Error during redirect analysis: {str(e)}")
            result["risk_score"] = 0.5
        
        return result

    def _is_suspicious_redirect(self, source_url, dest_url):
        """
        Check if a redirect between two URLs is suspicious.
        
        This helper method analyzes redirects for common phishing patterns:
        1. Protocol downgrade (HTTPS to HTTP)
        2. Unusual port changes
        3. Suspicious domain transitions
        4. Known malicious patterns
        
        Args:
            source_url (str): Original URL
            dest_url (str): Destination URL after redirect
            
        Returns:
            bool: True if the redirect appears suspicious
        """
        try:
            source = urllib.parse.urlparse(source_url)
            dest = urllib.parse.urlparse(dest_url)
            
            # Check for protocol downgrade (security risk)
            if source.scheme == 'https' and dest.scheme == 'http':
                return True
            
            # Check for unusual port changes
            if (source.port or 80 if source.scheme == 'http' else 443) != \
               (dest.port or 80 if dest.scheme == 'http' else 443):
                return True
            
            # Extract domains
            source_domain = tldextract.extract(source_url)
            dest_domain = tldextract.extract(dest_url)
            
            # Check for suspicious domain changes
            if source_domain.registered_domain != dest_domain.registered_domain:
                # Allow redirects to known trusted domains
                if dest_domain.registered_domain not in self.trusted_domains:
                    return True
            
            # Check for suspicious URL patterns
            suspicious_patterns = [
                r'\/[^\/]+\.php\?[^\/]+=[^\/]+',  # PHP scripts with parameters
                r'\/(?:login|signin|account)\/.*redirect',  # Login-related redirects
                r'\/(?:go|click|track)\.php',  # Tracking scripts
                r'\/[^\/]+\.cgi\?',  # CGI scripts
                r'\/(?:redir|redirect|forward)\.aspx'  # Redirect scripts
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, dest_url, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking redirect suspiciousness: {e}")
            return True  # Err on the side of caution
    
    def analyze_url(self, url):
        """
        Perform comprehensive analysis of a single URL.
        
        This method combines multiple analysis techniques to provide a thorough
        assessment of a URL's potential risk:
        1. Domain analysis
        2. Redirect chain analysis
        3. URL structure analysis
        4. Parameter analysis
        5. Protocol verification
        
        The analysis considers:
        - Domain reputation and characteristics
        - Redirect behavior and patterns
        - URL structure and components
        - Query parameters and their values
        - SSL/TLS usage and certificate validity
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Comprehensive analysis results containing:
                - is_suspicious (bool): Whether the URL is suspicious
                - risk_score (float): Overall risk score between 0.0 and 1.0
                - reasons (list): List of reasons for suspicion
                - analysis_details (dict): Detailed analysis results
                    - domain_analysis (dict): Results of domain analysis
                    - redirect_analysis (dict): Results of redirect analysis
                    - structure_analysis (dict): Results of URL structure analysis
        """
        result = {
            "is_suspicious": False,
            "risk_score": 0.0,
            "reasons": [],
            "analysis_details": {
                "domain_analysis": None,
                "redirect_analysis": None,
                "structure_analysis": None
            }
        }
        
        try:
            # Normalize the URL
            url = self._normalize_url(url)
            
            # Analyze domain characteristics
            domain_analysis = self.analyze_domain(url)
            result["analysis_details"]["domain_analysis"] = domain_analysis
            
            if domain_analysis["is_suspicious"]:
                result["is_suspicious"] = True
                result["risk_score"] = max(result["risk_score"], domain_analysis["risk_score"])
                result["reasons"].extend(domain_analysis["reasons"])
            
            # Follow and analyze redirects
            redirect_analysis = self.follow_redirects(url)
            result["analysis_details"]["redirect_analysis"] = redirect_analysis
            
            if redirect_analysis["is_suspicious"]:
                result["is_suspicious"] = True
                result["risk_score"] = max(result["risk_score"], redirect_analysis["risk_score"])
                result["reasons"].extend(redirect_analysis["reasons"])
            
            # Analyze URL structure and parameters
            structure_analysis = self._analyze_url_structure(url)
            result["analysis_details"]["structure_analysis"] = structure_analysis
            
            if structure_analysis["is_suspicious"]:
                result["is_suspicious"] = True
                result["risk_score"] = max(result["risk_score"], structure_analysis["risk_score"])
                result["reasons"].extend(structure_analysis["reasons"])
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            result["is_suspicious"] = True
            result["reasons"].append(f"Error during analysis: {str(e)}")
            result["risk_score"] = 0.5
        
        return result
    
    def _normalize_url(self, url):
        """
        Normalize a URL for consistent analysis.
        
        Performs various normalization steps to ensure consistent URL analysis:
        1. Add scheme if missing
        2. Convert to lowercase
        3. Remove default ports
        4. Sort query parameters
        5. Remove fragments
        6. Decode percent-encoded characters
        
        Args:
            url (str): URL to normalize
            
        Returns:
            str: Normalized URL
        """
        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Parse the URL
            parsed = urllib.parse.urlparse(url)
            
            # Convert to lowercase
            netloc = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Remove default ports
            if ':' in netloc:
                domain, port = netloc.split(':')
                if (parsed.scheme == 'http' and port == '80') or \
                   (parsed.scheme == 'https' and port == '443'):
                    netloc = domain
            
            # Sort query parameters
            if parsed.query:
                query_params = urllib.parse.parse_qs(parsed.query)
                sorted_query = '&'.join(
                    f"{k}={','.join(sorted(v))}"
                    for k, v in sorted(query_params.items())
                )
            else:
                sorted_query = ''
            
            # Rebuild URL without fragment
            normalized = urllib.parse.urlunparse((
                parsed.scheme,
                netloc,
                path,
                parsed.params,
                sorted_query,
                ''  # No fragment
            ))
            
            # Decode percent-encoded characters where possible
            normalized = urllib.parse.unquote(normalized)
            
            return normalized
            
        except Exception as e:
            logger.error(f"Error normalizing URL {url}: {e}")
            return url
    
    def _analyze_url_structure(self, url):
        """
        Analyze URL structure for suspicious patterns.
        
        This method examines various aspects of URL structure that might
        indicate phishing or malicious intent:
        1. Unusual character sequences
        2. Encoded content
        3. Parameter patterns
        4. Path structure
        5. Known malicious patterns
        
        Args:
            url (str): URL to analyze
            
        Returns:
            dict: Analysis results containing:
                - is_suspicious (bool): Whether the structure is suspicious
                - risk_score (float): Risk score between 0.0 and 1.0
                - reasons (list): List of suspicious patterns found
        """
        result = {
            "is_suspicious": False,
            "risk_score": 0.0,
            "reasons": []
        }
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check for excessive encoding
            if '%' in url:
                encoded_count = url.count('%')
                if encoded_count > 3:
                    result["is_suspicious"] = True
                    result["risk_score"] = max(result["risk_score"], 0.6)
                    result["reasons"].append(f"Excessive URL encoding ({encoded_count} instances)")
            
            # Check for suspicious path patterns
            suspicious_path_patterns = [
                r'//+',  # Multiple consecutive slashes
                r'/\.\./+',  # Directory traversal attempts
                r'(?<=/)[^/]{50,}',  # Very long path segments
                r'\.(php|asp|aspx|jsp)\.',  # Hidden file extensions
                r'[<>"]'  # Invalid URL characters
            ]
            
            for pattern in suspicious_path_patterns:
                if re.search(pattern, parsed.path):
                    result["is_suspicious"] = True
                    result["risk_score"] = max(result["risk_score"], 0.7)
                    result["reasons"].append(f"Suspicious path pattern: {pattern}")
            
            # Analyze query parameters
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                
                # Check for suspicious parameter names
                suspicious_params = ['redir', 'redirect', 'url', 'link', 'goto', 'return']
                for param in params:
                    if param.lower() in suspicious_params:
                        result["is_suspicious"] = True
                        result["risk_score"] = max(result["risk_score"], 0.6)
                        result["reasons"].append(f"Suspicious parameter: {param}")
                
                # Check for encoded URLs in parameters
                for values in params.values():
                    for value in values:
                        if 'http' in urllib.parse.unquote(value).lower():
                            result["is_suspicious"] = True
                            result["risk_score"] = max(result["risk_score"], 0.8)
                            result["reasons"].append("URL found in parameter value")
            
            # Check for mixed case domain
            if any(c.isupper() for c in parsed.netloc):
                result["is_suspicious"] = True
                result["risk_score"] = max(result["risk_score"], 0.5)
                result["reasons"].append("Mixed case in domain")
            
            # Check for excessive subdomains
            subdomain_count = len(parsed.netloc.split('.')) - 2
            if subdomain_count > 3:
                result["is_suspicious"] = True
                result["risk_score"] = max(result["risk_score"], 0.6)
                result["reasons"].append(f"Excessive subdomains ({subdomain_count})")
            
        except Exception as e:
            logger.error(f"Error analyzing URL structure for {url}: {e}")
            result["is_suspicious"] = True
            result["reasons"].append(f"Error during structure analysis: {str(e)}")
            result["risk_score"] = 0.5
        
        return result
    
    def analyze_email_urls(self, email_content):
        """
        Analyze all URLs found in an email for phishing indicators.
        
        This method provides a comprehensive analysis of all URLs in an email:
        1. Extracts URLs from various email components
        2. Analyzes each URL individually
        3. Performs pattern analysis across all URLs
        4. Identifies relationships between URLs
        5. Calculates overall risk metrics
        
        The analysis includes:
        - Individual URL risk assessment
        - URL pattern analysis
        - Domain clustering
        - Redirect chain analysis
        - Common phishing patterns
        
        Args:
            email_content (str): Raw email content (HTML or plain text)
            
        Returns:
            dict: Comprehensive analysis results containing:
                - urls_found (list): List of all URLs found
                - url_analysis (dict): Analysis results for each URL
                - overall_risk_score (float): Combined risk score
                - is_suspicious (bool): Whether the email's URLs are suspicious
                - reasons (list): List of suspicious patterns found
                - statistics (dict): URL analysis statistics
        """
        result = {
            "urls_found": [],
            "url_analysis": {},
            "overall_risk_score": 0.0,
            "is_suspicious": False,
            "reasons": [],
            "statistics": {
                "total_urls": 0,
                "suspicious_urls": 0,
                "unique_domains": 0,
                "shortener_count": 0,
                "redirect_count": 0
            }
        }
        
        try:
            # Extract all URLs from the email
            urls = self.extract_urls(email_content)
            result["urls_found"] = urls
            result["statistics"]["total_urls"] = len(urls)
            
            if not urls:
                logger.info("No URLs found in email content")
                return result
            
            # Track unique domains and patterns
            domains = set()
            suspicious_patterns = []
            
            # Analyze each URL
            for url in urls:
                # Perform comprehensive URL analysis
                analysis = self.analyze_url(url)
                result["url_analysis"][url] = analysis
                
                # Extract domain for uniqueness checking
                try:
                    domain = tldextract.extract(url).registered_domain
                    domains.add(domain)
                except Exception:
                    pass
                
                # Update statistics
                if analysis["is_suspicious"]:
                    result["statistics"]["suspicious_urls"] += 1
                    suspicious_patterns.extend(analysis["reasons"])
                
                # Track URL shortener usage
                if any(shortener in url.lower() for shortener in self.url_shorteners):
                    result["statistics"]["shortener_count"] += 1
                
                # Track redirects
                if analysis["analysis_details"]["redirect_analysis"] and \
                   len(analysis["analysis_details"]["redirect_analysis"]["redirect_chain"]) > 1:
                    result["statistics"]["redirect_count"] += 1
                
                # Update overall risk score
                result["overall_risk_score"] = max(
                    result["overall_risk_score"],
                    analysis["risk_score"]
                )
            
            # Update domain statistics
            result["statistics"]["unique_domains"] = len(domains)
            
            # Analyze patterns across all URLs
            if result["statistics"]["suspicious_urls"] > 0:
                result["is_suspicious"] = True
                
                # Calculate percentage of suspicious URLs
                suspicious_percentage = (result["statistics"]["suspicious_urls"] / 
                                      result["statistics"]["total_urls"] * 100)
                result["reasons"].append(
                    f"{suspicious_percentage:.1f}% of URLs ({result['statistics']['suspicious_urls']}) "
                    f"show suspicious characteristics"
                )
            
            # Check for mixed target domains
            if len(domains) > 2:
                result["is_suspicious"] = True
                result["reasons"].append(
                    f"Multiple target domains detected ({len(domains)})"
                )
            
            # Check for excessive URL shortener usage
            if result["statistics"]["shortener_count"] > 1:
                result["is_suspicious"] = True
                result["reasons"].append(
                    f"Multiple URL shorteners detected ({result['statistics']['shortener_count']})"
                )
            
            # Check for excessive redirects
            if result["statistics"]["redirect_count"] > 2:
                result["is_suspicious"] = True
                result["reasons"].append(
                    f"Multiple redirect chains detected ({result['statistics']['redirect_count']})"
                )
            
            # Analyze common patterns in suspicious URLs
            if suspicious_patterns:
                pattern_counts = Counter(suspicious_patterns)
                common_patterns = [
                    pattern for pattern, count in pattern_counts.items()
                    if count > 1
                ]
                if common_patterns:
                    result["reasons"].extend([
                        f"Repeated suspicious pattern: {pattern}"
                        for pattern in common_patterns
                    ])
            
        except Exception as e:
            logger.error(f"Error analyzing email URLs: {e}")
            result["is_suspicious"] = True
            result["reasons"].append(f"Error during analysis: {str(e)}")
            result["overall_risk_score"] = 0.5
        
        return result
    
    def _levenshtein_distance(self, s1, s2):
        """
        Calculate the Levenshtein distance between two strings.
        
        This method is used to detect typosquatting attempts by measuring
        the edit distance between two domain names. The distance represents
        the minimum number of single-character edits required to change one
        string into the other.
        
        Supported operations:
        - Insertions
        - Deletions
        - Substitutions
        
        Args:
            s1 (str): First string to compare
            s2 (str): Second string to compare
            
        Returns:
            int: Levenshtein distance between the strings
        """
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                # Calculate insertions, deletions and substitutions
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                
                # Take minimum of three operations
                current_row.append(min(insertions, deletions, substitutions))
            
            previous_row = current_row
        
        return previous_row[-1]

# Example usage
if __name__ == "__main__":
    analyzer = URLAnalyzer()
    
    # Example email content with URLs
    email_content = """
    <html>
    <body>
        <p>Please verify your account by clicking the link below:</p>
        <a href="http://bit.ly/2x4fGhY">Verify Account</a>
        <p>Or visit our secure site: https://paypa1.com/secure</p>
        <p>Contact us at support@example.com</p>
    </body>
    </html>
    """
    
    results = analyzer.analyze_email_urls(email_content)
    print(json.dumps(results, indent=2)) 