"""
Sender Analysis Module for Phishing Detection

This module provides comprehensive sender analysis capabilities for detecting
potential phishing attempts in emails. It includes features for:

1. Email sender validation and parsing
2. Domain age and registration analysis
3. SPF/DKIM/DMARC record verification
4. Domain reputation checking
5. Typosquatting detection
6. Sender domain alignment verification

The module uses multiple techniques to identify potentially malicious senders:
- Domain registration analysis
- Email authentication protocols
- Reputation databases
- Pattern matching
- DNS record verification
- Domain alignment checks

Author: Alex
Date: 2024
"""

import re
import dns.resolver
import whois
import requests
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from urllib.parse import urlparse
import logging
import json
import socket
import dkim
from email import parser as email_parser

# Configure logging with detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sender_analysis")

class SenderAnalyzer:
    """
    A comprehensive sender analysis system for phishing detection.
    
    This class provides methods to analyze email sender information for various
    indicators of phishing attempts. It implements multiple verification techniques
    and maintains lists of known patterns.
    
    Key Features:
    - Email address parsing and validation
    - Domain age verification
    - SPF record checking
    - DKIM signature verification
    - DMARC policy validation
    - Domain reputation analysis
    - Typosquatting detection
    
    The analyzer uses a scoring system where:
    - 0.0-0.3: Low risk
    - 0.3-0.6: Medium risk
    - 0.6-0.8: High risk
    - 0.8-1.0: Very high risk
    """
    
    def __init__(self, reputation_db_path=None, reputation_api_key=None):
        """
        Initialize the sender analyzer with configuration and reference data.
        
        Args:
            reputation_db_path (str): Path to CSV file containing domain reputation data
                                    Used for offline reputation checking
            reputation_api_key (str): API key for online domain reputation service
                                    Used when reputation_db is not available
        
        The initializer sets up:
        1. Reputation database (if provided)
        2. API key for reputation service
        3. List of trusted domains
        4. Reputation cache for performance
        """
        self.reputation_db = None
        self.reputation_api_key = reputation_api_key
        
        # Load reputation database if provided
        if reputation_db_path:
            try:
                self.reputation_db = pd.read_csv(reputation_db_path)
                logger.info(f"Loaded reputation database with {len(self.reputation_db)} entries")
            except Exception as e:
                logger.warning(f"Could not load reputation database: {e}")
                logger.debug(f"Reputation database path: {reputation_db_path}")
        
        # Comprehensive list of trusted email providers and services
        self.trusted_domains = [
            'gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'icloud.com',
            'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
            'linkedin.com', 'netflix.com', 'spotify.com', 'twitch.tv', 'youtube.com',
            'discord.com', 'steam.com', 'steamcommunity.com', 'steampowered.com',
            'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com'
        ]
        
        # Initialize cache for domain reputation results
        # This improves performance by avoiding repeated lookups
        self.reputation_cache = {}
    
    def parse_email_address(self, email_address):
        """
        Parse and validate an email address format.
        
        This method implements RFC 5322 compliant email parsing:
        - Extracts username and domain parts
        - Validates format and character usage
        - Handles special cases and variations
        
        The parser checks for:
        1. Valid username characters
        2. Valid domain format
        3. Proper @ symbol usage
        4. TLD requirements
        
        Args:
            email_address (str): Email address to parse and validate
            
        Returns:
            tuple: (username, domain) if valid, (None, None) if invalid
                  username: The local part of the email address
                  domain: The domain part of the email address
        """
        if not email_address:
            return None, None
            
        try:
            # RFC 5322 compliant email regex pattern
            # This handles most valid email formats while rejecting invalid ones
            pattern = r'^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$'
            match = re.match(pattern, email_address)
            
            if match:
                username = match.group(1)
                domain = match.group(2)
                
                # Additional validation could be added here:
                # - Check for consecutive special characters
                # - Validate domain format
                # - Check username length
                # - Verify TLD validity
                
                return username, domain
                
        except Exception as e:
            logger.error(f"Error parsing email address: {e}")
            logger.debug(f"Problematic email address: {email_address}")
        
        return None, None
    
    def check_domain_age(self, domain):
        """
        Analyze domain registration age and details.
        
        This method performs comprehensive domain age analysis to identify
        potentially suspicious new domains. It checks:
        1. Domain creation date
        2. Registration period
        3. Expiration date
        4. Registrar information
        
        The risk scoring is based on domain age:
        - < 30 days: Very high risk (0.9)
        - < 90 days: High risk (0.6)
        - < 180 days: Medium risk (0.3)
        - >= 180 days: Low risk (0.1)
        
        Args:
            domain (str): Domain name to analyze
            
        Returns:
            dict: Domain age analysis containing:
                - domain_age_days (int): Age of domain in days
                - is_new_domain (bool): Whether domain is considered new
                - registration_date (str): Domain creation date
                - expiration_date (str): Domain expiration date
                - registrar (str): Domain registrar name
                - risk_score (float): Risk score based on age
        """
        result = {
            "domain_age_days": None,
            "is_new_domain": False,
            "registration_date": None,
            "expiration_date": None,
            "registrar": None,
            "risk_score": 0.0
        }
        
        try:
            # Query WHOIS database for domain registration information
            # This provides authoritative data about domain creation and ownership
            domain_info = whois.whois(domain)
            
            # Process creation date from WHOIS response
            if domain_info.creation_date:
                # Handle multiple creation dates (some registrars return a list)
                # This can happen with domain transfers or WHOIS privacy services
                if isinstance(domain_info.creation_date, list):
                    # Take the first (usually earliest) date in the list
                    creation_date = domain_info.creation_date[0]
                else:
                    # Use the single date directly
                    creation_date = domain_info.creation_date
                
                # Calculate domain age only if we have a valid datetime object
                # Some WHOIS responses might contain malformed dates
                if isinstance(creation_date, datetime):
                    # Calculate the age in days from creation to now
                    domain_age = datetime.now() - creation_date
                    domain_age_days = domain_age.days
                    
                    # Store age information in the result
                    result["domain_age_days"] = domain_age_days
                    result["registration_date"] = creation_date.strftime("%Y-%m-%d")
                    
                    # Process expiration date if available
                    if domain_info.expiration_date:
                        # Handle multiple expiration dates (similar to creation dates)
                        if isinstance(domain_info.expiration_date, list):
                            expiration_date = domain_info.expiration_date[0]
                        else:
                            expiration_date = domain_info.expiration_date
                        
                        # Format and store if it's a valid datetime
                        if isinstance(expiration_date, datetime):
                            result["expiration_date"] = expiration_date.strftime("%Y-%m-%d")
                    
                    # Store registrar information if available
                    # This helps identify the registration authority
                    if domain_info.registrar:
                        result["registrar"] = domain_info.registrar
                    
                    # Calculate risk score based on domain age
                    # Phishers often use newly registered domains
                    if domain_age_days < 30:
                        # Very new domains (less than a month) are highest risk
                        # These are frequently used for short-lived phishing campaigns
                        result["is_new_domain"] = True
                        result["risk_score"] = 0.9  # Very high risk
                    elif domain_age_days < 90:
                        # Domains less than 3 months old are still high risk
                        result["risk_score"] = 0.6  # High risk
                    elif domain_age_days < 180:
                        # Domains 3-6 months old are medium risk
                        result["risk_score"] = 0.3  # Medium risk
                    else:
                        # Domains older than 6 months are generally lower risk
                        # Most legitimate domains have been registered for years
                        result["risk_score"] = 0.1  # Low risk
        
        except Exception as e:
            # Handle WHOIS lookup failures
            # This could be due to network issues, rate limiting, or non-existent domains
            logger.warning(f"Could not check domain age for {domain}: {e}")
            logger.debug(f"WHOIS query failed with error: {str(e)}")
            
            # Assign medium risk score when age check fails
            # We can't confirm age, so we take a cautious approach
            result["risk_score"] = 0.5
            
        return result
    
    def check_spf_record(self, domain):
        """
        Analyze SPF record configuration and validity.
        
        This method performs a comprehensive analysis of a domain's SPF record:
        1. Checks for presence of SPF record
        2. Validates record syntax
        3. Analyzes included domains
        4. Evaluates policy strength
        5. Checks for common misconfigurations
        
        The method checks for:
        - Record presence and format
        - Policy mechanisms (all, include, ip4/ip6, etc.)
        - Policy strictness (~all vs -all)
        - Included domains and services
        - Maximum DNS lookups (RFC 7208)
        
        Args:
            domain (str): Domain name to check SPF record for
            
        Returns:
            dict: SPF analysis results containing:
                - has_spf (bool): Whether domain has SPF record
                - spf_record (str): Raw SPF record if found
                - spf_valid (bool): Whether record is valid
                - spf_includes (list): Included domains
                - spf_mechanisms (list): SPF mechanisms used
                - spf_all_mechanism (str): Final 'all' mechanism
                - risk_score (float): Risk score based on SPF policy
        """
        result = {
            "has_spf": False,
            "spf_record": None,
            "spf_valid": False,
            "spf_includes": [],
            "spf_mechanisms": [],
            "spf_all_mechanism": None,
            "risk_score": 0.5  # Default medium risk
        }
        
        try:
            # Query domain's TXT records
            answers = dns.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                txt_record = rdata.to_text()
                
                # Look for SPF record (v=spf1)
                if "v=spf1" in txt_record:
                    result["has_spf"] = True
                    result["spf_record"] = txt_record
                    
                    # Split record into mechanisms
                    mechanisms = txt_record.split(' ')
                    result["spf_mechanisms"] = mechanisms[1:]  # Skip "v=spf1"
                    
                    # Extract included domains
                    includes = [m.replace('include:', '') for m in mechanisms if m.startswith('include:')]
                    result["spf_includes"] = includes
                    
                    # Find the 'all' mechanism
                    all_mechanisms = [m for m in mechanisms if m in ['+all', '-all', '~all', '?all']]
                    if all_mechanisms:
                        result["spf_all_mechanism"] = all_mechanisms[0]
                        
                        # Evaluate risk based on 'all' mechanism
                        if all_mechanisms[0] == '-all':
                            # Strict policy, low risk
                            result["risk_score"] = 0.2
                        elif all_mechanisms[0] == '~all':
                            # Soft fail, medium risk
                            result["risk_score"] = 0.4
                        elif all_mechanisms[0] == '?all':
                            # Neutral, higher risk
                            result["risk_score"] = 0.6
                        else:  # +all
                            # Pass all, very high risk
                            result["risk_score"] = 0.8
                    
                    # Validate SPF configuration
                    result["spf_valid"] = self._validate_spf(mechanisms)
                    
                    # If invalid SPF, increase risk
                    if not result["spf_valid"]:
                        result["risk_score"] = max(result["risk_score"], 0.7)
                    
                    break  # Stop after finding SPF record
            
            # No SPF record found
            if not result["has_spf"]:
                result["risk_score"] = 0.8  # High risk for missing SPF
                
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain {domain} does not exist")
            result["risk_score"] = 1.0  # Maximum risk for non-existent domain
            
        except dns.resolver.NoAnswer:
            logger.warning(f"No TXT records found for {domain}")
            result["risk_score"] = 0.8  # High risk for no TXT records
            
        except Exception as e:
            logger.error(f"Error checking SPF record for {domain}: {e}")
            result["risk_score"] = 0.6  # Medium-high risk for lookup errors
        
        return result
    
    def _validate_spf(self, mechanisms):
        """
        Validate SPF record mechanisms and syntax.
        
        This helper method checks SPF record validity according to RFC 7208:
        1. Validates mechanism syntax
        2. Checks for duplicate mechanisms
        3. Verifies qualifier usage
        4. Ensures single 'all' mechanism
        5. Validates IP addresses and prefixes
        
        The method checks for common errors:
        - Multiple 'all' mechanisms
        - Invalid qualifiers
        - Malformed IP addresses
        - Incorrect mechanism syntax
        - Missing 'all' mechanism
        
        Args:
            mechanisms (list): List of SPF mechanisms to validate
            
        Returns:
            bool: True if SPF record is valid, False otherwise
        """
        try:
            # Define valid SPF qualifiers according to RFC 7208
            # + (Pass), - (Fail), ~ (SoftFail), ? (Neutral)
            qualifiers = ['+', '-', '~', '?']
            
            # Define valid mechanism names according to RFC 7208
            # These are the standard mechanisms recognized in SPF processing
            valid_mechanisms = [
                'all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6',
                'exists', 'redirect', 'exp'
            ]
            
            # Track 'all' mechanism count - RFC requires exactly one
            # The 'all' mechanism is the default catch-all at the end of processing
            all_count = 0
            
            # Check each mechanism for validity
            for mechanism in mechanisms:
                # Skip empty mechanisms
                # This can happen with extra spaces in the SPF record
                if not mechanism:
                    continue
                
                # Extract qualifier if present
                # Default qualifier is '+' (Pass) if not specified
                if mechanism[0] in qualifiers:
                    qualifier = mechanism[0]
                    mechanism = mechanism[1:]  # Remove qualifier from mechanism
                else:
                    qualifier = '+'  # Default qualifier
                
                # Split mechanism into name and value (e.g., "ip4:192.168.1.1")
                parts = mechanism.split(':', 1)
                name = parts[0].lower()  # Normalize to lowercase
                
                # Validate mechanism name against list of valid mechanisms
                # This catches typos and non-standard mechanisms
                if name not in valid_mechanisms:
                    logger.warning(f"Invalid mechanism name: {name}")
                    return False
                
                # Check for duplicate or misplaced 'all' mechanism
                # 'all' should appear only once and typically at the end
                if name == 'all':
                    all_count += 1
                    if all_count > 1:
                        logger.warning("Multiple 'all' mechanisms found")
                        return False
                
                # Validate IP addresses in ip4/ip6 mechanisms
                # This ensures proper IP format according to standards
                if name in ['ip4', 'ip6'] and len(parts) > 1:
                    try:
                        # Extract IP address (ignoring CIDR prefix if present)
                        ip = parts[1].split('/', 1)[0]
                        
                        # Validate IP format using socket functions
                        # AF_INET for IPv4, AF_INET6 for IPv6
                        socket.inet_pton(
                            socket.AF_INET if name == 'ip4' else socket.AF_INET6,
                            ip
                        )
                    except Exception:
                        # Invalid IP format detected
                        logger.warning(f"Invalid IP address in {mechanism}")
                        return False
            
            # Ensure exactly one 'all' mechanism is present
            # This is required per RFC 7208 for a complete SPF record
            if all_count != 1:
                logger.warning("Missing or multiple 'all' mechanism")
                return False
            
            # If we've passed all checks, the SPF record is valid
            return True
            
        except Exception as e:
            # Handle any unexpected errors during validation
            logger.error(f"Error validating SPF mechanisms: {e}")
            return False
    
    def check_dkim_signature(self, email_content):
        """
        Verify DKIM signature in an email.
        
        Args:
            email_content (str): Raw email content
            
        Returns:
            dict: DKIM verification results
        """
        result = {
            "has_dkim": False,
            "dkim_valid": False,
            "dkim_domain": None,
            "dkim_selector": None,
            "risk_score": 0.5  # Default medium risk
        }
        
        try:
            # Parse the email into a structured message object for header analysis
            email_message = email_parser.Parser().parsestr(email_content)
            
            # Check if the email has a DKIM-Signature header
            # DKIM signatures are critical for email authentication
            if 'DKIM-Signature' in email_message:
                # Found a DKIM signature, mark as present
                result["has_dkim"] = True
                
                # Extract domain and selector from DKIM signature using regex
                # The domain (d=) identifies the signing entity
                # The selector (s=) is used with the domain to locate the public key
                dkim_header = email_message['DKIM-Signature']
                domain_match = re.search(r'd=([^;]+)', dkim_header)
                selector_match = re.search(r's=([^;]+)', dkim_header)
                
                # Store the domain if found in the DKIM signature
                if domain_match:
                    result["dkim_domain"] = domain_match.group(1)
                
                # Store the selector if found in the DKIM signature
                if selector_match:
                    result["dkim_selector"] = selector_match.group(1)
                
                # Verify DKIM signature using the dkim library
                try:
                    # Convert email_content to bytes if it's a string
                    # The dkim library requires bytes input for verification
                    if isinstance(email_content, str):
                        email_bytes = email_content.encode('utf-8')
                    else:
                        email_bytes = email_content
                    
                    # Perform cryptographic verification of the DKIM signature
                    # This checks if the email content matches the signature
                    dkim_result = dkim.verify(email_bytes)
                    result["dkim_valid"] = dkim_result
                    
                    # Assign risk score based on DKIM verification
                    # Valid DKIM signatures significantly reduce phishing risk
                    if result["dkim_valid"]:
                        result["risk_score"] = 0.1  # Valid DKIM - very low risk
                    else:
                        # Invalid signatures are highly suspicious - could indicate tampering
                        result["risk_score"] = 0.8  # Invalid DKIM - high risk
                except Exception as e:
                    # Error during verification is moderately suspicious
                    # Could be implementation issues or intentional obfuscation
                    logger.warning(f"Error verifying DKIM signature: {e}")
                    result["risk_score"] = 0.6  # Error verifying - medium-high risk
            else:
                # No DKIM signature is somewhat suspicious but not definitively malicious
                # Many legitimate emails still don't implement DKIM
                result["risk_score"] = 0.5
        
        except Exception as e:
            # General exception during DKIM checking
            logger.warning(f"Could not check DKIM signature: {e}")
        
        return result
    
    def check_dmarc_record(self, domain):
        """
        Check if a domain has a DMARC record and analyze its configuration.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: DMARC record information
        """
        result = {
            "has_dmarc": False,
            "dmarc_record": None,
            "dmarc_policy": None,
            "dmarc_subdomain_policy": None,
            "dmarc_pct": None,
            "dmarc_rua": None,
            "dmarc_ruf": None,
            "risk_score": 0.5  # Default medium risk
        }
        
        try:
            # DMARC records are stored as TXT records at _dmarc.domain
            # This is the standard location defined in RFC 7489
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_record = rdata.to_text()
                
                # Check if this is a DMARC record by looking for the version tag
                # Valid DMARC records must start with v=DMARC1
                if "v=DMARC1" in txt_record:
                    # Found a valid DMARC record
                    result["has_dmarc"] = True
                    result["dmarc_record"] = txt_record
                    
                    # Extract the policy (p=) - this is the core of DMARC
                    # Policy determines what happens to emails that fail authentication
                    # Values: none (monitor), quarantine (mark as suspicious), reject (block)
                    policy_match = re.search(r'p=(\w+)', txt_record)
                    if policy_match:
                        result["dmarc_policy"] = policy_match.group(1)
                    
                    # Extract subdomain policy (sp=)
                    # This is the policy for subdomains of the main domain
                    # If not specified, defaults to the main policy (p=)
                    sp_match = re.search(r'sp=(\w+)', txt_record)
                    if sp_match:
                        result["dmarc_subdomain_policy"] = sp_match.group(1)
                    
                    # Extract percentage (pct=)
                    # Controls what percentage of messages should be subject to policy
                    # Useful for gradual policy rollout (e.g., 10%, 50%, 100%)
                    pct_match = re.search(r'pct=(\d+)', txt_record)
                    if pct_match:
                        result["dmarc_pct"] = int(pct_match.group(1))
                    
                    # Extract aggregate report URI (rua=)
                    # Where to send aggregate reports about authentication results
                    # Typically an email address with mailto: prefix
                    rua_match = re.search(r'rua=mailto:([^;]+)', txt_record)
                    if rua_match:
                        result["dmarc_rua"] = rua_match.group(1)
                    
                    # Extract forensic report URI (ruf=)
                    # Where to send detailed forensic reports about authentication failures
                    # More detailed than aggregate reports
                    ruf_match = re.search(r'ruf=mailto:([^;]+)', txt_record)
                    if ruf_match:
                        result["dmarc_ruf"] = ruf_match.group(1)
                    
                    # Assign risk score based on DMARC policy strength
                    # Stronger policies indicate better email security practices
                    if result["dmarc_policy"] == "reject":
                        # Reject policy - strongest protection, lowest risk
                        # Domain owner is actively blocking unauthenticated emails
                        result["risk_score"] = 0.1  # Very low risk
                    elif result["dmarc_policy"] == "quarantine":
                        # Quarantine policy - medium protection
                        # Domain owner is marking suspicious emails but not blocking
                        result["risk_score"] = 0.2  # Low risk
                    else:  # "none" or other policies
                        # None/monitoring policy - weakest protection
                        # Domain owner is only monitoring, not enforcing
                        result["risk_score"] = 0.3  # Moderate-low risk
                    
                    break
            
            # If no DMARC record was found, increase the risk score
            # Missing DMARC is a significant security gap
            if not result["has_dmarc"]:
                result["risk_score"] = 0.7
        
        except Exception as e:
            # Handle any unexpected errors during DMARC lookup
            logger.warning(f"Could not check DMARC record for {domain}: {e}")
            
        return result
    
    def check_domain_reputation(self, domain):
        """
        Check domain reputation using various sources.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: Domain reputation information
        """
        result = {
            "reputation_score": 0.5,  # Default neutral score
            "blacklisted": False,
            "blacklist_count": 0,
            "sources": [],
            "risk_score": 0.5  # Default medium risk
        }
        
        # Check the in-memory cache first for performance optimization
        # This prevents repeated lookups for the same domain within a session
        if domain in self.reputation_cache:
            return self.reputation_cache[domain]
        
        try:
            # Fast path: Check if domain is in our predefined trusted domains list
            # These are known legitimate domains that don't need further verification
            if domain in self.trusted_domains:
                # Trusted domains get high reputation and low risk scores
                result["reputation_score"] = 0.9  # High reputation
                result["risk_score"] = 0.1  # Low risk
                
                # Store in cache for future lookups
                self.reputation_cache[domain] = result
                return result
            
            # Lookup domain in local reputation database if available
            # This allows for offline operation and custom reputation data
            if self.reputation_db is not None:
                # Filter the database to find the domain
                domain_data = self.reputation_db[self.reputation_db['domain'] == domain]
                
                # Process the domain if found in the database
                if not domain_data.empty:
                    # Extract reputation data from the database row
                    result["reputation_score"] = float(domain_data['reputation_score'].iloc[0])
                    result["blacklisted"] = bool(domain_data['blacklisted'].iloc[0])
                    result["blacklist_count"] = int(domain_data['blacklist_count'].iloc[0])
                    result["sources"] = domain_data['sources'].iloc[0].split(',')
                    
                    # Convert reputation score to risk score (inverse relationship)
                    # Higher reputation = lower risk
                    result["risk_score"] = 1.0 - result["reputation_score"]
                    
                    # Cache the result for future lookups
                    self.reputation_cache[domain] = result
        
        except Exception as e:
            # Handle any unexpected errors during reputation lookup
            logger.error(f"Error checking domain reputation for {domain}: {e}")
            
        return result
    
    def check_domain_typosquatting(self, domain):
        """
        Check if a domain might be typosquatting a trusted domain.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: Typosquatting check information
        """
        result = {
            "is_suspicious": False,
            "similar_to": None,
            "similarity_score": 0.0,
            "risk_score": 0.0
        }
        
        # Skip check for trusted domains
        if domain in self.trusted_domains:
            return result
        
        try:
            # Use Levenshtein distance algorithm to detect similarity between strings
            # This algorithm measures the minimum number of single-character edits
            # needed to change one string into another
            from Levenshtein import distance
            
            min_distance = float('inf')  # Initialize with infinity
            most_similar = None
            
            # Compare against each trusted domain to find potential typosquatting
            for trusted_domain in self.trusted_domains:
                # Calculate edit distance between the domain and trusted domain
                dist = distance(domain, trusted_domain)
                
                # Normalize the distance by the length of the longer domain
                # This provides a more accurate measure of similarity regardless of length
                max_len = max(len(domain), len(trusted_domain))
                normalized_dist = dist / max_len if max_len > 0 else 1.0
                similarity = 1.0 - normalized_dist  # Convert distance to similarity score
                
                # Track the most similar trusted domain
                if dist < min_distance:
                    min_distance = dist
                    most_similar = trusted_domain
                    result["similarity_score"] = similarity
            
            # If the domain is very similar to a trusted domain but not identical
            # Typosquatting typically involves 1-2 character differences
            if most_similar and domain != most_similar and min_distance <= 2:
                result["is_suspicious"] = True
                result["similar_to"] = most_similar
                
                # Assign risk score based on similarity
                if min_distance == 1:
                    # One character difference - very suspicious
                    # Examples: paypa1.com, arnazon.com (1 vs l, m vs rn)
                    result["risk_score"] = 0.9
                else:  # min_distance == 2
                    # Two character difference - suspicious but less so
                    # Examples: paypall.com, amazzon.com
                    result["risk_score"] = 0.7
            
        except ImportError:
            # Levenshtein package is required for this check
            logger.warning("Levenshtein package not available, skipping typosquatting check")
        except Exception as e:
            # Handle any unexpected errors during analysis
            logger.error(f"Error checking typosquatting for {domain}: {e}")
        
        return result
    
    def check_sender_domain_alignment(self, email_content, sender):
        """
        Check if the sender domain aligns with the domains in From, Return-Path, and Reply-To headers.
        
        Args:
            email_content (str): Raw email content
            sender (str): Email sender
            
        Returns:
            dict: Domain alignment analysis
        """
        result = {
            "is_aligned": True,
            "misaligned_headers": [],
            "risk_score": 0.0
        }
        
        try:
            # Parse the email into a structured message object for header analysis
            email_message = email_parser.Parser().parsestr(email_content)
            
            # Extract sender domain from the provided sender email address
            # Domain alignment requires comparing this against other header domains
            _, sender_domain = self.parse_email_address(sender)
            
            # Return early if sender domain couldn't be parsed
            if not sender_domain:
                return result
            
            # Check From header domain alignment
            # The From header should match the envelope sender domain in legitimate emails
            from_header = email_message.get('From', '')
            from_match = re.search(r'@([^>\s]+)', from_header)
            if from_match:
                from_domain = from_match.group(1)
                # Compare domains and flag misalignment
                if from_domain != sender_domain:
                    result["is_aligned"] = False
                    result["misaligned_headers"].append(f"From: {from_domain}")
            
            # Check Return-Path header alignment
            # Return-Path indicates where bounces should be sent and should match sender domain
            return_path = email_message.get('Return-Path', '')
            return_path_match = re.search(r'<([^>]+)>', return_path)
            if return_path_match:
                return_path_email = return_path_match.group(1)
                _, return_path_domain = self.parse_email_address(return_path_email)
                # Check for domain mismatch if a domain was successfully extracted
                if return_path_domain and return_path_domain != sender_domain:
                    result["is_aligned"] = False
                    result["misaligned_headers"].append(f"Return-Path: {return_path_domain}")
            
            # Check Reply-To header alignment
            # Phishers often use mismatched Reply-To to capture responses
            reply_to = email_message.get('Reply-To', '')
            reply_to_match = re.search(r'([^<\s]+@[^>\s]+)', reply_to)
            if reply_to_match:
                reply_to_email = reply_to_match.group(1)
                _, reply_to_domain = self.parse_email_address(reply_to_email)
                # Check for domain mismatch if a domain was successfully extracted
                if reply_to_domain and reply_to_domain != sender_domain:
                    result["is_aligned"] = False
                    result["misaligned_headers"].append(f"Reply-To: {reply_to_domain}")
            
            # Assign risk score based on alignment
            # Domain misalignment is a strong indicator of phishing
            # Legitimate organizations maintain alignment across all headers
            if not result["is_aligned"]:
                result["risk_score"] = 0.8  # High risk if domains are misaligned
        
        except Exception as e:
            # Handle any unexpected errors during analysis
            logger.error(f"Error checking domain alignment: {e}")
        
        return result
    
    def analyze_sender(self, email_address, email_content=None):
        """
        Analyze an email sender for phishing indicators.
        
        Args:
            email_address (str): Email address to analyze
            email_content (str): Raw email content for additional checks
            
        Returns:
            dict: Analysis results
        """
        result = {
            "sender": email_address,
            "username": None,
            "domain": None,
            "risk_score": 0.5,  # Default medium risk
            "analysis_details": {}
        }
        
        try:
            # Step 1: Parse and validate the email address format
            # This is the foundation for all subsequent checks
            username, domain = self.parse_email_address(email_address)
            
            # If domain parsing fails, return high risk score
            # Invalid email formats are strongly associated with phishing
            if not domain:
                result["risk_score"] = 0.8  # High risk if we can't parse the domain
                return result
            
            # Store parsed components for reference
            result["username"] = username
            result["domain"] = domain
            
            # Step 2: Perform comprehensive domain analysis
            # Start with domain age check - newly registered domains are suspicious
            domain_age_result = self.check_domain_age(domain)
            result["analysis_details"]["domain_age"] = domain_age_result
            
            # Step 3: Check domain reputation against known databases
            # Reputation is a strong indicator of legitimacy
            reputation_result = self.check_domain_reputation(domain)
            result["analysis_details"]["domain_reputation"] = reputation_result
            
            # Step 4: Look for potential typosquatting attempts
            # Detects domains similar to trusted ones (e.g., arnazon vs amazon)
            typosquatting_result = self.check_domain_typosquatting(domain)
            result["analysis_details"]["typosquatting"] = typosquatting_result
            
            # Step 5: Verify SPF record implementation and policy
            # SPF helps prevent sender address forgery
            spf_result = self.check_spf_record(domain)
            result["analysis_details"]["spf"] = spf_result
            
            # Step 6: Check DMARC policy implementation
            # DMARC provides instructions for handling failed authentication
            dmarc_result = self.check_dmarc_record(domain)
            result["analysis_details"]["dmarc"] = dmarc_result
            
            # Step 7: Perform additional checks if email content is provided
            if email_content:
                # Verify DKIM signature cryptographically
                # DKIM ensures email hasn't been modified in transit
                dkim_result = self.check_dkim_signature(email_content)
                result["analysis_details"]["dkim"] = dkim_result
                
                # Check for header alignment across different parts of the email
                # Misaligned headers often indicate spoofing attempts
                alignment_result = self.check_sender_domain_alignment(email_content, email_address)
                result["analysis_details"]["domain_alignment"] = alignment_result
            
            # Step 8: Calculate overall risk score using weighted average of all factors
            # Different checks have different importance in determining phishing likelihood
            weights = {
                "domain_age": 0.15,         # Newer domains are higher risk
                "domain_reputation": 0.25,  # Reputation is a strong signal
                "typosquatting": 0.2,       # Brand impersonation is common in phishing
                "spf": 0.1,                 # Authentication record presence
                "dmarc": 0.1,               # Policy enforcement instructions
                "dkim": 0.1,                # Message integrity verification
                "domain_alignment": 0.1     # Header consistency check
            }
            
            # Initialize weighted calculation variables
            weighted_score = 0.0
            total_weight = 0.0
            
            # Calculate weighted score based on available analysis components
            # Skip missing components (e.g., if email_content wasn't provided for DKIM)
            for key, weight in weights.items():
                if key in result["analysis_details"]:
                    weighted_score += result["analysis_details"][key]["risk_score"] * weight
                    total_weight += weight
            
            # Finalize risk score as weighted average if we have any weights
            if total_weight > 0:
                result["risk_score"] = weighted_score / total_weight
        
        except Exception as e:
            # Handle any unexpected errors during analysis
            logger.error(f"Error analyzing sender {email_address}: {e}")
            result["error"] = str(e)
        
        return result

# Example usage
if __name__ == "__main__":
    analyzer = SenderAnalyzer()
    
    # Test with a legitimate email
    result = analyzer.analyze_sender("info@gmail.com")
    print(f"Gmail analysis: {result['risk_score']:.2f} risk score")
    
    # Test with a suspicious email
    result = analyzer.analyze_sender("security@amaz0n-secure.com")
    print(f"Suspicious analysis: {result['risk_score']:.2f} risk score") 