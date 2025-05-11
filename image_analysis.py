import os
import cv2
import numpy as np
import requests
from io import BytesIO
from PIL import Image
import logging
import base64
import re
from urllib.parse import urlparse
import pytesseract
import io
import tempfile
import hashlib
from typing import Dict, List, Any, Tuple, Optional, Union
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("image_analysis")

class ImageAnalyzer:
    """
    Class to analyze images in emails for phishing indicators.
    Detects brand logos, OCR on images to find hidden text,
    and analyzes for common phishing visual patterns.
    """
    
    def __init__(self, logo_db_path=None, tesseract_path=None):
        """
        Initialize the image analyzer.
        
        Args:
            logo_db_path (str): Path to logo database directory
            tesseract_path (str): Path to tesseract executable
        """
        self.logo_db_path = logo_db_path or "logo_database"
        
        # Create logo database directory if it doesn't exist
        if not os.path.exists(self.logo_db_path):
            try:
                os.makedirs(self.logo_db_path)
                logger.info(f"Created logo database directory: {self.logo_db_path}")
            except Exception as e:
                logger.error(f"Failed to create logo database directory: {e}")
        
        # Set tesseract path if provided
        if tesseract_path:
            pytesseract.pytesseract.tesseract_cmd = tesseract_path
        
        # Load brand logos
        self.brand_logos = self._load_brand_logos()
        
        # Common brand names for detection
        self.common_brands = [
            "paypal", "apple", "microsoft", "amazon", "google", "facebook",
            "instagram", "twitter", "netflix", "bank of america", "chase",
            "wells fargo", "citibank", "linkedin", "dropbox", "gmail",
            "outlook", "office365", "yahoo", "spotify", "steam", "discord"
        ]
        
        # Initialize SIFT detector for logo matching
        self.sift = cv2.SIFT_create()
        
        # FLANN parameters for fast matching
        FLANN_INDEX_KDTREE = 1
        index_params = dict(algorithm=FLANN_INDEX_KDTREE, trees=5)
        search_params = dict(checks=50)
        self.flann = cv2.FlannBasedMatcher(index_params, search_params)
    
    def _load_brand_logos(self) -> Dict[str, Dict]:
        """
        Load brand logos from the logo database.
        
        Returns:
            dict: Dictionary of brand logos with their features
        """
        brand_logos = {}
        
        try:
            if not os.path.exists(self.logo_db_path):
                logger.warning(f"Logo database path does not exist: {self.logo_db_path}")
                return brand_logos
            
            # Load each logo file
            for filename in os.listdir(self.logo_db_path):
                if filename.endswith(('.png', '.jpg', '.jpeg')):
                    try:
                        # Extract brand name from filename
                        brand_name = os.path.splitext(filename)[0].lower()
                        
                        # Load logo image
                        logo_path = os.path.join(self.logo_db_path, filename)
                        logo_img = cv2.imread(logo_path, cv2.IMREAD_COLOR)
                        
                        if logo_img is not None:
                            # Convert to grayscale
                            gray_logo = cv2.cvtColor(logo_img, cv2.COLOR_BGR2GRAY)
                            
                            # Compute SIFT keypoints and descriptors
                            keypoints, descriptors = self.sift.detectAndCompute(gray_logo, None)
                            
                            # Store logo data
                            brand_logos[brand_name] = {
                                'image': logo_img,
                                'gray': gray_logo,
                                'keypoints': keypoints,
                                'descriptors': descriptors
                            }
                            
                            logger.info(f"Loaded logo for brand: {brand_name}")
                    except Exception as e:
                        logger.error(f"Error loading logo {filename}: {e}")
            
            logger.info(f"Loaded {len(brand_logos)} brand logos")
        
        except Exception as e:
            logger.error(f"Error loading brand logos: {e}")
        
        return brand_logos
    
    def add_brand_logo(self, brand_name: str, logo_image: Union[str, bytes, np.ndarray]) -> bool:
        """
        Add a new brand logo to the database.
        
        Args:
            brand_name (str): Name of the brand
            logo_image (str/bytes/ndarray): Logo image file path, bytes, or numpy array
            
        Returns:
            bool: Success or failure
        """
        try:
            # Normalize brand name
            brand_name = brand_name.lower().replace(' ', '_')
            
            # Convert image to OpenCV format
            if isinstance(logo_image, str):
                # It's a file path
                img = cv2.imread(logo_image, cv2.IMREAD_COLOR)
            elif isinstance(logo_image, bytes):
                # It's image bytes
                nparr = np.frombuffer(logo_image, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            elif isinstance(logo_image, np.ndarray):
                # It's already a numpy array
                img = logo_image
            else:
                logger.error(f"Unsupported image type: {type(logo_image)}")
                return False
            
            if img is None:
                logger.error("Failed to load logo image")
                return False
            
            # Save logo to database
            logo_path = os.path.join(self.logo_db_path, f"{brand_name}.png")
            cv2.imwrite(logo_path, img)
            
            # Update in-memory database
            gray_logo = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            keypoints, descriptors = self.sift.detectAndCompute(gray_logo, None)
            
            self.brand_logos[brand_name] = {
                'image': img,
                'gray': gray_logo,
                'keypoints': keypoints,
                'descriptors': descriptors
            }
            
            logger.info(f"Added logo for brand: {brand_name}")
            return True
        
        except Exception as e:
            logger.error(f"Error adding brand logo: {e}")
            return False
    
    def extract_images_from_email(self, email_content: str) -> List[Dict[str, Any]]:
        """
        Extract images from email content.
        
        Args:
            email_content (str): Raw email content
            
        Returns:
            list: List of extracted images with metadata
        """
        extracted_images = []
        
        try:
            # Extract base64 encoded images
            pattern = r'src="data:image/([^;]+);base64,([^"]+)"'
            matches = re.finditer(pattern, email_content)
            
            for match in matches:
                image_type = match.group(1)
                base64_data = match.group(2)
                
                try:
                    # Decode base64 data
                    image_data = base64.b64decode(base64_data)
                    
                    # Convert to OpenCV image
                    nparr = np.frombuffer(image_data, np.uint8)
                    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    
                    if img is not None:
                        # Generate a hash of the image for deduplication
                        img_hash = hashlib.md5(image_data).hexdigest()
                        
                        extracted_images.append({
                            'image': img,
                            'type': image_type,
                            'hash': img_hash,
                            'source': 'inline',
                            'size': img.shape
                        })
                
                except Exception as e:
                    logger.warning(f"Error decoding inline image: {e}")
            
            # Extract linked images
            pattern = r'<img[^>]+src="(https?://[^"]+)"'
            matches = re.finditer(pattern, email_content)
            
            for match in matches:
                image_url = match.group(1)
                
                try:
                    # Download image
                    response = requests.get(image_url, timeout=5)
                    image_data = response.content
                    
                    # Convert to OpenCV image
                    nparr = np.frombuffer(image_data, np.uint8)
                    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                    
                    if img is not None:
                        # Generate a hash of the image for deduplication
                        img_hash = hashlib.md5(image_data).hexdigest()
                        
                        # Extract image type from URL or content-type
                        image_type = os.path.splitext(image_url)[1].lstrip('.')
                        if not image_type and 'content-type' in response.headers:
                            content_type = response.headers['content-type']
                            if 'image/' in content_type:
                                image_type = content_type.split('image/')[1]
                        
                        extracted_images.append({
                            'image': img,
                            'type': image_type,
                            'hash': img_hash,
                            'source': 'remote',
                            'url': image_url,
                            'size': img.shape
                        })
                
                except Exception as e:
                    logger.warning(f"Error downloading image from {image_url}: {e}")
            
            logger.info(f"Extracted {len(extracted_images)} images from email")
        
        except Exception as e:
            logger.error(f"Error extracting images from email: {e}")
        
        return extracted_images
    
    def detect_brand_logos(self, image: np.ndarray) -> List[Dict[str, Any]]:
        """
        Detect brand logos in an image.
        
        Args:
            image (ndarray): Image to analyze
            
        Returns:
            list: Detected brands with confidence scores
        """
        detected_brands = []
        
        try:
            # Convert image to grayscale
            gray_img = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Compute SIFT keypoints and descriptors
            img_keypoints, img_descriptors = self.sift.detectAndCompute(gray_img, None)
            
            # No keypoints found
            if img_descriptors is None:
                return detected_brands
            
            # Match against each brand logo
            for brand_name, logo_data in self.brand_logos.items():
                logo_descriptors = logo_data['descriptors']
                
                # Skip if logo has no descriptors
                if logo_descriptors is None:
                    continue
                
                # Match descriptors using FLANN
                matches = self.flann.knnMatch(logo_descriptors, img_descriptors, k=2)
                
                # Apply ratio test to filter good matches
                good_matches = []
                for m, n in matches:
                    if m.distance < 0.7 * n.distance:
                        good_matches.append(m)
                
                # Calculate match confidence
                match_confidence = len(good_matches) / max(len(logo_descriptors), 1)
                
                # If enough good matches, consider it a detection
                if len(good_matches) >= 10 and match_confidence > 0.1:
                    detected_brands.append({
                        'brand': brand_name,
                        'confidence': float(match_confidence),
                        'matches': len(good_matches)
                    })
            
            # Sort by confidence
            detected_brands.sort(key=lambda x: x['confidence'], reverse=True)
        
        except Exception as e:
            logger.error(f"Error detecting brand logos: {e}")
        
        return detected_brands
    
    def extract_text_from_image(self, image: np.ndarray) -> str:
        """
        Extract text from an image using OCR.
        
        Args:
            image (ndarray): Image to analyze
            
        Returns:
            str: Extracted text
        """
        try:
            # Convert to PIL Image
            pil_img = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
            
            # Use pytesseract for OCR
            text = pytesseract.image_to_string(pil_img)
            
            return text.strip()
        
        except Exception as e:
            logger.error(f"Error extracting text from image: {e}")
            return ""
    
    def detect_urls_in_image(self, image: np.ndarray) -> List[Dict[str, Any]]:
        """
        Detect URLs in an image using OCR.
        
        Args:
            image (ndarray): Image to analyze
            
        Returns:
            list: Detected URLs with context
        """
        detected_urls = []
        
        try:
            # Extract text from image
            text = self.extract_text_from_image(image)
            
            # Find URLs in text
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
            urls = re.findall(url_pattern, text)
            
            # Process each URL
            for url in urls:
                # Parse URL
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                
                detected_urls.append({
                    'url': url,
                    'domain': domain,
                    'text_context': self._get_url_context(text, url)
                })
            
            # Look for URL-like text that might be misleading
            # (e.g. "paypal-secure.com" without http://)
            domain_pattern = r'(?<!\w)(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}(?!\w)'
            domains = re.findall(domain_pattern, text)
            
            for domain in domains:
                # Check if this domain is already part of a detected URL
                if not any(domain in url['domain'] for url in detected_urls):
                    detected_urls.append({
                        'url': None,
                        'domain': domain,
                        'text_context': self._get_url_context(text, domain)
                    })
        
        except Exception as e:
            logger.error(f"Error detecting URLs in image: {e}")
        
        return detected_urls
    
    def _get_url_context(self, text: str, url: str) -> str:
        """
        Get the context around a URL in text.
        
        Args:
            text (str): Full text
            url (str): URL to find context for
            
        Returns:
            str: Context around the URL
        """
        try:
            # Find the position of the URL in the text
            pos = text.find(url)
            
            if pos >= 0:
                # Get some context before and after the URL
                start = max(0, pos - 50)
                end = min(len(text), pos + len(url) + 50)
                
                # Extract context
                context = text[start:end].strip()
                
                # Highlight the URL in the context
                if pos - start > 0:
                    context_before = context[:pos - start]
                    context_url = context[pos - start:pos - start + len(url)]
                    context_after = context[pos - start + len(url):]
                    return f"{context_before}[{context_url}]{context_after}"
                else:
                    return context
            
            return ""
        
        except Exception as e:
            logger.error(f"Error getting URL context: {e}")
            return ""
    
    def detect_brand_impersonation(self, image: np.ndarray, text: str) -> Dict[str, Any]:
        """
        Detect potential brand impersonation in an image.
        
        Args:
            image (ndarray): Image to analyze
            text (str): Text extracted from the image
            
        Returns:
            dict: Brand impersonation analysis
        """
        result = {
            "is_impersonation": False,
            "brand": None,
            "confidence": 0.0,
            "risk_score": 0.0,
            "mismatched_urls": []
        }
        
        try:
            # Detect brand logos
            detected_brands = self.detect_brand_logos(image)
            
            # If no brands detected visually, check text for brand mentions
            if not detected_brands:
                for brand in self.common_brands:
                    if brand.lower() in text.lower():
                        detected_brands.append({
                            'brand': brand,
                            'confidence': 0.6,
                            'matches': 1
                        })
            
            # If still no brands detected, return
            if not detected_brands:
                return result
            
            # Get the most confident brand detection
            top_brand = detected_brands[0]
            result["brand"] = top_brand["brand"]
            result["confidence"] = top_brand["confidence"]
            
            # Detect URLs in the image
            detected_urls = self.detect_urls_in_image(image)
            
            # Check if URLs match the detected brand
            brand_domain = result["brand"].replace('_', '')
            
            for url_info in detected_urls:
                domain = url_info["domain"]
                
                # Check if the URL domain doesn't match the brand but might be trying to impersonate
                if brand_domain not in domain and any(brand_domain in d for d in self._generate_typos(brand_domain)):
                    result["is_impersonation"] = True
                    result["mismatched_urls"].append(url_info)
            
            # Calculate risk score
            if result["is_impersonation"]:
                result["risk_score"] = 0.9  # High risk
            elif result["brand"] and detected_urls:
                result["risk_score"] = 0.5  # Medium risk - brand and URLs present but no clear impersonation
            else:
                result["risk_score"] = 0.2  # Low risk
        
        except Exception as e:
            logger.error(f"Error detecting brand impersonation: {e}")
        
        return result
    
    def _generate_typos(self, domain: str) -> List[str]:
        """
        Generate common typosquatting variations of a domain.
        
        Args:
            domain (str): Original domain
            
        Returns:
            list: Typosquatting variations
        """
        typos = []
        
        # Common typosquatting techniques
        # Character substitution
        for i in range(len(domain)):
            for c in 'abcdefghijklmnopqrstuvwxyz0123456789-_':
                if c != domain[i]:
                    typo = domain[:i] + c + domain[i+1:]
                    typos.append(typo)
        
        # Character insertion
        for i in range(len(domain) + 1):
            for c in 'abcdefghijklmnopqrstuvwxyz0123456789-_':
                typo = domain[:i] + c + domain[i:]
                typos.append(typo)
        
        # Character deletion
        for i in range(len(domain)):
            typo = domain[:i] + domain[i+1:]
            typos.append(typo)
        
        # Character transposition
        for i in range(len(domain) - 1):
            typo = domain[:i] + domain[i+1] + domain[i] + domain[i+2:]
            typos.append(typo)
        
        # Common substitutions
        substitutions = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            'l': ['1'],
            'b': ['8'],
            't': ['7'],
            'g': ['9'],
            'z': ['2']
        }
        
        for i in range(len(domain)):
            if domain[i] in substitutions:
                for sub in substitutions[domain[i]]:
                    typo = domain[:i] + sub + domain[i+1:]
                    typos.append(typo)
        
        return typos
    
    def detect_url_manipulation(self, image: np.ndarray) -> Dict[str, Any]:
        """
        Detect potential URL manipulation in an image.
        
        Args:
            image (ndarray): Image to analyze
            
        Returns:
            dict: URL manipulation analysis
        """
        result = {
            "has_manipulated_urls": False,
            "suspicious_urls": [],
            "risk_score": 0.0
        }
        
        try:
            # Extract text from image
            text = self.extract_text_from_image(image)
            
            # Look for URLs with specific manipulation patterns
            
            # 1. Unicode homoglyphs (characters that look similar)
            homoglyph_pattern = r'https?://(?:[^\s<>"]|[^\x00-\x7F])+'
            homoglyph_matches = re.findall(homoglyph_pattern, text)
            
            for url in homoglyph_matches:
                # Check if URL contains non-ASCII characters
                if any(ord(c) > 127 for c in url):
                    result["has_manipulated_urls"] = True
                    result["suspicious_urls"].append({
                        "url": url,
                        "type": "homoglyph",
                        "risk": "high"
                    })
            
            # 2. Look for URLs with misleading text
            # This is a simplified version - in reality, you'd need more sophisticated analysis
            misleading_patterns = [
                (r'paypal.*\.(?!paypal\.com)', "PayPal impersonation"),
                (r'apple.*\.(?!apple\.com)', "Apple impersonation"),
                (r'microsoft.*\.(?!microsoft\.com)', "Microsoft impersonation"),
                (r'amazon.*\.(?!amazon\.com)', "Amazon impersonation"),
                (r'google.*\.(?!google\.com)', "Google impersonation"),
                (r'facebook.*\.(?!facebook\.com)', "Facebook impersonation"),
                (r'instagram.*\.(?!instagram\.com)', "Instagram impersonation"),
                (r'twitter.*\.(?!twitter\.com)', "Twitter impersonation"),
                (r'netflix.*\.(?!netflix\.com)', "Netflix impersonation"),
                (r'bank\s*of\s*america.*\.(?!bankofamerica\.com)', "Bank of America impersonation"),
                (r'chase.*\.(?!chase\.com)', "Chase Bank impersonation")
            ]
            
            for pattern, description in misleading_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    result["has_manipulated_urls"] = True
                    result["suspicious_urls"].append({
                        "url": "Pattern match: " + description,
                        "type": "brand_impersonation",
                        "risk": "high"
                    })
            
            # 3. Look for URLs with suspicious TLDs
            suspicious_tlds = ['.tk', '.ga', '.cf', '.ml', '.gq', '.xyz', '.top', '.club']
            tld_pattern = r'https?://[^\s<>"]+(' + '|'.join(suspicious_tlds) + r')'
            tld_matches = re.findall(tld_pattern, text, re.IGNORECASE)
            
            if tld_matches:
                result["has_manipulated_urls"] = True
                result["suspicious_urls"].append({
                    "url": "Suspicious TLD detected",
                    "type": "suspicious_tld",
                    "risk": "medium"
                })
            
            # Calculate risk score based on findings
            if result["has_manipulated_urls"]:
                high_risk_count = sum(1 for url in result["suspicious_urls"] if url["risk"] == "high")
                medium_risk_count = sum(1 for url in result["suspicious_urls"] if url["risk"] == "medium")
                
                # Weight high risk more heavily
                result["risk_score"] = min(0.9, (high_risk_count * 0.3 + medium_risk_count * 0.15))
        
        except Exception as e:
            logger.error(f"Error detecting URL manipulation: {e}")
        
        return result
    
    def analyze_image(self, image: np.ndarray) -> Dict[str, Any]:
        """
        Comprehensive analysis of an image for phishing indicators.
        
        Args:
            image (ndarray): Image to analyze
            
        Returns:
            dict: Analysis results
        """
        result = {
            "image_size": image.shape,
            "has_text": False,
            "extracted_text": "",
            "detected_brands": [],
            "detected_urls": [],
            "brand_impersonation": None,
            "url_manipulation": None,
            "risk_score": 0.0,
            "risk_factors": []
        }
        
        try:
            # Extract text from image
            text = self.extract_text_from_image(image)
            result["extracted_text"] = text
            result["has_text"] = len(text.strip()) > 0
            
            # Detect brand logos
            result["detected_brands"] = self.detect_brand_logos(image)
            
            # Detect URLs in image
            result["detected_urls"] = self.detect_urls_in_image(image)
            
            # Detect brand impersonation
            result["brand_impersonation"] = self.detect_brand_impersonation(image, text)
            
            # Detect URL manipulation
            result["url_manipulation"] = self.detect_url_manipulation(image)
            
            # Calculate overall risk score
            risk_scores = []
            
            # Brand impersonation risk
            if result["brand_impersonation"]["is_impersonation"]:
                risk_scores.append(result["brand_impersonation"]["risk_score"])
                result["risk_factors"].append("Brand impersonation detected")
            
            # URL manipulation risk
            if result["url_manipulation"]["has_manipulated_urls"]:
                risk_scores.append(result["url_manipulation"]["risk_score"])
                result["risk_factors"].append("URL manipulation detected")
            
            # URLs in image risk (medium risk if URLs are present in image)
            if result["detected_urls"]:
                risk_scores.append(0.5)
                result["risk_factors"].append("URLs embedded in image")
            
            # Calculate final risk score
            if risk_scores:
                result["risk_score"] = max(risk_scores)  # Use maximum risk score
            
            # If no specific risks but image has text and brands, assign a low risk
            if not risk_scores and result["has_text"] and result["detected_brands"]:
                result["risk_score"] = 0.3
        
        except Exception as e:
            logger.error(f"Error analyzing image: {e}")
            result["error"] = str(e)
        
        return result
    
    def analyze_email_images(self, email_content: str) -> Dict[str, Any]:
        """
        Analyze all images in an email for phishing indicators.
        
        Args:
            email_content (str): Raw email content
            
        Returns:
            dict: Analysis results
        """
        result = {
            "image_count": 0,
            "analyzed_images": [],
            "overall_risk_score": 0.0,
            "risk_factors": []
        }
        
        try:
            # Extract images from email
            images = self.extract_images_from_email(email_content)
            result["image_count"] = len(images)
            
            if not images:
                return result
            
            # Analyze each image
            max_risk_score = 0.0
            
            for img_data in images:
                image = img_data['image']
                
                # Skip very small images (likely tracking pixels)
                if image.shape[0] < 20 or image.shape[1] < 20:
                    continue
                
                # Analyze image
                analysis = self.analyze_image(image)
                
                # Add source information
                analysis["source"] = img_data.get('source', 'unknown')
                if 'url' in img_data:
                    analysis["source_url"] = img_data['url']
                
                # Update max risk score
                max_risk_score = max(max_risk_score, analysis["risk_score"])
                
                # Add to analyzed images
                result["analyzed_images"].append(analysis)
                
                # Collect risk factors
                for factor in analysis["risk_factors"]:
                    if factor not in result["risk_factors"]:
                        result["risk_factors"].append(factor)
            
            # Set overall risk score
            result["overall_risk_score"] = max_risk_score
        
        except Exception as e:
            logger.error(f"Error analyzing email images: {e}")
            result["error"] = str(e)
        
        return result

# Example usage
if __name__ == "__main__":
    analyzer = ImageAnalyzer()
    
    # Example email content with an embedded image
    email_content = """
    <html>
    <body>
        <p>Please verify your account:</p>
        <img src="https://example.com/logo.png" alt="Company Logo">
    </body>
    </html>
    """
    
    results = analyzer.analyze_email_images(email_content)
    print(f"Found {results['image_count']} images, {len(results['analyzed_images'])} suspicious")
    print(f"Overall risk score: {results['overall_risk_score']:.2f}") 