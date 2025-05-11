import os
import sys
import json
import logging
import time
import psutil
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
import argparse
import pickle
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import tldextract

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("performance_optimizer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("performance_optimizer")

class PerformanceOptimizer:
    """
    Optimize the performance of the phishing detector by:
    1. Implementing caching for frequently accessed data
    2. Optimizing code for faster execution
    3. Reducing memory usage
    4. Adding parallel processing where beneficial
    """
    
    def __init__(self, config_path: str = "phishing_detector_config.json"):
        """
        Initialize the performance optimizer.
        
        Args:
            config_path (str): Path to configuration file
        """
        self.config_path = config_path
        self.config = self._load_config(config_path)
        
        # Create cache directory
        os.makedirs("cache", exist_ok=True)
        
        # Initialize cache for domain reputation
        self.domain_cache_file = "cache/domain_reputation_cache.pkl"
        self.domain_cache = self._load_cache(self.domain_cache_file)
        
        # Initialize cache for URL analysis
        self.url_cache_file = "cache/url_analysis_cache.pkl"
        self.url_cache = self._load_cache(self.url_cache_file)
        
        # Initialize cache for embeddings
        self.embedding_cache_file = "cache/embedding_cache.pkl"
        self.embedding_cache = self._load_cache(self.embedding_cache_file)
        
        # Set cache TTL (time to live) in seconds
        self.cache_ttl = self.config.get("vector_database", {}).get("cache_ttl", 300)
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from JSON file.
        
        Args:
            config_path (str): Path to configuration file
            
        Returns:
            dict: Configuration dictionary
        """
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {config_path}")
                return config
            else:
                logger.warning(f"Configuration file not found: {config_path}")
                return {}
                
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return {}
    
    def _load_cache(self, cache_file: str) -> Dict[str, Any]:
        """
        Load cache from file.
        
        Args:
            cache_file (str): Path to cache file
            
        Returns:
            dict: Cache dictionary
        """
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'rb') as f:
                    cache = pickle.load(f)
                logger.info(f"Loaded cache from {cache_file}: {len(cache)} entries")
                return cache
            else:
                logger.info(f"Cache file not found: {cache_file}")
                return {}
                
        except Exception as e:
            logger.error(f"Error loading cache: {e}")
            return {}
    
    def _save_cache(self, cache: Dict[str, Any], cache_file: str):
        """
        Save cache to file.
        
        Args:
            cache (dict): Cache dictionary
            cache_file (str): Path to cache file
        """
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(cache, f)
            logger.info(f"Saved cache to {cache_file}: {len(cache)} entries")
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
    
    def _clean_cache(self, cache: Dict[str, Any]) -> Dict[str, Any]:
        """
        Clean expired entries from cache.
        
        Args:
            cache (dict): Cache dictionary
            
        Returns:
            dict: Cleaned cache dictionary
        """
        current_time = time.time()
        cleaned_cache = {}
        
        for key, (value, timestamp) in cache.items():
            if current_time - timestamp < self.cache_ttl:
                cleaned_cache[key] = (value, timestamp)
        
        logger.info(f"Cleaned cache: {len(cache)} -> {len(cleaned_cache)} entries")
        return cleaned_cache
    
    def optimize_url_analysis(self):
        """
        Optimize URL analysis by implementing caching for domain reputation
        and redirect chains.
        
        Returns:
            bool: Success or failure
        """
        try:
            # Check if url_analysis.py exists
            if not os.path.exists("url_analysis.py"):
                logger.error("url_analysis.py not found")
                return False
            
            # Read the file
            with open("url_analysis.py", 'r') as f:
                content = f.read()
            
            # Check if already optimized
            if "def get_cached_domain_info" in content:
                logger.info("URL analysis already optimized")
                return True
            
            # Add caching functions
            cache_functions = """
    def get_cached_domain_info(self, domain):
        \"\"\"
        Get domain information from cache or analyze it.
        
        Args:
            domain (str): Domain to analyze
            
        Returns:
            dict: Domain analysis results
        \"\"\"
        current_time = time.time()
        
        # Check if domain is in cache and not expired
        if domain in self.domain_cache:
            result, timestamp = self.domain_cache[domain]
            if current_time - timestamp < 300:  # 5 minutes TTL
                return result
        
        # Analyze domain
        result = self.analyze_domain(domain)
        
        # Cache result
        self.domain_cache[domain] = (result, current_time)
        
        # Save cache periodically (1% chance to avoid too frequent disk I/O)
        if np.random.random() < 0.01:
            self._save_domain_cache()
        
        return result
    
    def _save_domain_cache(self):
        \"\"\"
        Save domain cache to file.
        \"\"\"
        try:
            with open("cache/domain_reputation_cache.pkl", 'wb') as f:
                pickle.dump(self.domain_cache, f)
        except Exception as e:
            logger.error(f"Error saving domain cache: {e}")
    
    def _load_domain_cache(self):
        \"\"\"
        Load domain cache from file.
        
        Returns:
            dict: Domain cache
        \"\"\"
        try:
            if os.path.exists("cache/domain_reputation_cache.pkl"):
                with open("cache/domain_reputation_cache.pkl", 'rb') as f:
                    return pickle.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading domain cache: {e}")
            return {}
"""
            
            # Add cache initialization to __init__
            init_replacement = """
    def __init__(self, max_redirects=5, timeout=3):
        \"\"\"
        Initialize the URL analyzer.
        
        Args:
            max_redirects (int): Maximum number of redirects to follow
            timeout (int): Timeout for HTTP requests in seconds
        \"\"\"
        self.max_redirects = max_redirects
        self.timeout = timeout
        
        # Create cache directory
        os.makedirs("cache", exist_ok=True)
        
        # Initialize domain cache
        self.domain_cache = self._load_domain_cache()
        
        # Common URL shorteners
"""
            
            # Replace analyze_email_urls to use caching
            analyze_urls_replacement = """
    def analyze_email_urls(self, email_content):
        \"\"\"
        Extract and analyze all URLs in an email.
        
        Args:
            email_content (str): Raw email content
            
        Returns:
            dict: Analysis results
        \"\"\"
        result = {
            "urls_found": [],
            "suspicious_urls": [],
            "redirect_chains": {},
            "risk_score": 0.0,
            "is_suspicious": False,
            "reasons": []
        }
        
        try:
            # Extract URLs
            urls = self.extract_urls(email_content)
            result["urls_found"] = urls
            
            if not urls:
                return result
            
            # Analyze URLs in parallel
            with ThreadPoolExecutor(max_workers=min(10, len(urls))) as executor:
                future_to_url = {executor.submit(self.analyze_url, url): url for url in urls}
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        url_result = future.result()
                        
                        # Add redirect chain if available
                        if "redirect_chain" in url_result:
                            result["redirect_chains"][url] = url_result["redirect_chain"]
                        
                        # Check if URL is suspicious
                        if url_result.get("is_suspicious", False):
                            result["suspicious_urls"].append(url)
                            result["reasons"].extend(url_result.get("reasons", []))
                    except Exception as e:
                        logger.error(f"Error analyzing URL {url}: {e}")
            
            # Remove duplicate reasons
            result["reasons"] = list(set(result["reasons"]))
            
            # Calculate overall risk score
            if result["suspicious_urls"]:
                # Average risk score of suspicious URLs
                risk_scores = []
                
                for url in result["suspicious_urls"]:
                    url_result = self.analyze_url(url)
                    risk_scores.append(url_result.get("risk_score", 0.5))
                
                if risk_scores:
                    result["risk_score"] = sum(risk_scores) / len(risk_scores)
                    result["is_suspicious"] = result["risk_score"] > 0.5
            
        except Exception as e:
            logger.error(f"Error analyzing email URLs: {e}")
        
        return result
"""
            
            # Add imports
            imports_addition = """import time
import pickle
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
"""
            
            # Update the content
            updated_content = content
            
            # Add imports if not already present
            if "import time" not in content:
                import_end = content.find("# Configure logging")
                updated_content = content[:import_end] + imports_addition + "\n" + content[import_end:]
            
            # Replace __init__ method
            init_start = updated_content.find("def __init__")
            init_end = updated_content.find("# Common URL shorteners")
            if init_start != -1 and init_end != -1:
                updated_content = updated_content[:init_start] + init_replacement + updated_content[init_end:]
            
            # Add cache functions before analyze_email_urls
            analyze_urls_start = updated_content.find("def analyze_email_urls")
            if analyze_urls_start != -1:
                updated_content = updated_content[:analyze_urls_start] + cache_functions + "\n" + updated_content[analyze_urls_start:]
            
            # Replace analyze_email_urls method
            analyze_urls_start = updated_content.find("def analyze_email_urls")
            if analyze_urls_start != -1:
                analyze_urls_end = updated_content.find("def", analyze_urls_start + 1)
                if analyze_urls_end != -1:
                    updated_content = updated_content[:analyze_urls_start] + analyze_urls_replacement + updated_content[analyze_urls_end:]
            
            # Write the updated file
            with open("url_analysis.py", 'w') as f:
                f.write(updated_content)
            
            logger.info("URL analysis optimized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error optimizing URL analysis: {e}")
            return False
    
    def optimize_llm_analysis(self):
        """
        Optimize LLM analysis by implementing caching for embeddings.
        
        Returns:
            bool: Success or failure
        """
        try:
            # Check if advanced_llm_analysis.py exists
            if not os.path.exists("advanced_llm_analysis.py"):
                logger.error("advanced_llm_analysis.py not found")
                return False
            
            # Read the file
            with open("advanced_llm_analysis.py", 'r') as f:
                content = f.read()
            
            # Check if already optimized
            if "def get_cached_embedding" in content:
                logger.info("LLM analysis already optimized")
                return True
            
            # Add caching functions
            cache_functions = """
    def get_cached_embedding(self, text):
        \"\"\"
        Get embedding from cache or compute it.
        
        Args:
            text (str): Text to encode
            
        Returns:
            numpy.ndarray: Text embedding
        \"\"\"
        # Create a hash of the text as cache key
        import hashlib
        text_hash = hashlib.md5(text.encode()).hexdigest()
        
        current_time = time.time()
        
        # Check if embedding is in cache and not expired
        if text_hash in self.embedding_cache:
            embedding, timestamp = self.embedding_cache[text_hash]
            if current_time - timestamp < 3600:  # 1 hour TTL
                return embedding
        
        # Compute embedding
        embedding = self.model.encode(text)
        
        # Cache result
        self.embedding_cache[text_hash] = (embedding, current_time)
        
        # Save cache periodically (1% chance to avoid too frequent disk I/O)
        if np.random.random() < 0.01:
            self._save_embedding_cache()
        
        return embedding
    
    def _save_embedding_cache(self):
        \"\"\"
        Save embedding cache to file.
        \"\"\"
        try:
            with open("cache/embedding_cache.pkl", 'wb') as f:
                pickle.dump(self.embedding_cache, f)
        except Exception as e:
            logger.error(f"Error saving embedding cache: {e}")
    
    def _load_embedding_cache(self):
        \"\"\"
        Load embedding cache from file.
        
        Returns:
            dict: Embedding cache
        \"\"\"
        try:
            if os.path.exists("cache/embedding_cache.pkl"):
                with open("cache/embedding_cache.pkl", 'rb') as f:
                    return pickle.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading embedding cache: {e}")
            return {}
"""
            
            # Add cache initialization to __init__
            init_replacement = """
    def __init__(self, 
                 model_name: str = "sentence-transformers/all-mpnet-base-v2",
                 api_key: Optional[str] = None,
                 examples_path: Optional[str] = None,
                 use_openai: bool = False):
        \"\"\"
        Initialize the advanced LLM analyzer.
        
        Args:
            model_name (str): Name of the sentence transformer model to use
            api_key (str): API key for OpenAI (if using OpenAI)
            examples_path (str): Path to phishing examples file
            use_openai (bool): Whether to use OpenAI API
        \"\"\"
        self.model_name = model_name
        self.api_key = api_key
        self.use_openai = use_openai
        
        # Create cache directory
        os.makedirs("cache", exist_ok=True)
        
        # Initialize embedding cache
        self.embedding_cache = self._load_embedding_cache()
        
        # Load phishing examples
"""
            
            # Replace analyze_with_sentence_transformer to use caching
            analyze_replacement = """
    def analyze_with_sentence_transformer(self, email_content: str) -> Dict[str, Any]:
        \"\"\"
        Analyze email content using sentence transformers.
        
        Args:
            email_content (str): Email content to analyze
            
        Returns:
            dict: Analysis results
        \"\"\"
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
            
            # Get email embedding from cache or compute it
            email_embedding = self.get_cached_embedding(email_text)
            
            # Compare with examples
            similarities = []
            for example in self.examples:
                # Get example embedding from cache or compute it
                example_embedding = self.get_cached_embedding(example["content"])
                
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
"""
            
            # Add imports
            imports_addition = """import time
import pickle
import hashlib
"""
            
            # Update the content
            updated_content = content
            
            # Add imports if not already present
            if "import time" not in content:
                import_end = content.find("# Set random seed")
                updated_content = content[:import_end] + imports_addition + "\n" + content[import_end:]
            
            # Replace __init__ method
            init_start = updated_content.find("def __init__")
            init_end = updated_content.find("# Load phishing examples")
            if init_start != -1 and init_end != -1:
                updated_content = updated_content[:init_start] + init_replacement + updated_content[init_end:]
            
            # Add cache functions before analyze_with_sentence_transformer
            analyze_start = updated_content.find("def analyze_with_sentence_transformer")
            if analyze_start != -1:
                updated_content = updated_content[:analyze_start] + cache_functions + "\n" + updated_content[analyze_start:]
            
            # Replace analyze_with_sentence_transformer method
            analyze_start = updated_content.find("def analyze_with_sentence_transformer")
            if analyze_start != -1:
                analyze_end = updated_content.find("def", analyze_start + 1)
                if analyze_end != -1:
                    updated_content = updated_content[:analyze_start] + analyze_replacement + updated_content[analyze_end:]
            
            # Write the updated file
            with open("advanced_llm_analysis.py", 'w') as f:
                f.write(updated_content)
            
            logger.info("LLM analysis optimized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error optimizing LLM analysis: {e}")
            return False
    
    def optimize_parallel_processing(self):
        """
        Optimize parallel processing in the enhanced phishing detector.
        
        Returns:
            bool: Success or failure
        """
        try:
            # Check if enhanced_phishing_detector.py exists
            if not os.path.exists("enhanced_phishing_detector.py"):
                logger.error("enhanced_phishing_detector.py not found")
                return False
            
            # Read the file
            with open("enhanced_phishing_detector.py", 'r') as f:
                content = f.read()
            
            # Check if already optimized
            if "def _optimize_parallel_analysis" in content:
                logger.info("Parallel processing already optimized")
                return True
            
            # Add optimization function
            optimization_function = """
    def _optimize_parallel_analysis(self, 
                              email_content: str, 
                              sender: Optional[str], 
                              recipient: Optional[str]) -> Dict[str, Any]:
        \"\"\"
        Optimized parallel analysis of email components.
        Uses ThreadPoolExecutor with dynamic worker allocation based on system resources.
        
        Args:
            email_content (str): Raw email content
            sender (str): Sender email address
            recipient (str): Recipient email address
            
        Returns:
            dict: Component analysis results
        \"\"\"
        results = {}
        
        # Determine optimal number of workers based on available CPU cores
        # Use at most 75% of available cores to avoid system overload
        max_workers = max(1, int(psutil.cpu_count(logical=False) * 0.75))
        
        # Define analysis tasks
        tasks = []
        
        if self.sender_analyzer:
            tasks.append(("sender", lambda: self.sender_analyzer.analyze_sender(sender, email_content)))
        
        if self.image_analyzer:
            tasks.append(("image", lambda: self.image_analyzer.analyze_images(email_content)))
        
        if self.url_analyzer:
            tasks.append(("url", lambda: self.url_analyzer.analyze_email_urls(email_content)))
        
        if self.behavioral_analyzer and sender and recipient:
            tasks.append(("behavioral", lambda: self.behavioral_analyzer.analyze_behavior(sender, recipient, email_content)))
        
        # Execute tasks in parallel
        with ThreadPoolExecutor(max_workers=min(max_workers, len(tasks))) as executor:
            future_to_task = {executor.submit(task_func): task_name for task_name, task_func in tasks}
            
            for future in as_completed(future_to_task):
                task_name = future_to_task[future]
                try:
                    results[task_name] = future.result()
                except Exception as e:
                    logger.error(f"Error in {task_name} analysis: {e}")
                    results[task_name] = {"error": str(e)}
        
        # Run LLM analysis after other components (may use their results)
        if self.llm_analyzer:
            try:
                results["llm"] = self.llm_analyzer.analyze_email(email_content)
            except Exception as e:
                logger.error(f"Error in LLM analysis: {e}")
                results["llm"] = {"error": str(e)}
        
        # Run vector similarity analysis
        if self.vector_db_manager:
            try:
                similar_emails = find_similar_phishing_emails(email_content, threshold=self.vector_similarity_threshold)
                results["vector_similarity"] = {
                    "similar_emails": similar_emails,
                    "similarity_score": max([email.get("similarity", 0) for email in similar_emails]) if similar_emails else 0
                }
            except Exception as e:
                logger.error(f"Error in vector similarity analysis: {e}")
                results["vector_similarity"] = {"error": str(e)}
        
        return results
"""
            
            # Replace _parallel_analysis with the optimized version
            parallel_start = content.find("def _parallel_analysis")
            if parallel_start != -1:
                parallel_end = content.find("def", parallel_start + 1)
                if parallel_end != -1:
                    # Keep the original function but rename it
                    original_function = content[parallel_start:parallel_end]
                    original_function = original_function.replace("def _parallel_analysis", "def _original_parallel_analysis")
                    
                    # Insert the optimized function and the original as backup
                    content = content[:parallel_start] + optimization_function + "\n" + original_function + content[parallel_end:]
                    
                    # Replace function calls to use the optimized version
                    content = content.replace("self._parallel_analysis(", "self._optimize_parallel_analysis(")
            
            # Add psutil import if not present
            if "import psutil" not in content:
                import_end = content.find("# Set a fixed random seed")
                if import_end != -1:
                    content = content[:import_end] + "import psutil\n" + content[import_end:]
            
            # Write the updated file
            with open("enhanced_phishing_detector.py", 'w') as f:
                f.write(content)
            
            logger.info("Parallel processing optimized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error optimizing parallel processing: {e}")
            return False
    
    def update_requirements(self):
        """
        Update requirements.txt with necessary packages for optimization.
        
        Returns:
            bool: Success or failure
        """
        try:
            required_packages = ["psutil>=5.9.0"]
            
            # Check if Requirements.txt exists
            if os.path.exists("Requirements.txt"):
                with open("Requirements.txt", 'r') as f:
                    content = f.read()
                
                # Check if psutil is already in requirements
                if "psutil" not in content:
                    with open("Requirements.txt", 'a') as f:
                        f.write("\n# Performance optimization packages\n")
                        for package in required_packages:
                            f.write(f"{package}\n")
                    
                    logger.info("Updated Requirements.txt with optimization packages")
            else:
                logger.warning("Requirements.txt not found")
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating requirements: {e}")
            return False
    
    def run_all_optimizations(self):
        """
        Run all performance optimizations.
        
        Returns:
            bool: Success or failure
        """
        success = True
        
        # Create cache directory
        os.makedirs("cache", exist_ok=True)
        
        # Optimize URL analysis
        if not self.optimize_url_analysis():
            success = False
        
        # Optimize LLM analysis
        if not self.optimize_llm_analysis():
            success = False
        
        # Optimize parallel processing
        if not self.optimize_parallel_processing():
            success = False
        
        # Update requirements
        if not self.update_requirements():
            success = False
        
        return success

def main():
    parser = argparse.ArgumentParser(description='Optimize performance of the phishing detector')
    parser.add_argument('--config', type=str, default="phishing_detector_config.json",
                        help='Path to configuration file')
    
    args = parser.parse_args()
    
    # Initialize optimizer
    optimizer = PerformanceOptimizer(config_path=args.config)
    
    # Run all optimizations
    success = optimizer.run_all_optimizations()
    
    if success:
        logger.info("Performance optimization completed successfully")
    else:
        logger.warning("Performance optimization completed with some errors")

if __name__ == "__main__":
    main() 