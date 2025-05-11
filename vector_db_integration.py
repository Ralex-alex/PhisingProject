import os
import numpy as np
import pandas as pd
import json
import logging
import faiss
import pickle
import time
from typing import Dict, List, Any, Tuple, Optional, Union
from sentence_transformers import SentenceTransformer
import threading

# Set random seed for reproducibility
np.random.seed(42)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vector_db_integration")

class PhishingVectorDB:
    """
    Class for managing a vector database of phishing emails using FAISS.
    Enables similarity search to find emails similar to known phishing attempts.
    """
    
    def __init__(self, 
                 model_name: str = "sentence-transformers/all-mpnet-base-v2",
                 db_path: str = "models/phishing_vector_db",
                 metadata_path: str = "models/phishing_vector_metadata.json",
                 dimension: int = 768,
                 create_if_missing: bool = True):
        """
        Initialize the vector database.
        
        Args:
            model_name (str): Name of the sentence transformer model to use
            db_path (str): Path to save/load the FAISS index
            metadata_path (str): Path to save/load email metadata
            dimension (int): Dimension of the embedding vectors
            create_if_missing (bool): Whether to create a new DB if not found
        """
        self.model_name = model_name
        self.db_path = db_path
        self.metadata_path = metadata_path
        self.dimension = dimension
        
        # Initialize sentence transformer model
        try:
            self.model = SentenceTransformer(model_name)
            logger.info(f"Loaded sentence transformer model: {model_name}")
        except Exception as e:
            logger.error(f"Error loading sentence transformer model: {e}")
            self.model = None
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize or load the index
        self.index = None
        self.metadata = []
        
        if os.path.exists(db_path) and os.path.exists(metadata_path):
            self.load()
        elif create_if_missing:
            self.create_new_index()
    
    def create_new_index(self) -> None:
        """
        Create a new FAISS index.
        """
        try:
            # Create a new FAISS index
            # Using IndexFlatIP for inner product similarity (cosine)
            self.index = faiss.IndexFlatIP(self.dimension)
            
            # Initialize empty metadata list
            self.metadata = []
            
            logger.info(f"Created new FAISS index with dimension {self.dimension}")
            
            # Save the empty index and metadata
            self.save()
        except Exception as e:
            logger.error(f"Error creating new index: {e}")
    
    def load(self) -> bool:
        """
        Load the FAISS index and metadata from disk.
        
        Returns:
            bool: Success or failure
        """
        try:
            # Load FAISS index
            self.index = faiss.read_index(self.db_path)
            logger.info(f"Loaded FAISS index with {self.index.ntotal} vectors")
            
            # Load metadata
            with open(self.metadata_path, 'r') as f:
                self.metadata = json.load(f)
            
            logger.info(f"Loaded metadata for {len(self.metadata)} emails")
            return True
        except Exception as e:
            logger.error(f"Error loading vector database: {e}")
            # Create a new index if loading failed
            self.create_new_index()
            return False
    
    def save(self) -> bool:
        """
        Save the FAISS index and metadata to disk.
        
        Returns:
            bool: Success or failure
        """
        try:
            # Save FAISS index
            faiss.write_index(self.index, self.db_path)
            
            # Save metadata
            with open(self.metadata_path, 'w') as f:
                json.dump(self.metadata, f)
            
            logger.info(f"Saved vector database with {self.index.ntotal} vectors")
            return True
        except Exception as e:
            logger.error(f"Error saving vector database: {e}")
            return False
    
    def add_email(self, 
                 email_content: str, 
                 is_phishing: bool, 
                 metadata: Dict[str, Any] = None) -> bool:
        """
        Add an email to the vector database.
        
        Args:
            email_content (str): Email content to add
            is_phishing (bool): Whether the email is phishing
            metadata (dict): Additional metadata about the email
            
        Returns:
            bool: Success or failure
        """
        if self.model is None or self.index is None:
            logger.error("Model or index not initialized")
            return False
        
        try:
            # Generate embedding
            embedding = self.model.encode([email_content])[0]
            
            # Convert to float32 and normalize
            embedding = embedding.astype(np.float32)
            faiss.normalize_L2(np.reshape(embedding, (1, -1)))
            
            # Add to index
            self.index.add(np.reshape(embedding, (1, -1)))
            
            # Prepare metadata
            email_metadata = {
                "id": len(self.metadata),
                "timestamp": time.time(),
                "is_phishing": is_phishing,
                "content_preview": email_content[:100] + "..." if len(email_content) > 100 else email_content
            }
            
            # Add additional metadata if provided
            if metadata:
                email_metadata.update(metadata)
            
            # Add to metadata list
            self.metadata.append(email_metadata)
            
            logger.info(f"Added email to vector database (ID: {email_metadata['id']})")
            return True
        except Exception as e:
            logger.error(f"Error adding email to vector database: {e}")
            return False
    
    def add_batch(self, 
                 emails: List[Dict[str, Any]]) -> Tuple[int, int]:
        """
        Add a batch of emails to the vector database.
        
        Args:
            emails (list): List of dictionaries containing email data
                Each dict should have 'content', 'is_phishing', and optional 'metadata'
            
        Returns:
            tuple: (Number of successful additions, total attempted)
        """
        if self.model is None or self.index is None:
            logger.error("Model or index not initialized")
            return (0, len(emails))
        
        successful = 0
        
        try:
            # Extract content for batch encoding
            contents = [email['content'] for email in emails]
            
            # Generate embeddings in batch
            embeddings = self.model.encode(contents)
            
            # Convert to float32 and normalize
            embeddings = embeddings.astype(np.float32)
            faiss.normalize_L2(embeddings)
            
            # Add to index
            self.index.add(embeddings)
            
            # Add metadata
            start_id = len(self.metadata)
            for i, email in enumerate(emails):
                email_metadata = {
                    "id": start_id + i,
                    "timestamp": time.time(),
                    "is_phishing": email['is_phishing'],
                    "content_preview": email['content'][:100] + "..." if len(email['content']) > 100 else email['content']
                }
                
                # Add additional metadata if provided
                if 'metadata' in email and email['metadata']:
                    email_metadata.update(email['metadata'])
                
                self.metadata.append(email_metadata)
                successful += 1
            
            logger.info(f"Added {successful} emails to vector database in batch")
            return (successful, len(emails))
        except Exception as e:
            logger.error(f"Error adding batch to vector database: {e}")
            return (successful, len(emails))
    
    def search_similar(self, 
                      query: str, 
                      k: int = 5, 
                      threshold: float = 0.7) -> List[Dict[str, Any]]:
        """
        Search for emails similar to the query.
        
        Args:
            query (str): Query text
            k (int): Number of results to return
            threshold (float): Similarity threshold (0-1)
            
        Returns:
            list: List of similar emails with metadata and similarity scores
        """
        if self.model is None or self.index is None:
            logger.error("Model or index not initialized")
            return []
        
        if self.index.ntotal == 0:
            logger.warning("Vector database is empty")
            return []
        
        try:
            # Generate query embedding
            query_embedding = self.model.encode([query])[0]
            
            # Convert to float32 and normalize
            query_embedding = query_embedding.astype(np.float32)
            faiss.normalize_L2(np.reshape(query_embedding, (1, -1)))
            
            # Search the index
            D, I = self.index.search(np.reshape(query_embedding, (1, -1)), k)
            
            # Process results
            results = []
            for i in range(len(I[0])):
                idx = I[0][i]
                similarity = float(D[0][i])
                
                # Skip results below threshold
                if similarity < threshold:
                    continue
                
                # Get metadata
                if idx < len(self.metadata):
                    metadata = self.metadata[idx].copy()
                    metadata['similarity'] = similarity
                    results.append(metadata)
            
            logger.info(f"Found {len(results)} similar emails for query")
            return results
        except Exception as e:
            logger.error(f"Error searching vector database: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the vector database.
        
        Returns:
            dict: Database statistics
        """
        stats = {
            "total_emails": 0,
            "phishing_emails": 0,
            "legitimate_emails": 0,
            "model_name": self.model_name,
            "dimension": self.dimension,
            "last_updated": None
        }
        
        if self.index is not None:
            stats["total_emails"] = self.index.ntotal
        
        if self.metadata:
            stats["phishing_emails"] = sum(1 for m in self.metadata if m.get('is_phishing', False))
            stats["legitimate_emails"] = stats["total_emails"] - stats["phishing_emails"]
            
            # Find the most recent timestamp
            timestamps = [m.get('timestamp', 0) for m in self.metadata]
            if timestamps:
                stats["last_updated"] = max(timestamps)
        
        return stats
    
    def remove_email(self, email_id: int) -> bool:
        """
        Remove an email from the database by ID.
        Note: This is an expensive operation in FAISS as it requires rebuilding the index.
        
        Args:
            email_id (int): ID of the email to remove
            
        Returns:
            bool: Success or failure
        """
        if self.index is None or not self.metadata:
            logger.error("Index or metadata not initialized")
            return False
        
        try:
            # Find the email in metadata
            email_idx = None
            for i, meta in enumerate(self.metadata):
                if meta.get('id') == email_id:
                    email_idx = i
                    break
            
            if email_idx is None:
                logger.warning(f"Email with ID {email_id} not found")
                return False
            
            # Create a new index
            new_index = faiss.IndexFlatIP(self.dimension)
            
            # Get all vectors from the current index
            all_vectors = faiss.rev_swig_ptr(self.index.get_xb(), self.index.ntotal * self.dimension)
            all_vectors = all_vectors.reshape(self.index.ntotal, self.dimension)
            
            # Remove the vector at the specified index
            mask = np.ones(self.index.ntotal, dtype=bool)
            mask[email_idx] = False
            filtered_vectors = all_vectors[mask]
            
            # Add the filtered vectors to the new index
            if len(filtered_vectors) > 0:
                new_index.add(filtered_vectors)
            
            # Update metadata
            new_metadata = [m for i, m in enumerate(self.metadata) if i != email_idx]
            
            # Update IDs to maintain consistency
            for i, meta in enumerate(new_metadata):
                meta['id'] = i
            
            # Replace the old index and metadata
            self.index = new_index
            self.metadata = new_metadata
            
            logger.info(f"Removed email with ID {email_id} from vector database")
            return True
        except Exception as e:
            logger.error(f"Error removing email from vector database: {e}")
            return False
    
    def clear(self) -> bool:
        """
        Clear the vector database.
        
        Returns:
            bool: Success or failure
        """
        try:
            # Create a new empty index
            self.create_new_index()
            logger.info("Cleared vector database")
            return True
        except Exception as e:
            logger.error(f"Error clearing vector database: {e}")
            return False
    
    def import_from_csv(self, 
                       csv_path: str, 
                       content_column: str, 
                       label_column: str,
                       batch_size: int = 100) -> Tuple[int, int]:
        """
        Import emails from a CSV file.
        
        Args:
            csv_path (str): Path to CSV file
            content_column (str): Name of column containing email content
            label_column (str): Name of column containing phishing labels
            batch_size (int): Batch size for processing
            
        Returns:
            tuple: (Number of successful imports, total attempted)
        """
        if not os.path.exists(csv_path):
            logger.error(f"CSV file not found: {csv_path}")
            return (0, 0)
        
        try:
            # Load CSV
            df = pd.read_csv(csv_path)
            logger.info(f"Loaded {len(df)} rows from {csv_path}")
            
            if content_column not in df.columns:
                logger.error(f"Content column '{content_column}' not found in CSV")
                return (0, 0)
            
            if label_column not in df.columns:
                logger.error(f"Label column '{label_column}' not found in CSV")
                return (0, 0)
            
            # Process in batches
            successful = 0
            total = len(df)
            
            for i in range(0, total, batch_size):
                batch_df = df.iloc[i:min(i+batch_size, total)]
                
                # Prepare batch
                batch = []
                for _, row in batch_df.iterrows():
                    content = str(row[content_column])
                    is_phishing = bool(row[label_column])
                    
                    # Create metadata from other columns
                    metadata = {col: row[col] for col in df.columns 
                               if col != content_column and col != label_column}
                    
                    batch.append({
                        'content': content,
                        'is_phishing': is_phishing,
                        'metadata': metadata
                    })
                
                # Add batch to database
                batch_successful, _ = self.add_batch(batch)
                successful += batch_successful
                
                logger.info(f"Processed batch {i//batch_size + 1}/{(total-1)//batch_size + 1}: "
                           f"{batch_successful}/{len(batch)} successful")
            
            # Save after import
            self.save()
            
            logger.info(f"Imported {successful}/{total} emails from CSV")
            return (successful, total)
        except Exception as e:
            logger.error(f"Error importing from CSV: {e}")
            return (0, 0)

class PhishingVectorDBManager:
    """
    Manager class for the PhishingVectorDB with thread safety and caching.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls, 
                    model_name: str = "sentence-transformers/all-mpnet-base-v2",
                    db_path: str = "models/phishing_vector_db",
                    metadata_path: str = "models/phishing_vector_metadata.json") -> 'PhishingVectorDBManager':
        """
        Get the singleton instance of the manager.
        
        Args:
            model_name (str): Model name for the vector database
            db_path (str): Path to the vector database
            metadata_path (str): Path to the metadata file
            
        Returns:
            PhishingVectorDBManager: Singleton instance
        """
        with cls._lock:
            if cls._instance is None:
                cls._instance = PhishingVectorDBManager(model_name, db_path, metadata_path)
            return cls._instance
    
    def __init__(self, 
                model_name: str = "sentence-transformers/all-mpnet-base-v2",
                db_path: str = "models/phishing_vector_db",
                metadata_path: str = "models/phishing_vector_metadata.json"):
        """
        Initialize the manager.
        
        Args:
            model_name (str): Model name for the vector database
            db_path (str): Path to the vector database
            metadata_path (str): Path to the metadata file
        """
        self.db = PhishingVectorDB(model_name, db_path, metadata_path)
        self.lock = threading.Lock()
        self.cache = {}
        self.cache_ttl = 300  # Cache TTL in seconds
        self.cache_timestamps = {}
    
    def add_email(self, 
                 email_content: str, 
                 is_phishing: bool, 
                 metadata: Dict[str, Any] = None) -> bool:
        """
        Thread-safe method to add an email to the database.
        
        Args:
            email_content (str): Email content
            is_phishing (bool): Whether the email is phishing
            metadata (dict): Additional metadata
            
        Returns:
            bool: Success or failure
        """
        with self.lock:
            result = self.db.add_email(email_content, is_phishing, metadata)
            if result:
                self.db.save()
                self._clear_cache()
            return result
    
    def search_similar(self, 
                      query: str, 
                      k: int = 5, 
                      threshold: float = 0.7,
                      use_cache: bool = True) -> List[Dict[str, Any]]:
        """
        Thread-safe method to search for similar emails with caching.
        
        Args:
            query (str): Query text
            k (int): Number of results
            threshold (float): Similarity threshold
            use_cache (bool): Whether to use cache
            
        Returns:
            list: Similar emails
        """
        # Check cache first if enabled
        cache_key = f"search_{query}_{k}_{threshold}"
        if use_cache and cache_key in self.cache:
            # Check if cache is still valid
            if time.time() - self.cache_timestamps.get(cache_key, 0) < self.cache_ttl:
                return self.cache[cache_key]
        
        # Perform search with lock
        with self.lock:
            results = self.db.search_similar(query, k, threshold)
        
        # Update cache
        if use_cache:
            self.cache[cache_key] = results
            self.cache_timestamps[cache_key] = time.time()
        
        return results
    
    def get_stats(self, use_cache: bool = True) -> Dict[str, Any]:
        """
        Thread-safe method to get database statistics with caching.
        
        Args:
            use_cache (bool): Whether to use cache
            
        Returns:
            dict: Database statistics
        """
        cache_key = "stats"
        if use_cache and cache_key in self.cache:
            # Check if cache is still valid
            if time.time() - self.cache_timestamps.get(cache_key, 0) < self.cache_ttl:
                return self.cache[cache_key]
        
        with self.lock:
            stats = self.db.get_stats()
        
        # Update cache
        if use_cache:
            self.cache[cache_key] = stats
            self.cache_timestamps[cache_key] = time.time()
        
        return stats
    
    def save(self) -> bool:
        """
        Thread-safe method to save the database.
        
        Returns:
            bool: Success or failure
        """
        with self.lock:
            return self.db.save()
    
    def _clear_cache(self) -> None:
        """Clear the cache."""
        self.cache = {}
        self.cache_timestamps = {}

def find_similar_phishing_emails(email_content: str, 
                               k: int = 5, 
                               threshold: float = 0.7) -> List[Dict[str, Any]]:
    """
    Find emails similar to the given content in the vector database.
    
    Args:
        email_content (str): Email content to compare
        k (int): Number of similar emails to return
        threshold (float): Similarity threshold (0-1)
        
    Returns:
        list: Similar emails with metadata and similarity scores
    """
    try:
        # Get vector DB instance
        db_manager = PhishingVectorDBManager.get_instance()
        
        # Search for similar emails
        results = db_manager.search_similar(email_content, k=k, threshold=threshold)
        
        # If the database is empty or no similar emails found, return an empty list
        if not results:
            logger.warning("Vector database is empty")
            return []
            
        return results
    except Exception as e:
        logger.error(f"Error finding similar emails: {e}")
        return []

def record_email_feedback(email_content: str, 
                         is_phishing: bool, 
                         metadata: Dict[str, Any] = None) -> bool:
    """
    Record user feedback on an email for improving the system.
    
    Args:
        email_content (str): Email content
        is_phishing (bool): User's determination if it's phishing
        metadata (dict): Additional metadata
        
    Returns:
        bool: Success or failure
    """
    db_manager = PhishingVectorDBManager.get_instance()
    
    # Add default metadata if not provided
    if metadata is None:
        metadata = {}
    
    # Add source information
    metadata['source'] = 'user_feedback'
    metadata['feedback_timestamp'] = time.time()
    
    return db_manager.add_email(email_content, is_phishing, metadata)

if __name__ == "__main__":
    # Example usage
    db = PhishingVectorDB()
    
    # Add some example emails
    db.add_email("Dear user, your account has been suspended. Click here to verify: http://suspicious-link.com", 
                True, {"source": "example"})
    
    db.add_email("Hello, this is a legitimate email about your recent purchase. Thank you for shopping with us!",
                False, {"source": "example"})
    
    # Search for similar emails
    results = db.search_similar("Your account needs verification, click here: http://verify-now.com")
    
    print(f"Found {len(results)} similar emails")
    for result in results:
        print(f"Similarity: {result['similarity']:.2f}, Phishing: {result['is_phishing']}")
        print(f"Preview: {result['content_preview']}")
        print("---")
    
    # Save the database
    db.save() 