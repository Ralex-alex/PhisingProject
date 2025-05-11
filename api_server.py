import os
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks, File, UploadFile, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List, Union
import pandas as pd
import joblib
import json
from datetime import datetime
import logging
import traceback
import numpy as np
import base64
import time

# Import our phishing detection pipeline
from combined_pipeline import PhishingDetectionPipeline
from enhanced_phishing_detector import EnhancedPhishingDetector
from vector_db_integration import record_email_feedback, find_similar_phishing_emails

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("api_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("phishing_detection_api")

# Initialize FastAPI app
app = FastAPI(
    title="Phishing Detection API",
    description="API for detecting phishing emails using advanced ML/LLM techniques",
    version="1.0.0"
)

# Add CORS middleware to allow requests from specified origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Input models
class EmailContent(BaseModel):
    subject: Optional[str] = Field(None, description="Email subject")
    body: str = Field(..., description="Email body content")
    sender: Optional[str] = Field(None, description="Email sender address")
    recipient: Optional[str] = Field(None, description="Email recipient address")
    html_content: Optional[bool] = Field(False, description="Whether the body contains HTML")
    
    class Config:
        schema_extra = {
            "example": {
                "subject": "Urgent: Account Verification Required",
                "body": "Dear User, Your account has been suspended. Click here to verify: http://suspicious-link.com",
                "sender": "security@bank-verify.com",
                "recipient": "user@example.com",
                "html_content": False
            }
        }

class BatchEmailRequest(BaseModel):
    emails: List[EmailContent] = Field(..., description="List of emails to analyze")

class FeedbackRequest(BaseModel):
    email_id: Optional[str] = Field(None, description="ID of the email (if available)")
    email_content: str = Field(..., description="Content of the email")
    user_verdict: bool = Field(..., description="User's verdict (true=phishing, false=legitimate)")
    original_verdict: Optional[bool] = Field(None, description="Original system verdict")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

# Response models
class SuspiciousElement(BaseModel):
    type: str
    description: str
    risk_score: float

class SimilarEmail(BaseModel):
    id: int
    similarity: float
    content_preview: str
    is_phishing: bool
    timestamp: float

class PhishingPrediction(BaseModel):
    is_phishing: bool
    confidence: float
    risk_level: str
    suspicious_elements: List[SuspiciousElement]
    recommendations: List[str]
    similar_phishing_emails: Optional[List[SimilarEmail]] = None
    analysis_time: float
    
    class Config:
        schema_extra = {
            "example": {
                "is_phishing": True,
                "confidence": 0.92,
                "risk_level": "high",
                "suspicious_elements": [
                    {"type": "url", "description": "Suspicious URL: http://suspicious-link.com", "risk_score": 0.95},
                    {"type": "sender", "description": "Domain has known bad reputation", "risk_score": 0.7}
                ],
                "recommendations": [
                    "Do not click on any links in this email",
                    "Do not download or open any attachments"
                ],
                "similar_phishing_emails": [
                    {"id": 123, "similarity": 0.95, "content_preview": "Your account has been suspended...", "is_phishing": True, "timestamp": 1625097600}
                ],
                "analysis_time": 0.75
            }
        }

class BatchPredictionResponse(BaseModel):
    results: List[PhishingPrediction]
    metadata: Dict[str, Any]

class FeedbackResponse(BaseModel):
    success: bool
    message: str
    feedback_id: Optional[str] = None

# Global variables
MODEL_DIR = "models"
MODEL = None
ENHANCED_DETECTOR = None

def load_model():
    """Load the trained phishing detection model"""
    global MODEL
    
    try:
        if MODEL is None:
            logger.info("Loading phishing detection model...")
            
            # Check if model directory exists
            if not os.path.exists(MODEL_DIR):
                # Create a new model if not existing
                logger.warning("Model directory not found. Creating a new model...")
                pipeline = PhishingDetectionPipeline()
                
                # Try to use the existing dataset or fallback to smaller dataset
                try:
                    data_path = "expanded_data/combined_dataset.csv"
                    if not os.path.exists(data_path):
                        data_path = "emails_from_spamassassin.csv"
                        
                    # Prepare data and train model
                    data_dict = pipeline.prepare_data(data_path, test_size=0.3)
                    pipeline.train(data_dict)
                    pipeline.save(directory=MODEL_DIR)
                except Exception as e:
                    logger.error(f"Error training new model: {e}")
                    raise HTTPException(status_code=500, detail="Failed to initialize model")
            
            # Load the trained model
            MODEL = PhishingDetectionPipeline()
            MODEL.load(directory=MODEL_DIR)
            logger.info("Model loaded successfully")
            
        return MODEL
    
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Model initialization failed")

def load_enhanced_detector():
    """Load the enhanced phishing detector"""
    global ENHANCED_DETECTOR
    
    try:
        if ENHANCED_DETECTOR is None:
            logger.info("Loading enhanced phishing detector...")
            
            # Initialize the enhanced detector
            ENHANCED_DETECTOR = EnhancedPhishingDetector(
                config_path="phishing_detector_config.json",
                history_db_path="email_history.csv",
                examples_path="phishing_examples.json",
                logo_db_path="logo_database"
            )
            
            logger.info("Enhanced detector loaded successfully")
        
        return ENHANCED_DETECTOR
    
    except Exception as e:
        logger.error(f"Error loading enhanced detector: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail="Enhanced detector initialization failed")

def get_model():
    """Dependency to get the model"""
    return load_model()

def get_enhanced_detector():
    """Dependency to get the enhanced detector"""
    return load_enhanced_detector()

def log_prediction_request(email_data: Union[EmailContent, BatchEmailRequest], prediction_result: Any):
    """Log prediction requests for monitoring and improvement"""
    try:
        timestamp = datetime.now().isoformat()
        
        # Prepare log entry (omit full email content for privacy)
        log_entry = {
            "timestamp": timestamp,
            "email_count": 1 if isinstance(email_data, EmailContent) else len(email_data.emails),
            "prediction_result": prediction_result
        }
        
        # In a production environment, you might send this to a database or monitoring system
        logger.info(f"Prediction logged: {json.dumps(log_entry)}")
    
    except Exception as e:
        logger.error(f"Error logging prediction: {str(e)}")

def extract_suspicious_elements(text: str, prediction: float) -> List[Dict[str, Any]]:
    """Extract suspicious elements from the email text"""
    suspicious_elements = []
    
    # Extract URLs
    import re
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
    for url in urls:
        # Simple URL risk assessment (you would use more sophisticated methods in production)
        risk_score = 0.7
        if any(keyword in url for keyword in ['secure', 'login', 'account', 'verify']):
            risk_score = 0.85
        if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            risk_score = 0.95
            
        suspicious_elements.append({
            "type": "url",
            "description": f"Suspicious URL: {url}",
            "risk_score": risk_score
        })
    
    # Check for suspicious keywords
    suspicious_keywords = ['urgent', 'verify', 'account', 'login', 'password', 
                           'click', 'confirm', 'update', 'suspend']
    
    for keyword in suspicious_keywords:
        if keyword in text.lower():
            suspicious_elements.append({
                "type": "keyword",
                "description": f"Suspicious keyword: {keyword}",
                "risk_score": 0.6 + (prediction * 0.2)  # Scale with the model's prediction
            })
    
    return suspicious_elements

def format_email_content(subject: Optional[str], body: str, html_content: bool = False) -> str:
    """Format email content for analysis"""
    if html_content:
        # If it's HTML content, add proper headers
        email_content = f"Subject: {subject or ''}\nContent-Type: text/html; charset=UTF-8\n\n{body}"
    else:
        # Plain text email
        email_content = f"Subject: {subject or ''}\n\n{body}"
    
    return email_content

# Routes
@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "Phishing Detection API",
        "documentation": "/docs",
        "version": "1.0.0"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        model = load_model()
        detector = load_enhanced_detector()
        return {
            "status": "healthy", 
            "model_loaded": model is not None,
            "enhanced_detector_loaded": detector is not None
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"status": "unhealthy", "error": str(e)}
        )

@app.post("/predict", response_model=PhishingPrediction)
async def predict_phishing(
    email: EmailContent,
    background_tasks: BackgroundTasks,
    model: PhishingDetectionPipeline = Depends(get_model),
    enhanced_detector: EnhancedPhishingDetector = Depends(get_enhanced_detector)
):
    """
    Analyze a single email for phishing indicators using the enhanced detector
    """
    try:
        # Format the email content
        email_content = format_email_content(email.subject, email.body, email.html_content)
        
        # Use the enhanced detector for analysis
        result = enhanced_detector.analyze_email(
            email_content=email_content,
            sender=email.sender,
            recipient=email.recipient
        )
        
        # Format the response
        response = {
            "is_phishing": result["is_phishing"],
            "confidence": result["confidence"],
            "risk_level": result["risk_level"],
            "suspicious_elements": result["suspicious_elements"],
            "recommendations": result["recommendations"],
            "analysis_time": result["analysis_time"]
        }
        
        # Add similar phishing emails if available
        if "similar_phishing_emails" in result and result["similar_phishing_emails"]:
            response["similar_phishing_emails"] = result["similar_phishing_emails"]
        
        # Log the prediction in the background
        background_tasks.add_task(log_prediction_request, email, response)
        
        return response
    
    except Exception as e:
        logger.error(f"Error predicting phishing: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/batch-predict", response_model=BatchPredictionResponse)
async def batch_predict(
    request: BatchEmailRequest,
    background_tasks: BackgroundTasks,
    enhanced_detector: EnhancedPhishingDetector = Depends(get_enhanced_detector)
):
    """
    Analyze multiple emails for phishing indicators
    """
    try:
        # Prepare emails for batch analysis
        emails = []
        for email_data in request.emails:
            email_content = format_email_content(
                email_data.subject, 
                email_data.body, 
                email_data.html_content
            )
            
            emails.append({
                'content': email_content,
                'sender': email_data.sender,
                'recipient': email_data.recipient
            })
        
        # Analyze emails in batch
        batch_results = enhanced_detector.analyze_batch(emails)
        
        # Format the response
        results = []
        for result in batch_results:
            prediction = {
                "is_phishing": result["is_phishing"],
                "confidence": result["confidence"],
                "risk_level": result["risk_level"],
                "suspicious_elements": result["suspicious_elements"],
                "recommendations": result["recommendations"],
                "analysis_time": result["analysis_time"]
            }
            
            # Add similar phishing emails if available
            if "similar_phishing_emails" in result and result["similar_phishing_emails"]:
                prediction["similar_phishing_emails"] = result["similar_phishing_emails"]
            
            results.append(prediction)
        
        # Log the batch prediction in the background
        background_tasks.add_task(log_prediction_request, request, {
            "count": len(results),
            "phishing_count": sum(1 for r in results if r["is_phishing"])
        })
        
        return {
            "results": results,
            "metadata": {
                "count": len(results),
                "phishing_count": sum(1 for r in results if r["is_phishing"]),
                "timestamp": datetime.now().isoformat()
            }
        }
    
    except Exception as e:
        logger.error(f"Error in batch prediction: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/feedback", response_model=FeedbackResponse)
async def submit_feedback(request: FeedbackRequest):
    """
    Submit user feedback on a phishing prediction
    """
    try:
        # Record the feedback in the vector database
        metadata = request.metadata or {}
        metadata.update({
            "original_verdict": request.original_verdict,
            "feedback_source": "api"
        })
        
        success = record_email_feedback(
            email_content=request.email_content,
            is_phishing=request.user_verdict,
            metadata=metadata
        )
        
        if success:
            return {
                "success": True,
                "message": "Feedback recorded successfully",
                "feedback_id": str(int(time.time()))  # Simple ID generation
            }
        else:
            return {
                "success": False,
                "message": "Failed to record feedback"
            }
    
    except Exception as e:
        logger.error(f"Error submitting feedback: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }

@app.post("/analyze-image")
async def analyze_image(
    file: UploadFile = File(...),
    enhanced_detector: EnhancedPhishingDetector = Depends(get_enhanced_detector)
):
    """
    Analyze an image for phishing indicators
    """
    try:
        # Read the image file
        image_data = await file.read()
        
        # Convert to base64 for embedding in HTML
        base64_image = base64.b64encode(image_data).decode('utf-8')
        image_type = file.content_type.split('/')[-1]
        
        # Create a simple HTML with the embedded image
        html_content = f"<html><body><img src='data:image/{image_type};base64,{base64_image}'></body></html>"
        
        # Use the image analyzer from the enhanced detector
        image_analysis = enhanced_detector.image_analyzer.analyze_email_images(html_content)
        
        return {
            "analysis_result": image_analysis,
            "overall_risk_score": image_analysis["overall_risk_score"],
            "risk_factors": image_analysis["risk_factors"]
        }
    
    except Exception as e:
        logger.error(f"Error analyzing image: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze-sender")
async def analyze_sender(
    sender: str,
    email_content: Optional[str] = None,
    enhanced_detector: EnhancedPhishingDetector = Depends(get_enhanced_detector)
):
    """
    Analyze an email sender for phishing indicators
    """
    try:
        # Use the sender analyzer from the enhanced detector
        sender_analysis = enhanced_detector.sender_analyzer.analyze_sender(
            email_address=sender,
            email_content=email_content
        )
        
        return {
            "analysis_result": sender_analysis,
            "risk_score": sender_analysis["risk_score"],
            "risk_factors": sender_analysis.get("risk_factors", [])
        }
    
    except Exception as e:
        logger.error(f"Error analyzing sender: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/find-similar")
async def find_similar_emails(
    email_content: str,
    k: int = 5,
    threshold: float = 0.7
):
    """
    Find emails similar to the provided content
    """
    try:
        # Find similar phishing emails
        similar_emails = find_similar_phishing_emails(
            email_content=email_content,
            k=k,
            threshold=threshold
        )
        
        return {
            "similar_emails": similar_emails,
            "count": len(similar_emails)
        }
    
    except Exception as e:
        logger.error(f"Error finding similar emails: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    # Run the FastAPI app with uvicorn
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True) 