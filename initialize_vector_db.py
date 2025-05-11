import os
import sys
import json
import logging
from vector_db_integration import PhishingVectorDBManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("initialize_vector_db")

def initialize_vector_database():
    """Initialize the vector database with sample emails"""
    logger.info("Initializing vector database with sample emails...")
    
    # Get vector DB instance
    db_manager = PhishingVectorDBManager.get_instance()
    
    # Check if database already has entries
    stats = db_manager.get_stats()
    if stats.get('total_emails', 0) > 0:
        logger.info(f"Vector database already contains {stats['total_emails']} emails. Skipping initialization.")
        return True
    
    # Sample phishing emails
    phishing_samples = [
        {
            "content": """
Subject: Urgent: Your Account Has Been Suspended

Dear Valued Customer,

We regret to inform you that your account has been suspended due to suspicious activity. 
To restore your account, please click the link below and verify your information:

http://security-verify-account.com/login.php

Failure to verify your account within 24 hours will result in permanent suspension.

Regards,
Security Team
            """,
            "is_phishing": True,
            "metadata": {"type": "account_suspension"}
        },
        {
            "content": """
Subject: Payment Confirmation Required

Dear Sir/Madam,

We have tried to process your recent payment but it was declined. 
Please update your payment information by clicking here:
https://payment-update-secure.net/form.php?id=12345

Your subscription will be canceled if we don't receive your updated information.

Best regards,
Billing Department
            """,
            "is_phishing": True,
            "metadata": {"type": "payment_scam"}
        },
        {
            "content": """
Subject: Your Package Delivery Failed

Hello,

We attempted to deliver your package today but were unable to complete the delivery.
To reschedule your delivery, please download and fill out the attached form.

[attachment: delivery_form.exe]

Thank you,
Delivery Services
            """,
            "is_phishing": True,
            "metadata": {"type": "malware_attachment"}
        },
        {
            "content": """
Subject: Lottery Winner Notification!!!

Congratulations! Your email address has won $5,000,000 in our international lottery.
To claim your prize, please send us your personal details and a processing fee of $100.

Contact our agent immediately: claim_agent@lottery-winner-intl.com

Yours faithfully,
International Lottery Association
            """,
            "is_phishing": True,
            "metadata": {"type": "lottery_scam"}
        },
        {
            "content": """
Subject: Inheritance Notification

I am Barrister James Williams, a solicitor. I am contacting you regarding an unclaimed inheritance of $15.5 million from a deceased client who shares your last name.

To proceed with the transfer, I need your full details and a small fee of $250 for legal documentation.

Please reply to: barrister_james@legal-inheritance.org

Regards,
Barrister James Williams
            """,
            "is_phishing": True,
            "metadata": {"type": "inheritance_scam"}
        }
    ]
    
    # Sample legitimate emails
    legitimate_samples = [
        {
            "content": """
Subject: Your Monthly Statement is Ready

Hello,

Your monthly statement for May 2023 is now available in your online account.
To view your statement, please log in to your account at our official website: https://www.legitimatebank.com

If you have any questions about your statement, please contact our customer service.

Thank you for banking with us.

Best regards,
Customer Service Team
Legitimate Bank
            """,
            "is_phishing": False,
            "metadata": {"type": "bank_statement"}
        },
        {
            "content": """
Subject: Order Confirmation #12345

Dear Customer,

Thank you for your order! We're pleased to confirm that we've received your order #12345.

Order Details:
- Product: Wireless Headphones
- Quantity: 1
- Price: $79.99
- Shipping: Standard (3-5 business days)

You can track your order status by logging into your account on our website.

If you have any questions, please contact our support team.

Thank you for shopping with us!

Best regards,
Customer Support
            """,
            "is_phishing": False,
            "metadata": {"type": "order_confirmation"}
        },
        {
            "content": """
Subject: Meeting Reminder: Project Update

Hi Team,

This is a reminder that we have our weekly project update meeting tomorrow at 10:00 AM in Conference Room A.

Agenda:
1. Progress updates from each team member
2. Discussion of current challenges
3. Planning for next sprint

Please come prepared with your status updates.

Best regards,
Project Manager
            """,
            "is_phishing": False,
            "metadata": {"type": "meeting_reminder"}
        },
        {
            "content": """
Subject: Welcome to Our Newsletter

Hello,

Thank you for subscribing to our monthly newsletter! We're excited to have you join our community.

In each newsletter, you'll receive:
- Industry news and updates
- Tips and best practices
- Exclusive offers for subscribers

If you ever wish to unsubscribe, you can click the unsubscribe link at the bottom of any email.

Best regards,
Newsletter Team
            """,
            "is_phishing": False,
            "metadata": {"type": "newsletter"}
        },
        {
            "content": """
Subject: Your Appointment Confirmation

Dear Patient,

This is to confirm your appointment with Dr. Smith on June 15, 2023, at 2:30 PM.

Please arrive 15 minutes early to complete any necessary paperwork. If you need to reschedule, please call our office at least 24 hours in advance.

Remember to bring your insurance card and a list of current medications.

Thank you,
Medical Center Appointments
            """,
            "is_phishing": False,
            "metadata": {"type": "appointment_confirmation"}
        }
    ]
    
    # Add phishing samples to the database
    for sample in phishing_samples:
        success = db_manager.add_email(
            sample["content"],
            sample["is_phishing"],
            sample["metadata"]
        )
        if not success:
            logger.error(f"Failed to add phishing sample: {sample['metadata']['type']}")
    
    # Add legitimate samples to the database
    for sample in legitimate_samples:
        success = db_manager.add_email(
            sample["content"],
            sample["is_phishing"],
            sample["metadata"]
        )
        if not success:
            logger.error(f"Failed to add legitimate sample: {sample['metadata']['type']}")
    
    # Save the database
    db_manager.save()
    
    # Check final stats
    stats = db_manager.get_stats()
    logger.info(f"Vector database initialized with {stats['total_emails']} emails")
    logger.info(f"Phishing emails: {stats.get('phishing_emails', 0)}")
    logger.info(f"Legitimate emails: {stats.get('legitimate_emails', 0)}")
    
    return True

if __name__ == "__main__":
    initialize_vector_database() 