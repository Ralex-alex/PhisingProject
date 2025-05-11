import os
import sys
import logging
from vector_db_integration import PhishingVectorDBManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("enhanced_training_data")

def add_enhanced_training_data():
    """Add more detailed training examples to the vector database"""
    logger.info("Adding enhanced training data to vector database...")
    
    # Get vector DB instance
    db_manager = PhishingVectorDBManager.get_instance()
    
    # Additional phishing examples with common patterns
    phishing_examples = [
        # Banking phishing examples
        {
            "content": """
Subject: URGENT: Your Online Banking Access Suspended

Dear Customer,

We have detected unusual activity on your online banking account. To prevent unauthorized access, your account has been temporarily suspended.

To restore your account access, please verify your information by clicking the following link:
http://secure-banking-verification.com/restore.php

This link will expire in 24 hours. Failure to verify your account will result in permanent suspension.

Regards,
Security Department
            """,
            "is_phishing": True,
            "metadata": {"type": "banking_phishing", "confidence": 0.95}
        },
        {
            "content": """
Subject: Security Alert: Unusual Sign-in Activity

Dear Customer,

We detected an unusual sign-in attempt to your online banking account from an unrecognized device.

If this was not you, please secure your account immediately by clicking the link below:
http://security-alert-banking.com/secure-account.php

Your account may be restricted if you don't verify your identity within 12 hours.

Sincerely,
Bank Security Team
            """,
            "is_phishing": True,
            "metadata": {"type": "banking_phishing", "confidence": 0.95}
        },
        # Payment/subscription phishing
        {
            "content": """
Subject: ACTION REQUIRED: Update Your Payment Information

Dear Valued Customer,

We were unable to process your recent payment for your subscription. To avoid service interruption, please update your payment information immediately.

Update your payment details here:
https://payment-update-portal.net/form.php?id=67890

Your service will be terminated if payment is not received within 48 hours.

Customer Support Team
            """,
            "is_phishing": True,
            "metadata": {"type": "payment_phishing", "confidence": 0.9}
        },
        {
            "content": """
Subject: Your Netflix Subscription Payment Failed

Hello Netflix Member,

We're having trouble with your current billing information. We'll try again, but in the meantime you may want to update your payment details.

Please update your payment method here:
https://netflix-billing-update.com/account

If we cannot validate your billing information, your membership will be canceled.

The Netflix Team
            """,
            "is_phishing": True,
            "metadata": {"type": "subscription_phishing", "confidence": 0.9}
        },
        # Account verification phishing
        {
            "content": """
Subject: Verify Your Account Now to Avoid Suspension

Dear User,

Our system has detected that your account information needs to be verified.

Please click on the link below to verify your account details:
http://account-verification-center.com/verify.php

Failure to verify your account within 24 hours will result in account suspension.

Account Services Team
            """,
            "is_phishing": True,
            "metadata": {"type": "verification_phishing", "confidence": 0.9}
        },
        # Prize/lottery phishing
        {
            "content": """
Subject: CONGRATULATIONS! You've Won a New iPhone 14 Pro!

Hello Lucky Winner,

Your email address has been randomly selected as the winner of a brand new iPhone 14 Pro in our monthly giveaway!

To claim your prize, click here:
http://prize-claim-center.org/iphone14/claim.php

You must claim your prize within 3 days or another winner will be selected.

Prize Distribution Team
            """,
            "is_phishing": True,
            "metadata": {"type": "prize_phishing", "confidence": 0.95}
        },
        # Urgent action phishing
        {
            "content": """
Subject: IMMEDIATE ACTION REQUIRED: Account Compromised

Dear Customer,

Your account has been compromised. We have detected multiple unauthorized login attempts.

For your security, we have temporarily limited access to your account.

To restore full access, please verify your identity here:
http://account-security-restore.com/verify

This requires immediate attention.

Security Protection Team
            """,
            "is_phishing": True,
            "metadata": {"type": "urgent_action_phishing", "confidence": 0.95}
        },
        # Document sharing phishing
        {
            "content": """
Subject: Important Document Shared With You

Hello,

An important document has been shared with you via OneDrive.

Click here to view the document:
http://onedrive-document-view.com/doc.php?id=12345

The document will expire in 24 hours.

OneDrive Sharing Service
            """,
            "is_phishing": True,
            "metadata": {"type": "document_phishing", "confidence": 0.85}
        },
        # IT support phishing
        {
            "content": """
Subject: IT Department: Urgent Security Update Required

Dear Employee,

Our IT department has detected that your system is missing critical security updates.

To install the required security patch, please download and run the file from:
http://security-updates-portal.com/patch.exe

This update is mandatory for all employees.

IT Support Team
            """,
            "is_phishing": True,
            "metadata": {"type": "it_support_phishing", "confidence": 0.9}
        },
        # Tax refund phishing
        {
            "content": """
Subject: Tax Refund Notification: Action Required

Dear Taxpayer,

After the last annual calculation, we have determined that you are eligible for a tax refund of $734.80.

To complete the refund process, please submit the form at:
http://tax-refund-claims.com/form.php

Refunds not claimed within 14 days will be voided.

Tax & Revenue Service
            """,
            "is_phishing": True,
            "metadata": {"type": "tax_phishing", "confidence": 0.9}
        }
    ]
    
    # Additional legitimate emails
    legitimate_examples = [
        # Newsletter
        {
            "content": """
Subject: Your Weekly Tech Newsletter

Hi there,

Here's your weekly roundup of the latest tech news:

1. Microsoft announces new Surface devices
2. Apple releases iOS 16.5 update
3. Google introduces AI features for Workspace

Read the full articles on our website: https://legittech.news/weekly

To manage your subscription preferences, visit your account settings.

Best regards,
Tech Newsletter Team
            """,
            "is_phishing": False,
            "metadata": {"type": "newsletter", "confidence": 0.95}
        },
        # Order confirmation
        {
            "content": """
Subject: Your Amazon Order #123-4567890-1234567

Hello,

Thank you for your order. We'll send a confirmation when your item ships.

Your Order Details:
- Wireless Headphones
- $89.99
- Arriving: June 10-12

To view the status of your order, please visit Your Orders on Amazon.com.

Amazon Customer Service
            """,
            "is_phishing": False,
            "metadata": {"type": "order_confirmation", "confidence": 0.95}
        },
        # Appointment reminder
        {
            "content": """
Subject: Reminder: Your Dental Appointment Tomorrow

Dear Patient,

This is a friendly reminder that you have a dental appointment scheduled for tomorrow, June 8, 2023, at 2:30 PM with Dr. Johnson.

Please arrive 10 minutes early to complete any necessary paperwork. If you need to reschedule, please call our office at (555) 123-4567.

Remember to bring your insurance card.

Thank you,
City Dental Clinic
            """,
            "is_phishing": False,
            "metadata": {"type": "appointment_reminder", "confidence": 0.95}
        },
        # Password reset (legitimate)
        {
            "content": """
Subject: Password Reset Request

Hello,

We received a request to reset your password for your account. If you made this request, please click the link below to reset your password:

https://accounts.google.com/reset?token=abc123

If you didn't make this request, you can ignore this email and your password will remain unchanged.

Security Team
Google Accounts
            """,
            "is_phishing": False,
            "metadata": {"type": "password_reset", "confidence": 0.9}
        },
        # Shipping notification
        {
            "content": """
Subject: Your Order Has Shipped!

Hi there,

Great news! Your recent order #45678 has shipped and is on its way to you.

Tracking Number: 1Z999AA10123456784
Carrier: UPS
Estimated Delivery: June 9, 2023

You can track your package here: https://www.ups.com/track?tracknum=1Z999AA10123456784

Thank you for your order!

Shipping Department
            """,
            "is_phishing": False,
            "metadata": {"type": "shipping_notification", "confidence": 0.95}
        },
        # Event invitation
        {
            "content": """
Subject: Invitation: Annual Tech Conference 2023

Dear Tech Enthusiast,

You're invited to our Annual Tech Conference 2023!

Date: July 15-17, 2023
Location: San Francisco Convention Center
Theme: "AI and the Future of Technology"

Register now at our official website: https://techconference2023.com/register

Early bird registration ends June 15.

We hope to see you there!

Conference Organizing Committee
            """,
            "is_phishing": False,
            "metadata": {"type": "event_invitation", "confidence": 0.9}
        },
        # Account notification
        {
            "content": """
Subject: Your Monthly Account Statement

Dear Customer,

Your monthly account statement for May 2023 is now available in your online banking portal.

Account: *****1234
Statement Period: May 1-31, 2023

To view your statement, please log in to your account at www.legitimatebank.com.

If you have any questions, please contact our customer service at 1-800-123-4567.

Thank you for banking with us.

Customer Service
Legitimate Bank
            """,
            "is_phishing": False,
            "metadata": {"type": "account_statement", "confidence": 0.95}
        },
        # Service update
        {
            "content": """
Subject: Important Update to Our Terms of Service

Dear User,

We're writing to inform you about upcoming changes to our Terms of Service and Privacy Policy, effective July 1, 2023.

Key changes include:
- Updated data processing practices
- New options for managing your privacy settings
- Improved account security features

You can review the full updated terms at: https://ourservice.com/terms

If you continue to use our services after July 1, 2023, you agree to these updated terms.

Legal Team
Our Service
            """,
            "is_phishing": False,
            "metadata": {"type": "terms_update", "confidence": 0.9}
        },
        # Marketing email
        {
            "content": """
Subject: Summer Sale - Up to 50% Off!

Hello Shopper,

Our Summer Sale is here! Enjoy discounts of up to 50% on selected items.

SHOP NOW: https://legitimatestore.com/summer-sale

Sale ends June 30, 2023.

To unsubscribe from marketing emails, click here.

Happy Shopping!
Marketing Team
Legitimate Store
            """,
            "is_phishing": False,
            "metadata": {"type": "marketing", "confidence": 0.85}
        },
        # Support response
        {
            "content": """
Subject: Re: Help with my account [Ticket #12345]

Hello,

Thank you for contacting our support team. I'm happy to help with your account issue.

Based on your description, it sounds like you need to clear your browser cache. Here's how:

1. Open your browser settings
2. Navigate to Privacy & Security
3. Select 'Clear browsing data'
4. Choose 'Cached images and files'
5. Click 'Clear data'

If you continue to experience issues, please reply to this email or visit our help center at https://support.legitimateservice.com.

Best regards,
John
Customer Support Team
            """,
            "is_phishing": False,
            "metadata": {"type": "support_response", "confidence": 0.95}
        }
    ]
    
    # Add phishing examples to the database
    for example in phishing_examples:
        success = db_manager.add_email(
            example["content"],
            example["is_phishing"],
            example["metadata"]
        )
        if not success:
            logger.error(f"Failed to add phishing example: {example['metadata']['type']}")
    
    # Add legitimate examples to the database
    for example in legitimate_examples:
        success = db_manager.add_email(
            example["content"],
            example["is_phishing"],
            example["metadata"]
        )
        if not success:
            logger.error(f"Failed to add legitimate example: {example['metadata']['type']}")
    
    # Save the database
    db_manager.save()
    
    # Check final stats
    stats = db_manager.get_stats()
    logger.info(f"Vector database now contains {stats['total_emails']} emails")
    logger.info(f"Phishing emails: {stats.get('phishing_emails', 0)}")
    logger.info(f"Legitimate emails: {stats.get('legitimate_emails', 0)}")
    
    return True

if __name__ == "__main__":
    add_enhanced_training_data() 