// Function to extract email content from the current page
function extractEmailContent() {
  let subject = '';
  let body = '';
  let sender = '';
  let recipient = '';
  let htmlContent = false;
  let isEmailSelected = false;
  
  // Check which webmail service we're on
  if (window.location.href.includes('mail.google.com')) {
    // Gmail
    try {
      // First check if we're actually viewing an email
      const url = window.location.href;
      const isInEmailView = url.includes('#inbox/') || 
                          url.includes('/message/') ||
                          url.includes('?compose=') ||
                          url.match(/#[a-zA-Z]+\/[a-zA-Z0-9]+/); // Matches patterns like #sent/ABC123
      
      // More specific checks for email view with multiple selector fallbacks
      const emailContainerSelectors = [
        'div[role="main"]',
        '.adn.ads',
        '.g3',
        '.ii.gt',
        'div[data-message-id]'
      ];
      
      const emailBodySelectors = [
        'div.a3s.aiL',
        'div[data-message-id] div.ii.gt',
        'div.adP.adO',
        'div[dir="ltr"]',
        '.message-content',
        'div.gmail_quote',
        'div[aria-label="Message Body"]'
      ];
      
      const subjectSelectors = [
        'h2.hP',
        '.ha h2',
        'div[data-thread-perm-id] h2',
        '[data-legacy-thread-id] h2',
        'div[role="main"] h2',
        'div[role="heading"]',
        'span.hP'
      ];
      
      // Try each selector until we find a match
      let emailContainer = null;
      let emailBody = null;
      let subjectElement = null;
      
      for (const selector of emailContainerSelectors) {
        emailContainer = document.querySelector(selector);
        if (emailContainer) break;
      }
      
      for (const selector of emailBodySelectors) {
        emailBody = document.querySelector(selector);
        if (emailBody) break;
      }
      
      for (const selector of subjectSelectors) {
        subjectElement = document.querySelector(selector);
        if (subjectElement) break;
      }
      
      // Additional check for thread view
      const threadContainer = document.querySelector('div[role="main"] div[role="list"], .adn.ads, div[data-message-id]');
      
      // Log current state for debugging
      console.log('Checking email selection...', {
        hasContainer: !!emailContainer,
        hasBody: !!emailBody,
        hasSubject: !!subjectElement,
        hasThread: !!threadContainer,
        url: window.location.href,
        isInEmailView
      });
      
      // If we're not in an email view but have some elements, wait briefly
      if ((!isInEmailView || !emailBody || !subjectElement) && emailContainer) {
        console.log('Email content not immediately found, waiting briefly...');
        return new Promise((resolve) => {
          setTimeout(async () => {
            // Try again after waiting
            for (const selector of emailBodySelectors) {
              emailBody = document.querySelector(selector);
              if (emailBody) break;
            }
            
            for (const selector of subjectSelectors) {
              subjectElement = document.querySelector(selector);
              if (subjectElement) break;
            }
            
            // Check if URL has updated
            const newUrl = window.location.href;
            const newIsInEmailView = newUrl.includes('#inbox/') || 
                                   newUrl.includes('/message/') ||
                                   newUrl.includes('?compose=') ||
                                   newUrl.match(/#[a-zA-Z]+\/[a-zA-Z0-9]+/);
            
            if (!newIsInEmailView || (!emailBody && !subjectElement)) {
              console.log('Still missing required elements after waiting');
              resolve({ isEmailSelected: false, error: 'Please open an email to analyze' });
              return;
            }
            
            // If we have either body or subject, try to extract what we can
            if (emailBody || subjectElement) {
              const result = await extractEmailDetails(emailBody, subjectElement);
              resolve(result);
            } else {
              resolve({ isEmailSelected: false, error: 'Email content not found' });
            }
          }, 1000);
        });
      }
      
      // If we're not in an email view and don't have an email container
      if (!isInEmailView && !emailContainer) {
        console.log('Not in email view');
        return { isEmailSelected: false, error: 'Please open an email to analyze' };
      }
      
      // Extract email details if we have any required elements
      if (emailBody || subjectElement) {
        return extractEmailDetails(emailBody, subjectElement);
      }
      
      return { isEmailSelected: false, error: 'Email content not found' };
      
    } catch (e) {
      console.error('Error extracting Gmail content:', e);
      return { 
        isEmailSelected: false, 
        error: `Error extracting email content: ${e.message}` 
      };
    }
  }
  
  return { isEmailSelected: false, error: 'Not in Gmail' };
}

// Helper function to extract email details
async function extractEmailDetails(emailBody, subjectElement) {
  try {
    let subject = '';
    let body = '';
    let htmlContent = false;
    
    // Get the subject if available
    if (subjectElement) {
      subject = subjectElement.textContent.trim();
      console.log('Found subject:', subject);
    } else {
      // Try to find subject in other elements
      const threadSubject = document.querySelector('div[role="main"] span[data-thread-id]')?.textContent?.trim();
      if (threadSubject) {
        subject = threadSubject;
        console.log('Found subject from thread:', subject);
      }
    }
    
    // Get the body if available
    if (emailBody) {
      const rawBody = emailBody.innerHTML.trim();
      if (rawBody) {
        body = rawBody;
        htmlContent = true;
        console.log('Found email body, length:', body.length);
      }
    }
    
    // Enhanced sender detection with multiple fallback methods
    const senderSelectors = [
      'span[email]',
      '.gD',
      'span[data-hovercard-id*="@"]',
      'div[data-tooltip][data-email]',
      'span.go',
      'span[data-hovercard-owner-id]',
      '.message-from',
      '.sender-info',
      'div[role="main"] span[email]',
      'table.cf.gJ td.gF span'
    ];
    
    let sender = '';
    let senderElement = null;
    
    // Try each sender selector
    for (const selector of senderSelectors) {
      const elements = document.querySelectorAll(selector);
      for (const element of elements) {
        const potentialSender = element.getAttribute('email') || 
                              element.getAttribute('data-hovercard-id') ||
                              element.getAttribute('data-email') ||
                              element.textContent.trim();
        
        if (potentialSender && potentialSender.includes('@')) {
          sender = potentialSender;
          senderElement = element;
          break;
        }
      }
      if (sender) break;
    }
    
    // If no sender found, try parsing from the email header
    if (!sender) {
      const headerSelectors = [
        '.ha h3',
        '.message-header',
        'div[role="main"] h3',
        '.cf.gJ',
        'table.cf.gJ'
      ];
      
      for (const selector of headerSelectors) {
        const headerText = document.querySelector(selector)?.textContent || '';
        const emailMatch = headerText.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
        if (emailMatch) {
          sender = emailMatch[0];
          break;
        }
      }
    }
    
    if (!sender) {
      console.log('Could not find sender element');
      return { isEmailSelected: false, error: 'Sender not found' };
    }
    
    console.log('Found sender:', sender);
    
    // Try to get recipient with multiple selectors
    const recipientSelectors = [
      'span[data-hovercard-id*="@"]:not(.gD)',
      'span.g2:not(.gD)',
      '.to-field span',
      '.recipient-info',
      'div[role="main"] span[email]:not(.gD)',
      'table.cf.gJ td.gF .g2'
    ];
    
    let recipient = '';
    for (const selector of recipientSelectors) {
      const elements = document.querySelectorAll(selector);
      for (const element of elements) {
        const potentialRecipient = element.getAttribute('data-hovercard-id') ||
                                 element.getAttribute('email') ||
                                 element.textContent.trim();
        if (potentialRecipient && potentialRecipient.includes('@')) {
          recipient = potentialRecipient;
          break;
        }
      }
      if (recipient) break;
    }
    
    console.log('Found recipient:', recipient);
    
    // Consider email selected if we have at least subject or body, plus sender
    const isEmailSelected = !!(sender && (subject || body));
    
    if (!isEmailSelected) {
      return { 
        isEmailSelected: false, 
        error: 'Could not find complete email content. Please make sure an email is fully opened.' 
      };
    }
    
    return {
      subject,
      body,
      sender,
      recipient,
      htmlContent,
      isEmailSelected: true
    };
  } catch (e) {
    console.error('Error in extractEmailDetails:', e);
    return { 
      isEmailSelected: false, 
      error: `Error extracting email details: ${e.message}` 
    };
  }
}

// Function to show phishing result
function showPhishingResult(data, sender) {
  // Remove any existing result
  const existingResult = document.getElementById('phishing-result');
  if (existingResult) {
    existingResult.remove();
  }
  
  // Create overlay
  const overlay = document.createElement('div');
  overlay.id = 'phishing-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    z-index: 9998;
    opacity: 0;
    transition: opacity 0.2s ease-in-out;
  `;
  
  // Create result element
  const resultElement = document.createElement('div');
  resultElement.id = 'phishing-result';
  resultElement.setAttribute('role', 'dialog');
  resultElement.setAttribute('aria-labelledby', 'phishing-result-title');
  resultElement.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%) scale(0.95);
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    z-index: 9999;
    max-width: 500px;
    width: 90%;
    font-family: 'Google Sans', Roboto, sans-serif;
    opacity: 0;
    transition: all 0.2s ease-in-out;
  `;
  
  // Style based on result
  let resultHTML = '';
  if (data.is_phishing) {
    resultHTML = `
      <div style="color: #d93025; margin-bottom: 15px;">
        <h2 id="phishing-result-title" style="margin: 0; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 24px;" role="img" aria-label="Warning">⚠️</span>
          Phishing Email Detected
        </h2>
      </div>
      <div style="margin-bottom: 15px;">
        <p style="margin: 5px 0;"><strong>Confidence:</strong> ${Math.round(data.confidence * 100)}%</p>
        <p style="margin: 5px 0;"><strong>Risk Level:</strong> ${data.risk_level.toUpperCase()}</p>
      </div>
    `;
    
    if (data.suspicious_elements && data.suspicious_elements.length > 0) {
      resultHTML += `
        <div style="margin-bottom: 15px;">
          <h3 style="margin: 0 0 8px 0;">Suspicious Elements:</h3>
          <ul style="margin: 0; padding-left: 20px;">
            ${data.suspicious_elements.map(element => 
              `<li style="margin-bottom: 5px;">${element.description}</li>`
            ).join('')}
          </ul>
        </div>
      `;
    }
    
    if (data.recommendations && data.recommendations.length > 0) {
      resultHTML += `
        <div style="margin-bottom: 15px;">
          <h3 style="margin: 0 0 8px 0;">Recommendations:</h3>
          <ul style="margin: 0; padding-left: 20px;">
            ${data.recommendations.map(rec => 
              `<li style="margin-bottom: 5px;">${rec}</li>`
            ).join('')}
          </ul>
        </div>
      `;
    }
  } else {
    resultHTML = `
      <div style="color: #188038; margin-bottom: 15px;">
        <h2 id="phishing-result-title" style="margin: 0; display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 24px;" role="img" aria-label="Checkmark">✓</span>
          Legitimate Email
        </h2>
      </div>
      <div style="margin-bottom: 15px;">
        <p style="margin: 5px 0;"><strong>Confidence:</strong> ${Math.round((1 - data.confidence) * 100)}%</p>
        <p style="margin: 5px 0;">No high-risk phishing indicators detected.</p>
      </div>
    `;
    
    if (data.recommendations && data.recommendations.length > 0) {
      resultHTML += `
        <div style="margin-bottom: 15px;">
          <h3 style="margin: 0 0 8px 0;">Recommendations:</h3>
          <ul style="margin: 0; padding-left: 20px;">
            ${data.recommendations.map(rec => 
              `<li style="margin-bottom: 5px;">${rec}</li>`
            ).join('')}
          </ul>
        </div>
      `;
    }
  }
  
  // Add actions
  resultHTML += `
    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px;">
      <button id="phishing-close-btn" style="
        padding: 8px 16px;
        border: none;
        border-radius: 4px;
        background: #f1f3f4;
        cursor: pointer;
        font-family: inherit;
        transition: background 0.2s;
      ">Close</button>
      <button id="phishing-report-btn" style="
        padding: 8px 16px;
        border: none;
        border-radius: 4px;
        background: #1a73e8;
        color: white;
        cursor: pointer;
        font-family: inherit;
        transition: background 0.2s;
      ">${data.is_phishing ? 'Report False Positive' : 'Report False Negative'}</button>
    </div>
  `;
  
  resultElement.innerHTML = resultHTML;
  
  // Add to page
  document.body.appendChild(overlay);
  document.body.appendChild(resultElement);
  
  // Force reflow to enable transitions
  overlay.offsetHeight;
  resultElement.offsetHeight;
  
  // Show with animation
  overlay.style.opacity = '1';
  resultElement.style.opacity = '1';
  resultElement.style.transform = 'translate(-50%, -50%) scale(1)';
  
  // Add button hover effects
  const closeBtn = document.getElementById('phishing-close-btn');
  const reportBtn = document.getElementById('phishing-report-btn');
  
  closeBtn.addEventListener('mouseover', () => closeBtn.style.background = '#e8eaed');
  closeBtn.addEventListener('mouseout', () => closeBtn.style.background = '#f1f3f4');
  reportBtn.addEventListener('mouseover', () => reportBtn.style.background = '#1557b0');
  reportBtn.addEventListener('mouseout', () => reportBtn.style.background = '#1a73e8');
  
  // Add close handlers
  function closeModal() {
    overlay.style.opacity = '0';
    resultElement.style.opacity = '0';
    resultElement.style.transform = 'translate(-50%, -50%) scale(0.95)';
    setTimeout(() => {
      overlay.remove();
      resultElement.remove();
    }, 200);
  }
  
  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal();
  });
  
  // Add keyboard navigation
  const focusableElements = resultElement.querySelectorAll('button');
  const firstFocusable = focusableElements[0];
  const lastFocusable = focusableElements[focusableElements.length - 1];
  
  // Focus first button
  firstFocusable.focus();
  
  function handleTabKey(e) {
    if (e.key === 'Tab') {
      if (e.shiftKey) {
        if (document.activeElement === firstFocusable) {
          e.preventDefault();
          lastFocusable.focus();
        }
      } else {
        if (document.activeElement === lastFocusable) {
          e.preventDefault();
          firstFocusable.focus();
        }
      }
    }
    
    if (e.key === 'Escape') {
      closeModal();
    }
  }
  
  resultElement.addEventListener('keydown', handleTabKey);
  
  // Add report button handler
  reportBtn.addEventListener('click', async () => {
    try {
      showLoadingIndicator();
      
      // First check if API is healthy
      const healthCheck = await new Promise(resolve => {
        chrome.runtime.sendMessage({ type: 'GET_API_STATUS' }, response => {
          resolve(response?.isHealthy);
        });
      });

      if (!healthCheck) {
        throw new Error('API service is not available');
      }

      // Ensure data object has required properties
      if (!data) {
        throw new Error('No analysis data available');
      }

      // For false positives, user_verdict should be false (not phishing)
      // For false negatives, user_verdict should be true (is phishing)
      const userVerdict = data.is_phishing ? false : true;

      // Prepare feedback data with null checks
      const feedbackData = {
        is_phishing: Boolean(data.is_phishing),
        email_content: data.emailContent || '',
        user_verdict: userVerdict,
        email_data: {
          subject: data.subject || '',
          sender: sender || '',
          confidence: typeof data.confidence === 'number' ? data.confidence : 0,
          reported_as: data.is_phishing ? 'false_positive' : 'false_negative',
          domain: sender ? sender.split('@')[1] : '',
          context: {
            is_known_sender: sender ? isKnownSender(sender) : false,
            is_business_domain: sender ? isBusinessDomain(sender) : false,
            has_valid_dkim: true,
            has_valid_spf: true,
            sender_category: sender ? getSenderCategory(sender) : 'unknown',
            email_type: getEmailType(data.subject)
          }
        }
      };

      console.log('Submitting feedback with data:', {
        ...data,
        emailContent: data.emailContent ? `${data.emailContent.substring(0, 100)}...` : ''
      });
      console.log('Submitting feedback payload:', {
        ...feedbackData,
        email_content: feedbackData.email_content ? `${feedbackData.email_content.substring(0, 100)}...` : ''
      });

      // Make the API request
      const response = await Promise.race([
        new Promise((resolve, reject) => {
          const requestTimeout = setTimeout(() => {
            reject(new Error('Request timed out after 10 seconds'));
          }, 10000);

          chrome.runtime.sendMessage({
            type: 'API_REQUEST',
            url: 'http://localhost:8000/feedback',
            method: 'POST',
            body: feedbackData
          }, response => {
            clearTimeout(requestTimeout);
            console.log('Raw feedback response:', response);
            
            if (chrome.runtime.lastError) {
              console.error('Chrome runtime error:', chrome.runtime.lastError);
              reject(new Error(chrome.runtime.lastError.message));
              return;
            }
            
            if (!response) {
              reject(new Error('No response received from API'));
              return;
            }

            // Handle different response formats
            let parsedResponse;
            try {
              parsedResponse = typeof response === 'string' ? JSON.parse(response) : response;
              
              // Check if the response has an error field
              if (parsedResponse.error) {
                reject(new Error(parsedResponse.error));
                return;
              }

              // Check if the response has a data field
              if (parsedResponse.data) {
                parsedResponse = parsedResponse.data;
              }

              console.log('Parsed feedback response:', parsedResponse);
              resolve(parsedResponse);
            } catch (error) {
              console.error('Error parsing response:', error);
              reject(new Error('Invalid response format'));
            }
          });
        })
      ]);

      hideLoadingIndicator();
      
      console.log('Final response:', response);
      
      // Check for success in both the wrapper and data object
      if (response.success || 
          (response.data && response.data.success) || 
          (response.status && response.status === 'success')) {
        
        // Get feedback ID if available
        const feedbackId = response.data?.feedback_id || 'unknown';
        
        // Show success message with feedback ID
        showSuccess(`Thank you for your feedback! Your feedback ID is ${feedbackId}. This helps improve our phishing detection.`);
        
        // Log success details
        console.log('Feedback submitted successfully:', {
          feedbackId,
          message: response.data?.message || 'Feedback recorded'
        });
        
        closeModal();
      } else {
        console.error('Unsuccessful response:', response);
        throw new Error(response.error || response.data?.error || 'Failed to submit feedback');
      }
    } catch (error) {
      console.error('Feedback submission error:', error);
      hideLoadingIndicator();
      
      // Improve error message display
      let errorMessage = error.message;
      if (error.message.includes('status: 422')) {
        errorMessage = 'Invalid feedback data format. Please try again.';
      } else if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
        errorMessage = 'Network error. Please check your connection and try again.';
      } else if (error.message.includes('timeout')) {
        errorMessage = 'Request timed out. Please try again.';
      } else if (error.message === 'No response received from API') {
        errorMessage = 'No response from server. Please try again.';
      }
      
      showError(`Failed to submit feedback: ${errorMessage}`);
    }
  });
}

// Function to show success message
function showSuccess(message) {
  const successElement = document.createElement('div');
  successElement.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: #188038;
    color: white;
    padding: 12px 20px;
    border-radius: 4px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    z-index: 9999;
    font-family: 'Google Sans', Roboto, sans-serif;
  `;
  successElement.textContent = message;
  
  document.body.appendChild(successElement);
  
  setTimeout(() => {
    successElement.remove();
  }, 3000);
}

// Function to show error message
function showError(message) {
  const errorElement = document.createElement('div');
  errorElement.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: #d93025;
    color: white;
    padding: 12px 20px;
    border-radius: 4px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    z-index: 9999;
    font-family: 'Google Sans', Roboto, sans-serif;
  `;
  errorElement.textContent = message;
  
  document.body.appendChild(errorElement);
  
  setTimeout(() => {
    errorElement.remove();
  }, 3000);
}

// Function to make API requests through background script
async function makeAPIRequest(url, method = 'GET', body = null) {
  console.log(`Making API request to ${url}`, { method, body });
  
  try {
    // First check API health
    const healthCheck = await new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'GET_API_STATUS' }, response => {
        resolve(response?.isHealthy);
      });
    });
    
    // Make the actual request
    const response = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        type: 'API_REQUEST',
        url,
        method,
        body
      }, response => {
        if (chrome.runtime.lastError) {
          console.error('Chrome runtime error:', chrome.runtime.lastError);
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        
        if (!response) {
          console.error('No response received from API');
          reject(new Error('No response received from API'));
          return;
        }
        
        console.log('API response received:', response);
        
        if (response.success && response.data) {
          resolve(response.data);
        } else if (response.success === false) {
          reject(new Error(response.error || 'API request failed'));
        } else {
          reject(new Error('Invalid API response format'));
        }
      });
    });
    
    return response;
    
  } catch (error) {
    console.error('API request failed:', error);
    throw error; // Preserve the original error message
  }
}

// Function to show loading indicator
function showLoadingIndicator() {
  // Remove any existing indicators
  hideLoadingIndicator();
  
  // Create loading indicator
  const loadingElement = document.createElement('div');
  loadingElement.id = 'phishing-loading';
  loadingElement.className = 'phishing-loading';
  loadingElement.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    z-index: 9999;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
  `;
  
  loadingElement.innerHTML = `
    <div class="phishing-loading-spinner" style="
      width: 30px;
      height: 30px;
      border: 3px solid #f3f3f3;
      border-top: 3px solid #3498db;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    "></div>
    <p style="margin: 0; color: #333;">Analyzing email for phishing indicators...</p>
    <style>
      @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
    </style>
  `;
  
  // Add to page
  document.body.appendChild(loadingElement);
}

// Hide loading indicator
function hideLoadingIndicator() {
  const loadingElement = document.getElementById('phishing-loading');
  if (loadingElement) {
    loadingElement.remove();
  }
}

// Function to add the phishing check button
function addPhishingCheckButton() {
  // Remove any existing button first
  const existingButton = document.getElementById('phishing-check-btn');
  if (existingButton) {
    existingButton.remove();
  }
  
  // Create button container
  const buttonContainer = document.createElement('div');
  buttonContainer.id = 'phishing-check-container';
  buttonContainer.style.cssText = `
    display: inline-flex;
    align-items: center;
    margin-left: 8px;
    position: relative;
  `;
  
  // Create the button
  const button = document.createElement('button');
  button.id = 'phishing-check-btn';
  button.setAttribute('aria-label', 'Check for phishing');
  button.style.cssText = `
    background: none;
    border: 1px solid #dadce0;
    border-radius: 4px;
    padding: 6px 12px;
    font-family: 'Google Sans', Roboto, sans-serif;
    font-size: 14px;
    color: #3c4043;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: all 0.2s;
    height: 32px;
    min-width: 32px;
    white-space: nowrap;
  `;
  
  // Add icon and text
  button.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v5.7c0 4.83-3.4 9.36-7 10.46-3.6-1.1-7-5.63-7-10.46v-5.7l7-3.12z"/>
      <path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zm0 8c-1.66 0-3-1.34-3-3s1.34-3 3-3 3 1.34 3 3-1.34 3-3 3z"/>
    </svg>
    <span>Check for Phishing</span>
  `;
  
  // Add hover and active states
  button.addEventListener('mouseover', () => {
    button.style.background = '#f1f3f4';
    button.style.borderColor = '#dadce0';
  });
  
  button.addEventListener('mouseout', () => {
    button.style.background = 'none';
    button.style.borderColor = '#dadce0';
  });
  
  button.addEventListener('mousedown', () => {
    button.style.background = '#e8eaed';
  });
  
  button.addEventListener('mouseup', () => {
    button.style.background = '#f1f3f4';
  });
  
  // Add click handler
  button.addEventListener('click', handlePhishingCheck);
  
  buttonContainer.appendChild(button);
  
  // Find the best position to insert the button
  const toolbar = findButtonPosition();
  if (!toolbar) {
    console.log('Could not find Gmail toolbar');
    return null;
  }
  
  // Find the best position in the toolbar
  const referenceButtons = toolbar.querySelectorAll('.T-I.J-J5-Ji,[role="button"]');
  let insertAfter = null;
  
  for (const btn of referenceButtons) {
    const text = btn.textContent.toLowerCase();
    if (text.includes('spam') || text.includes('delete') || text.includes('archive')) {
      insertAfter = btn;
    }
  }
  
  if (insertAfter && insertAfter.parentNode) {
    // Insert after a relevant button
    insertAfter.parentNode.insertBefore(buttonContainer, insertAfter.nextSibling);
  } else {
    // Fallback: append to toolbar
    toolbar.appendChild(buttonContainer);
  }
  
  return button;
}

// Initialize the extension
(function() {
  console.log('PhishSentinel extension initialized');
  
  let lastUrl = location.href;
  let buttonAddAttempts = 0;
  const MAX_ATTEMPTS = 15;  // Increased from 10
  const INITIAL_RETRY_DELAY = 50;  // Reduced from 100ms
  const observers = new Map();
  
  // Function to attempt adding button with retry
  function attemptAddButton(immediate = false) {
    if (buttonAddAttempts >= MAX_ATTEMPTS) {
      console.log('Max button add attempts reached');
      buttonAddAttempts = 0;
      return;
    }
    
    buttonAddAttempts++;
    console.log(`Attempting to add button (attempt ${buttonAddAttempts})`);
    
    const button = addPhishingCheckButton();
    
    if (!button) {
      // Calculate delay with exponential backoff
      const delay = immediate ? 0 : Math.min(INITIAL_RETRY_DELAY * Math.pow(1.5, buttonAddAttempts - 1), 2000);
      setTimeout(() => attemptAddButton(false), delay);
    } else {
      console.log('Button added successfully');
      buttonAddAttempts = 0;
    }
  }
  
  // Set up mutation observer for Gmail's dynamic content
  const setupObservers = () => {
    // Clean up existing observers
    observers.forEach(observer => observer.disconnect());
    observers.clear();
    
    // Main content observer
    const contentObserver = new MutationObserver((mutations) => {
      // Check for URL changes
      const currentUrl = location.href;
      if (currentUrl !== lastUrl) {
        console.log('URL changed:', currentUrl);
        lastUrl = currentUrl;
        buttonAddAttempts = 0;
        attemptAddButton(true);
      }
      
      // Check for relevant content changes
      if (isInEmailView() && isEmailContentLoaded()) {
        const button = document.getElementById('phishing-check-btn');
        if (!button) {
          console.log('Content loaded but button missing, adding button');
          buttonAddAttempts = 0;
          attemptAddButton(true);
        }
      }
    });
    
    // Observe the entire document for maximum coverage
    contentObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['role', 'class', 'style', 'data-message-id']
    });
    
    observers.set('content', contentObserver);
    
    // Toolbar-specific observer
    const toolbarObserver = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'childList' || 
            (mutation.type === 'attributes' && mutation.attributeName === 'role')) {
          const button = document.getElementById('phishing-check-btn');
          if (!button && isInEmailView()) {
            console.log('Toolbar changed, attempting to add button');
            buttonAddAttempts = 0;
            attemptAddButton(true);
          }
        }
      }
    });
    
    // Find and observe all possible toolbar locations
    const toolbarSelectors = [
      'div[role="toolbar"]',
      '.G-tF',
      'div[gh="mtb"]',
      'div[gh="tm"]',
      '.G-atb'
    ];
    
    toolbarSelectors.forEach(selector => {
      const element = document.querySelector(selector);
      if (element) {
        toolbarObserver.observe(element, {
          childList: true,
          attributes: true,
          attributeFilter: ['role', 'class']
        });
      }
    });
    
    observers.set('toolbar', toolbarObserver);
  };
  
  // Initial setup
  setupObservers();
  
  // Handle page load events
  ['DOMContentLoaded', 'load'].forEach(event => {
    window.addEventListener(event, () => {
      console.log(`${event} fired, checking for email view`);
      if (isInEmailView()) {
        buttonAddAttempts = 0;
        attemptAddButton(true);
      }
    });
  });
  
  // Handle navigation events
  ['popstate', 'hashchange'].forEach(event => {
    window.addEventListener(event, () => {
      console.log(`Navigation event: ${event}`);
      lastUrl = location.href;
      buttonAddAttempts = 0;
      attemptAddButton(true);
    });
  });
  
  // Initial check
  if (isInEmailView()) {
    console.log('Initial load: Email view detected');
    attemptAddButton(true);
  }
  
  // Periodic check for the first few seconds
  let checkCount = 0;
  const intervalId = setInterval(() => {
    if (checkCount++ < 20) { // Increased from 10 to 20 checks
      if (isInEmailView() && !document.getElementById('phishing-check-btn')) {
        console.log('Periodic check: Email view detected, button missing');
        attemptAddButton(true);
      }
    } else {
      clearInterval(intervalId);
    }
  }, 250); // Reduced from 500ms to 250ms
})();

// Helper functions for feedback context
function isKnownSender(sender) {
  const knownDomains = [
    'cursor.so',
    'github.com',
    'google.com',
    'microsoft.com',
    'apple.com',
    'twitch.tv',
    'twitter.com',
    'linkedin.com'
    // Add more known domains as needed
  ];
  const domain = sender.split('@')[1].toLowerCase();
  return knownDomains.includes(domain);
}

function isBusinessDomain(sender) {
  const domain = sender.split('@')[1].toLowerCase();
  // Check if it's not a free email provider
  const freeEmailProviders = [
    'gmail.com',
    'yahoo.com',
    'hotmail.com',
    'outlook.com',
    'aol.com'
  ];
  return !freeEmailProviders.includes(domain);
}

function getSenderCategory(sender) {
  const domain = sender.split('@')[1].toLowerCase();
  if (domain === 'cursor.so') return 'developer_tool';
  if (domain === 'github.com') return 'development_platform';
  if (domain === 'twitch.tv') return 'streaming_platform';
  if (domain.includes('google')) return 'tech_company';
  if (domain.includes('microsoft')) return 'tech_company';
  if (domain.includes('apple')) return 'tech_company';
  if (domain.includes('linkedin')) return 'social_network';
  if (domain.includes('twitter')) return 'social_network';
  return 'unknown';
}

function getEmailType(subject) {
  if (!subject) return 'unknown';
  
  subject = subject.toLowerCase();
  if (subject.includes('password') || subject.includes('security') || subject.includes('login')) {
    return 'security_related';
  }
  if (subject.includes('invoice') || subject.includes('payment') || subject.includes('bill')) {
    return 'financial';
  }
  if (subject.includes('update') || subject.includes('news') || subject.includes('newsletter')) {
    return 'informational';
  }
  if (subject.includes('welcome') || subject.includes('getting started')) {
    return 'onboarding';
  }
  if (subject.includes('verify') || subject.includes('confirm')) {
    return 'verification';
  }
  return 'general';
}

// Function to check if we're in an email view
function isInEmailView() {
  const url = window.location.href;
  
  // Check URL patterns
  const emailViewPatterns = [
    '#inbox/',
    '/message/',
    '?compose=',
    '#sent/',
    '#starred/',
    '#snoozed/',
    '#draft/',
    '#all/',
    '#spam/',
    '#trash/',
    '#category/',
    '#label/',
    '#search/',
    '#settings/'
  ];
  
  // Check if URL matches any email view pattern
  const isEmailUrl = emailViewPatterns.some(pattern => url.includes(pattern));
  
  // Check for email view elements
  const emailViewSelectors = [
    'div[role="main"]',
    '.adn.ads',
    '.g3',
    '.ii.gt',
    'div[data-message-id]',
    'table.Bs.nH.iY',
    'div.nH.aHU',
    '.BltHke[role="main"]',
    // Inbox specific selectors
    'div[gh="tl"]',  // Gmail list container
    'table.F.cf.zt',  // Email list table
    'div.AO',        // Main content area
    'div.ae4.UI'     // Email list view
  ];
  
  // Check if any email view elements exist
  const hasEmailElements = emailViewSelectors.some(selector => 
    document.querySelector(selector)
  );
  
  return isEmailUrl || hasEmailElements;
}

// Function to check if email content is loaded
function isEmailContentLoaded() {
  const contentIndicators = [
    // Email view indicators
    'div.a3s.aiL',                    // Email body
    'div[data-message-id]',           // Message container
    'div.adn.ads',                    // Email view
    'div.nH.aHU',                     // Email container
    'table.Bs.nH.iY',                 // Email table
    'div[role="main"] h2.hP',         // Subject header
    '.ha h3',                         // Sender info
    
    // Inbox view indicators
    'div[gh="tl"]',                   // Gmail list container
    'table.F.cf.zt',                  // Email list table
    'div.AO',                         // Main content area
    'div.ae4.UI',                     // Email list view
    'table.F.cf.zt tr'                // Email list items
  ];
  
  return contentIndicators.some(selector => document.querySelector(selector));
}

// Function to find the best position for the button
function findButtonPosition() {
  const toolbarSelectors = [
    // Email view toolbars
    'div[role="toolbar"]',
    '.G-tF',
    '.T-I-ax7',
    '.nH.aqK',
    '.gH.nH.oy8Mbf',
    
    // Inbox view toolbars
    'div[gh="mtb"]',                  // Main toolbar
    'div[gh="tm"]',                   // Top menu
    '.G-atb',                         // Action toolbar
    'div[role="toolbar"]'             // Generic toolbar
  ];
  
  let toolbar = null;
  for (const selector of toolbarSelectors) {
    toolbar = document.querySelector(selector);
    if (toolbar) break;
  }
  
  return toolbar;
}

// Handle phishing check button click
async function handlePhishingCheck() {
  try {
    const emailContent = await Promise.resolve(extractEmailContent());
    
    if (!emailContent.isEmailSelected) {
      showError(emailContent.error || 'Please select an email first.');
      return;
    }
    
    showLoadingIndicator();
    
    // First check if API is healthy
    const healthCheck = await new Promise(resolve => {
      chrome.runtime.sendMessage({ type: 'GET_API_STATUS' }, response => {
        resolve(response?.isHealthy);
      });
    });

    if (!healthCheck) {
      throw new Error('API service is not available');
    }
    
    const response = await makeAPIRequest('http://localhost:8000/predict', 'POST', {
      subject: emailContent.subject,
      body: emailContent.body,
      sender: emailContent.sender,
      recipient: emailContent.recipient,
      html_content: emailContent.htmlContent
    });
    
    hideLoadingIndicator();
    
    // Store the email content for feedback
    response.emailContent = emailContent.body || emailContent.htmlContent || '';
    response.subject = emailContent.subject || '';
    response.sender = emailContent.sender || '';
    
    // The response is the actual data now, not wrapped in a success field
    if (response && response.is_phishing !== undefined) {
      showPhishingResult(response, emailContent.sender);
    } else {
      console.error('Invalid API response:', response);
      showError('Failed to analyze email. Invalid response format.');
    }
  } catch (error) {
    hideLoadingIndicator();
    showError(error.message || 'Failed to analyze email. Please try again.');
    console.error('Error analyzing email:', error);
  }
} 