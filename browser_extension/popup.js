document.addEventListener('DOMContentLoaded', function() {
  // Get DOM elements
  const checkButton = document.getElementById('check-button');
  const subjectInput = document.getElementById('subject');
  const bodyInput = document.getElementById('body');
  const loadingDiv = document.getElementById('loading');
  const resultDiv = document.getElementById('result');
  
  // API endpoint
  const API_URL = 'http://localhost:8000/predict';
  
  // Check if we're connected to the API server
  checkServerStatus();
  
  // Add event listener for the check button
  checkButton.addEventListener('click', function() {
    // Get input values
    const subject = subjectInput.value.trim();
    const body = bodyInput.value.trim();
    
    // Validate input
    if (!body) {
      showResult('Please enter the email body content.', 'warning');
      return;
    }
    
    // Show loading
    loadingDiv.classList.remove('hidden');
    resultDiv.classList.add('hidden');
    
    // Prepare request data
    const requestData = {
      subject: subject,
      body: body,
      sender: ""  // Optional in our API
    };
    
    // Send request to API
    fetch(API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestData)
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('API request failed');
      }
      return response.json();
    })
    .then(data => {
      // Process the response
      processResult(data);
    })
    .catch(error => {
      console.error('Error:', error);
      showResult('Error connecting to the phishing detection service. Make sure the API server is running.', 'error');
    })
    .finally(() => {
      // Hide loading
      loadingDiv.classList.add('hidden');
    });
  });
  
  // Try to extract email content from the current tab
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (tabs[0] && tabs[0].url) {
      const url = tabs[0].url;
      
      // Check if we're on a webmail site
      if (url.includes('mail.google.com') || 
          url.includes('outlook.live.com') || 
          url.includes('outlook.office365.com')) {
        
        // Execute content script to extract email
        chrome.tabs.executeScript(
          tabs[0].id,
          {code: 'extractEmailContent();'},
          function(results) {
            if (results && results[0]) {
              const emailData = results[0];
              subjectInput.value = emailData.subject || '';
              bodyInput.value = emailData.body || '';
            }
          }
        );
      }
    }
  });
  
  function processResult(data) {
    // Extract data from response
    const isPhishing = data.is_phishing;
    const confidence = Math.round(data.confidence * 100);
    const riskLevel = data.risk_level;
    
    let resultHTML = '';
    
    if (isPhishing) {
      resultHTML = `
        <h2>⚠️ PHISHING DETECTED ⚠️</h2>
        <p><strong>Confidence:</strong> ${confidence}%</p>
        <p><strong>Risk Level:</strong> ${riskLevel.toUpperCase()}</p>
        <p>This email contains suspicious elements typical of phishing attempts.</p>
        <p><strong>ADVICE:</strong> Do not click any links, do not download attachments, and do not reply to this email.</p>
      `;
      resultDiv.className = 'result danger';
    } else {
      resultHTML = `
        <h2>✓ LEGITIMATE EMAIL</h2>
        <p><strong>Confidence:</strong> ${confidence}%</p>
        <p>No suspicious elements detected in this email.</p>
      `;
      resultDiv.className = 'result safe';
    }
    
    resultDiv.innerHTML = resultHTML;
    resultDiv.classList.remove('hidden');
  }
  
  function showResult(message, type) {
    let className = 'result';
    
    if (type === 'error' || type === 'danger') {
      className += ' danger';
    } else if (type === 'warning') {
      className += ' warning';
    }
    
    resultDiv.className = className;
    resultDiv.innerHTML = `<p>${message}</p>`;
    resultDiv.classList.remove('hidden');
  }
  
  function checkServerStatus() {
    fetch('http://localhost:8000/health')
      .then(response => {
        if (!response.ok) {
          throw new Error('API server not available');
        }
        return response.json();
      })
      .then(data => {
        if (data.status === 'healthy') {
          console.log('API server is running');
        } else {
          showResult('Warning: API server is not healthy. Some features may not work correctly.', 'warning');
        }
      })
      .catch(error => {
        console.error('Error checking server status:', error);
        showResult('API server is not running. Please start the phishing detection service.', 'error');
      });
  }
}); 