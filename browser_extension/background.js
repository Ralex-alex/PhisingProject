// Background script to handle API communication
let apiHealthCheckInterval = null;
let isApiHealthy = false;

// Function to check API health
async function checkApiHealth() {
  try {
    const response = await fetch('http://localhost:8000/health', {
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    const newHealthStatus = data.status === 'healthy';
    
    // If health status changed, notify all tabs
    if (newHealthStatus !== isApiHealthy) {
      isApiHealthy = newHealthStatus;
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach(tab => {
          if (tab.url?.includes('mail.google.com')) {
            chrome.tabs.sendMessage(tab.id, {
              type: 'API_STATUS_CHANGE',
              isHealthy: isApiHealthy
            });
          }
        });
      });
    }
  } catch (error) {
    console.error('API health check failed:', error);
    isApiHealthy = false;
  }
}

// Start periodic health checks
function startHealthCheck() {
  if (!apiHealthCheckInterval) {
    checkApiHealth(); // Initial check
    apiHealthCheckInterval = setInterval(checkApiHealth, 30000); // Check every 30 seconds
  }
}

// Stop health checks
function stopHealthCheck() {
  if (apiHealthCheckInterval) {
    clearInterval(apiHealthCheckInterval);
    apiHealthCheckInterval = null;
  }
}

// Handle API requests from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'API_REQUEST') {
    // Make the API request
    fetch(request.url, {
      method: request.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: request.body ? JSON.stringify(request.body) : undefined
    })
    .then(async response => {
      // Update API health status based on response
      isApiHealthy = true;
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorText}`);
      }
      return response.json();
    })
    .then(data => {
      // If we get here, the API is definitely healthy
      isApiHealthy = true;
      sendResponse({ success: true, data });
    })
    .catch(error => {
      console.error('API request failed:', error);
      // Only mark API as unhealthy if it's a connection error
      if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
        isApiHealthy = false;
      }
      sendResponse({
        success: false,
        error: error.message || 'Failed to communicate with the API server.'
      });
    });
    
    return true; // Required to use sendResponse asynchronously
  }
  
  // Handle API health check requests
  if (request.type === 'GET_API_STATUS') {
    // Do a fresh health check
    checkApiHealth().then(() => {
      sendResponse({ isHealthy: isApiHealthy });
    });
    return true;
  }
});

// Start health checks when extension loads
startHealthCheck();

// Handle extension lifecycle
chrome.runtime.onStartup.addListener(startHealthCheck);
chrome.runtime.onSuspend.addListener(stopHealthCheck);

// Handle tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url?.includes('mail.google.com')) {
    // Do a fresh health check when navigating to Gmail
    checkApiHealth().then(() => {
      chrome.tabs.sendMessage(tabId, {
        type: 'API_STATUS_CHANGE',
        isHealthy: isApiHealthy
      });
    });
  }
}); 