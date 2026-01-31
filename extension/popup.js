// PhishGuard AI - Popup Script
// Displays current page status and extension statistics

let currentTab = null;

/**
 * Initialize popup
 */
document.addEventListener('DOMContentLoaded', async () => {
  console.log('PhishGuard AI popup opened');
  
  try {
    // Get current tab
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tabs[0];
    
    if (!currentTab) {
      showError('Could not get current tab');
      return;
    }
    
    // Load data
    await Promise.all([
      loadPageStatus(),
      loadStatistics()
    ]);
    
    // Setup event listeners
    setupEventListeners();
    
    // Hide loading, show content
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('mainContent').classList.remove('hidden');
    
  } catch (error) {
    console.error('Error initializing popup:', error);
    showError('Failed to load PhishGuard AI');
  }
});

/**
 * Load current page status
 */
async function loadPageStatus() {
  try {
    // Display current URL
    const urlElement = document.getElementById('currentUrl');
    if (urlElement && currentTab.url) {
      // Truncate URL if too long
      const displayUrl = currentTab.url.length > 60 
        ? currentTab.url.substring(0, 57) + '...'
        : currentTab.url;
      urlElement.textContent = displayUrl;
    }
    
    // Get status from background script
    chrome.runtime.sendMessage({ action: 'getStatus' }, (status) => {
      if (chrome.runtime.lastError) {
        console.error('Error getting status:', chrome.runtime.lastError);
        displaySafeStatus(); // Default to safe on error
        return;
      }
      
      console.log('Page status:', status);
      
      if (status && !status.safe) {
        displayThreatStatus(status);
      } else {
        displaySafeStatus();
      }
    });
    
  } catch (error) {
    console.error('Error loading page status:', error);
    displaySafeStatus();
  }
}

/**
 * Display threat status
 */
function displayThreatStatus(status) {
  const { score, riskLevel, reasons = [] } = status;
  
  // Update status icon
  const statusIcon = document.getElementById('statusIcon');
  if (statusIcon) {
    statusIcon.textContent = score >= 80 ? '🚨' : '⚠️';
  }
  
  // Update status text
  const statusText = document.getElementById('statusText');
  if (statusText) {
    statusText.textContent = 'Threat Detected!';
    statusText.style.color = '#dc2626';
  }
  
  // Update status subtext
  const statusSubtext = document.getElementById('statusSubtext');
  if (statusSubtext) {
    const mainReason = reasons[0] || 'Suspicious activity detected';
    statusSubtext.textContent = mainReason;
  }
  
  // Update threat score
  const scoreValue = document.getElementById('scoreValue');
  const scoreDisplay = document.getElementById('scoreDisplay');
  
  if (scoreValue && scoreDisplay) {
    scoreValue.textContent = `${score}/100`;
    scoreValue.className = 'score-value danger';
    scoreDisplay.className = 'threat-score-display';
  }
  
  // Update badge
  const badge = document.getElementById('statusBadge');
  if (badge) {
    if (score >= 80) {
      badge.textContent = 'CRITICAL';
      badge.className = 'badge badge-danger';
    } else if (score >= 60) {
      badge.textContent = 'HIGH RISK';
      badge.className = 'badge badge-danger';
    } else {
      badge.textContent = 'WARNING';
      badge.className = 'badge badge-warning';
    }
  }
}

/**
 * Display safe status
 */
function displaySafeStatus() {
  // Update status icon
  const statusIcon = document.getElementById('statusIcon');
  if (statusIcon) {
    statusIcon.textContent = '✅';
  }
  
  // Update status text
  const statusText = document.getElementById('statusText');
  if (statusText) {
    statusText.textContent = 'This page is safe';
    statusText.style.color = '#16a34a';
  }
  
  // Update status subtext
  const statusSubtext = document.getElementById('statusSubtext');
  if (statusSubtext) {
    statusSubtext.textContent = 'No threats detected on this page';
  }
  
  // Update threat score
  const scoreValue = document.getElementById('scoreValue');
  const scoreDisplay = document.getElementById('scoreDisplay');
  
  if (scoreValue && scoreDisplay) {
    scoreValue.textContent = '0/100';
    scoreValue.className = 'score-value safe';
    scoreDisplay.className = 'threat-score-display safe';
  }
  
  // Update badge
  const badge = document.getElementById('statusBadge');
  if (badge) {
    badge.textContent = 'SAFE';
    badge.className = 'badge badge-safe';
  }
}

/**
 * Load statistics from storage
 */
async function loadStatistics() {
  try {
    const result = await chrome.storage.local.get(['threatsBlocked', 'totalScans']);
    
    // Update threats blocked
    const threatsBlockedElement = document.getElementById('threatsBlocked');
    if (threatsBlockedElement) {
      threatsBlockedElement.textContent = formatNumber(result.threatsBlocked || 0);
    }
    
    // Update total scans
    const totalScansElement = document.getElementById('totalScans');
    if (totalScansElement) {
      totalScansElement.textContent = formatNumber(result.totalScans || 0);
    }
    
  } catch (error) {
    console.error('Error loading statistics:', error);
  }
}

/**
 * Format number with commas
 */
function formatNumber(num) {
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
  // Settings button
  const settingsBtn = document.getElementById('settingsBtn');
  if (settingsBtn) {
    settingsBtn.addEventListener('click', () => {
      console.log('Settings clicked');
      // TODO: Open settings page
      alert('Settings feature coming soon!');
    });
  }
  
  // Dashboard button
  const dashboardBtn = document.getElementById('dashboardBtn');
  if (dashboardBtn) {
    dashboardBtn.addEventListener('click', () => {
      console.log('Dashboard clicked');
      // Open dashboard in new tab
      chrome.tabs.create({ url: 'http://localhost:5173' });
    });
  }
  
  // History button
  const historyBtn = document.getElementById('historyBtn');
  if (historyBtn) {
    historyBtn.addEventListener('click', async () => {
      console.log('History clicked');
      
      // Get threat history
      const result = await chrome.storage.local.get('threatHistory');
      const history = result.threatHistory || [];
      
      if (history.length === 0) {
        alert('No threat history yet. Keep browsing safely!');
      } else {
        // Show history summary
        const recent = history.slice(0, 5);
        const historyText = recent.map((event, i) => {
          const date = new Date(event.timestamp).toLocaleString();
          return `${i + 1}. ${event.url}\n   Score: ${event.score} | ${event.blocked ? 'BLOCKED' : 'Allowed'}\n   ${date}`;
        }).join('\n\n');
        
        alert(`Recent Threat History:\n\n${historyText}\n\n(Showing ${recent.length} of ${history.length} total)`);
      }
    });
  }
  
  // Whitelist button
  const whitelistBtn = document.getElementById('whitelistBtn');
  if (whitelistBtn) {
    whitelistBtn.addEventListener('click', async () => {
      console.log('Whitelist clicked');
      
      // Get whitelist
      const result = await chrome.storage.local.get('whitelist');
      const whitelist = result.whitelist || [];
      
      if (whitelist.length === 0) {
        alert('Whitelist is empty.\n\nYou can add trusted sites to the whitelist when PhishGuard flags them.');
      } else {
        const whitelistText = whitelist.map((domain, i) => `${i + 1}. ${domain}`).join('\n');
        alert(`Whitelisted Domains:\n\n${whitelistText}\n\n(${whitelist.length} total)`);
      }
    });
  }
}

/**
 * Show error message
 */
function showError(message) {
  const loading = document.getElementById('loading');
  if (loading) {
    loading.innerHTML = `
      <div style="color: #dc2626; padding: 20px;">
        <div style="font-size: 48px; margin-bottom: 16px;">⚠️</div>
        <div style="font-size: 14px; font-weight: 600;">${message}</div>
      </div>
    `;
  }
}

// Refresh status every 5 seconds while popup is open
setInterval(() => {
  if (document.hasFocus()) {
    loadPageStatus();
    loadStatistics();
  }
}, 5000);

console.log('PhishGuard AI popup script loaded');
