// PhishGuard AI - Popup Script with Dynamic Effects
// Displays current page status and extension statistics with smooth animations

let currentTab = null;
let particleInterval = null;

/**
 * Initialize popup with dynamic effects
 */
document.addEventListener('DOMContentLoaded', async () => {
  console.log('PhishGuard AI popup opened');
  
  try {
    // Create animated particles
    createParticles();
    
    // Get current tab
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tabs[0];
    
    if (!currentTab) {
      showError('Could not get current tab');
      return;
    }
    
    // Load data with animations
    await Promise.all([
      loadPageStatus(),
      loadStatistics()
    ]);
    
    // Setup event listeners with ripple effects
    setupEventListeners();
    
    // Hide loading, show content with animation
    setTimeout(() => {
      document.getElementById('loading').classList.add('hidden');
      document.getElementById('mainContent').classList.remove('hidden');
    }, 500);
    
  } catch (error) {
    console.error('Error initializing popup:', error);
    showError('Failed to load PhishGuard AI');
  }
});

/**
 * Create animated particle effects
 */
function createParticles() {
  const particlesContainer = document.getElementById('particles');
  if (!particlesContainer) return;
  
  // Create 15 particles
  for (let i = 0; i < 15; i++) {
    const particle = document.createElement('div');
    particle.className = 'particle';
    particle.style.left = Math.random() * 100 + '%';
    particle.style.animationDelay = Math.random() * 15 + 's';
    particle.style.animationDuration = (10 + Math.random() * 10) + 's';
    particlesContainer.appendChild(particle);
  }
}

/**
 * Animate number counting
 */
function animateNumber(element, targetValue, duration = 1000) {
  if (!element) return;
  
  const startValue = parseInt(element.textContent.replace(/,/g, '')) || 0;
  const increment = targetValue > startValue ? 1 : -1;
  const steps = Math.abs(targetValue - startValue);
  const stepDuration = duration / steps;
  
  element.classList.add('counting');
  
  let currentValue = startValue;
  const timer = setInterval(() => {
    currentValue += increment;
    
    if ((increment > 0 && currentValue >= targetValue) || 
        (increment < 0 && currentValue <= targetValue)) {
      currentValue = targetValue;
      clearInterval(timer);
      element.classList.remove('counting');
    }
    
    element.textContent = formatNumber(currentValue);
  }, stepDuration);
}

/**
 * Add ripple effect on click
 */
function addRippleEffect(element, event) {
  const ripple = document.createElement('div');
  ripple.className = 'ripple';
  
  const rect = element.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);
  const x = event.clientX - rect.left - size / 2;
  const y = event.clientY - rect.top - size / 2;
  
  ripple.style.width = ripple.style.height = size + 'px';
  ripple.style.left = x + 'px';
  ripple.style.top = y + 'px';
  
  element.style.position = 'relative';
  element.appendChild(ripple);
  
  setTimeout(() => {
    ripple.remove();
  }, 600);
}

/**
 * Smooth state transition
 */
function transitionState(element, newClass, oldClass) {
  if (!element) return;
  
  element.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
  element.classList.remove(oldClass);
  element.classList.add(newClass);
  
  // Trigger reflow for animation
  element.offsetHeight;
}

/**
 * Load current page status with animations
 */
async function loadPageStatus() {
  try {
    // Display current URL with fade-in
    const urlElement = document.getElementById('currentUrl');
    if (urlElement && currentTab.url) {
      const displayUrl = currentTab.url.length > 60 
        ? currentTab.url.substring(0, 57) + '...'
        : currentTab.url;
      
      urlElement.style.opacity = '0';
      urlElement.textContent = displayUrl;
      
      setTimeout(() => {
        urlElement.style.transition = 'opacity 0.5s ease';
        urlElement.style.opacity = '1';
      }, 100);
    }
    
    // Get status from background script
    chrome.runtime.sendMessage({ action: 'getStatus' }, (status) => {
      if (chrome.runtime.lastError) {
        console.error('Error getting status:', chrome.runtime.lastError);
        displaySafeStatus();
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
 * Display threat status with animations
 */
function displayThreatStatus(status) {
  const { score, riskLevel, reasons = [] } = status;
  
  // Animate status icon change
  const statusIcon = document.getElementById('statusIcon');
  if (statusIcon) {
    statusIcon.style.transform = 'scale(0) rotate(180deg)';
    setTimeout(() => {
      statusIcon.textContent = score >= 80 ? '🚨' : '⚠️';
      statusIcon.style.transition = 'transform 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
      statusIcon.style.transform = 'scale(1) rotate(0deg)';
    }, 250);
  }
  
  // Update status text with fade
  const statusText = document.getElementById('statusText');
  if (statusText) {
    statusText.style.opacity = '0';
    statusText.textContent = 'Threat Detected!';
    statusText.style.color = '#dc2626';
    setTimeout(() => {
      statusText.style.transition = 'opacity 0.4s ease';
      statusText.style.opacity = '1';
    }, 100);
  }
  
  // Update status subtext
  const statusSubtext = document.getElementById('statusSubtext');
  if (statusSubtext) {
    statusSubtext.style.opacity = '0';
    const mainReason = reasons[0] || 'Suspicious activity detected';
    statusSubtext.textContent = mainReason;
    setTimeout(() => {
      statusSubtext.style.transition = 'opacity 0.4s ease';
      statusSubtext.style.opacity = '1';
    }, 200);
  }
  
  // Animate threat score
  const scoreValue = document.getElementById('scoreValue');
  const scoreDisplay = document.getElementById('scoreDisplay');
  
  if (scoreValue && scoreDisplay) {
    // Animate score counting
    scoreValue.classList.add('counting');
    let currentScore = 0;
    const targetScore = score;
    const duration = 1500;
    const steps = targetScore;
    const stepDuration = duration / steps;
    
    const scoreTimer = setInterval(() => {
      currentScore++;
      if (currentScore >= targetScore) {
        currentScore = targetScore;
        clearInterval(scoreTimer);
        scoreValue.classList.remove('counting');
      }
      scoreValue.textContent = `${currentScore}/100`;
    }, stepDuration);
    
    // Transition display style
    transitionState(scoreDisplay, 'threat-score-display', 'safe');
    transitionState(scoreValue, 'danger', 'safe');
  }
  
  // Animate badge change
  const badge = document.getElementById('statusBadge');
  if (badge) {
    badge.style.transform = 'scale(0) rotate(180deg)';
    setTimeout(() => {
      if (score >= 80) {
        badge.textContent = 'CRITICAL';
        transitionState(badge, 'badge-danger', 'badge-safe');
      } else if (score >= 60) {
        badge.textContent = 'HIGH RISK';
        transitionState(badge, 'badge-danger', 'badge-safe');
      } else {
        badge.textContent = 'WARNING';
        transitionState(badge, 'badge-warning', 'badge-safe');
      }
      badge.style.transition = 'transform 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
      badge.style.transform = 'scale(1) rotate(0deg)';
    }, 250);
  }
}

/**
 * Display safe status with animations
 */
function displaySafeStatus() {
  // Update status icon
  const statusIcon = document.getElementById('statusIcon');
  if (statusIcon) {
    statusIcon.style.transform = 'scale(0)';
    setTimeout(() => {
      statusIcon.textContent = '✅';
      statusIcon.style.transition = 'transform 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
      statusIcon.style.transform = 'scale(1)';
    }, 200);
  }
  
  // Update status text
  const statusText = document.getElementById('statusText');
  if (statusText) {
    statusText.style.opacity = '0';
    statusText.textContent = 'This page is safe';
    statusText.style.color = '#16a34a';
    setTimeout(() => {
      statusText.style.transition = 'opacity 0.4s ease';
      statusText.style.opacity = '1';
    }, 100);
  }
  
  // Update status subtext
  const statusSubtext = document.getElementById('statusSubtext');
  if (statusSubtext) {
    statusSubtext.style.opacity = '0';
    statusSubtext.textContent = 'No threats detected on this page';
    setTimeout(() => {
      statusSubtext.style.transition = 'opacity 0.4s ease';
      statusSubtext.style.opacity = '1';
    }, 200);
  }
  
  // Update threat score
  const scoreValue = document.getElementById('scoreValue');
  const scoreDisplay = document.getElementById('scoreDisplay');
  
  if (scoreValue && scoreDisplay) {
    animateNumber(scoreValue, 0, 800);
    scoreValue.textContent = '0/100';
    transitionState(scoreValue, 'safe', 'danger');
    transitionState(scoreDisplay, 'safe', 'threat-score-display');
  }
  
  // Update badge
  const badge = document.getElementById('statusBadge');
  if (badge) {
    badge.style.transform = 'scale(0)';
    setTimeout(() => {
      badge.textContent = 'SAFE';
      transitionState(badge, 'badge-safe', 'badge-danger');
      badge.style.transition = 'transform 0.5s cubic-bezier(0.4, 0, 0.2, 1)';
      badge.style.transform = 'scale(1)';
    }, 200);
  }
}

/**
 * Load statistics with animated counting
 */
async function loadStatistics() {
  try {
    const result = await chrome.storage.local.get(['threatsBlocked', 'totalScans']);
    
    // Animate threats blocked
    const threatsBlockedElement = document.getElementById('threatsBlocked');
    if (threatsBlockedElement) {
      const targetValue = result.threatsBlocked || 0;
      animateNumber(threatsBlockedElement, targetValue, 1200);
    }
    
    // Animate total scans
    const totalScansElement = document.getElementById('totalScans');
    if (totalScansElement) {
      const targetValue = result.totalScans || 0;
      animateNumber(totalScansElement, targetValue, 1200);
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
 * Setup event listeners with ripple effects
 */
function setupEventListeners() {
  // Settings button
  const settingsBtn = document.getElementById('settingsBtn');
  if (settingsBtn) {
    settingsBtn.addEventListener('click', (e) => {
      addRippleEffect(settingsBtn, e);
      console.log('Settings clicked');
      setTimeout(() => {
        alert('Settings feature coming soon!');
      }, 300);
    });
  }
  
  // Dashboard button
  const dashboardBtn = document.getElementById('dashboardBtn');
  if (dashboardBtn) {
    dashboardBtn.addEventListener('click', (e) => {
      addRippleEffect(dashboardBtn, e);
      console.log('Dashboard clicked');
      setTimeout(() => {
        chrome.tabs.create({ url: 'http://localhost:5173' });
      }, 300);
    });
  }
  
  // History button
  const historyBtn = document.getElementById('historyBtn');
  if (historyBtn) {
    historyBtn.addEventListener('click', async (e) => {
      addRippleEffect(historyBtn, e);
      console.log('History clicked');
      
      setTimeout(async () => {
        const result = await chrome.storage.local.get('threatHistory');
        const history = result.threatHistory || [];
        
        if (history.length === 0) {
          alert('No threat history yet. Keep browsing safely!');
        } else {
          const recent = history.slice(0, 5);
          const historyText = recent.map((event, i) => {
            const date = new Date(event.timestamp).toLocaleString();
            return `${i + 1}. ${event.url}\n   Score: ${event.score} | ${event.blocked ? 'BLOCKED' : 'Allowed'}\n   ${date}`;
          }).join('\n\n');
          
          alert(`Recent Threat History:\n\n${historyText}\n\n(Showing ${recent.length} of ${history.length} total)`);
        }
      }, 300);
    });
  }
  
  // Whitelist button
  const whitelistBtn = document.getElementById('whitelistBtn');
  if (whitelistBtn) {
    whitelistBtn.addEventListener('click', async (e) => {
      addRippleEffect(whitelistBtn, e);
      console.log('Whitelist clicked');
      
      setTimeout(async () => {
        const result = await chrome.storage.local.get('whitelist');
        const whitelist = result.whitelist || [];
        
        if (whitelist.length === 0) {
          alert('Whitelist is empty.\n\nYou can add trusted sites to the whitelist when PhishGuard flags them.');
        } else {
          const whitelistText = whitelist.map((domain, i) => `${i + 1}. ${domain}`).join('\n');
          alert(`Whitelisted Domains:\n\n${whitelistText}\n\n(${whitelist.length} total)`);
        }
      }, 300);
    });
  }
  
  // Add ripple to stat cards
  const statCards = document.querySelectorAll('.stat-card');
  statCards.forEach(card => {
    card.addEventListener('click', (e) => {
      addRippleEffect(card, e);
      // Add bounce effect
      card.style.transform = 'scale(0.95)';
      setTimeout(() => {
        card.style.transform = '';
      }, 150);
    });
  });
}

/**
 * Show error message
 */
function showError(message) {
  const loading = document.getElementById('loading');
  if (loading) {
    loading.innerHTML = `
      <div style="color: #dc2626; padding: 20px; animation: fadeIn 0.5s ease;">
        <div style="font-size: 48px; margin-bottom: 16px; animation: shake 0.5s ease;">⚠️</div>
        <div style="font-size: 14px; font-weight: 600;">${message}</div>
      </div>
    `;
  }
}

// Refresh status every 5 seconds with smooth updates
setInterval(() => {
  if (document.hasFocus()) {
    loadPageStatus();
    loadStatistics();
  }
}, 5000);

console.log('PhishGuard AI popup script loaded with dynamic effects');
