// PhishGuard AI - Background Service Worker
// Monitors navigation, coordinates threat analysis, manages extension state

const API_ENDPOINT = 'http://localhost:8000/api/v1/analyze/url';
const THREAT_THRESHOLD = 60; // Score above which we show warnings
const ANALYSIS_TIMEOUT = 5000; // 5 second timeout for API calls
const USE_MOCK_API = false; // Connected to backend

// In-memory cache for analyzed URLs (to prevent duplicate analysis)
const urlCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Track current threat status per tab
const tabThreatStatus = new Map();

/**
 * Check if URL should be skipped from analysis
 */
function shouldSkipURL(url) {
  if (!url) return true;
  
  // Skip Chrome internal pages
  if (url.startsWith('chrome://')) return true;
  if (url.startsWith('chrome-extension://')) return true;
  if (url.startsWith('about:')) return true;
  if (url.startsWith('edge://')) return true;
  if (url.startsWith('devtools://')) return true;
  
  // Skip local files (optional - remove if you want to analyze local files)
  if (url.startsWith('file://')) return true;
  
  // Skip data URLs
  if (url.startsWith('data:')) return true;
  if (url.startsWith('blob:')) return true;
  
  // Skip extension install pages
  if (url.includes('chrome.google.com/webstore')) return true;
  
  // Skip localhost and local development servers
  if (url.includes('localhost') || url.includes('127.0.0.1') || url.includes('0.0.0.0')) return true;
  
  return false;
}

/**
 * Check if backend is available
 */
async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000); // 2 second timeout
    
    const response = await fetch('http://localhost:8000/health', {
      method: 'GET',
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    return response.ok;
  } catch (error) {
    if (error.name === 'AbortError') {
      console.warn('Backend health check timed out');
    } else {
      console.warn('Backend health check failed:', error.message);
    }
    return false;
  }
}

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
  console.log('%c🛡️ PhishGuard AI installed', 'color: #00ff00; font-weight: bold; font-size: 14px');
  
  // Initialize storage with default values
  chrome.storage.local.set({
    threatsBlocked: 0,
    totalScans: 0,
    threatHistory: [],
    whitelist: [],
    settings: {
      enabled: true,
      blockThreshold: 60,
      showNotifications: true
    }
  });
  
  // Check backend connectivity if not using mock API
  if (!USE_MOCK_API) {
    console.log('%c🔌 Checking backend connection...', 'color: #ffaa00; font-weight: bold');
    const isBackendAvailable = await checkBackendHealth();
    if (isBackendAvailable) {
      console.log('%c✅ Backend is CONNECTED and ready at http://localhost:8000', 'color: #00ff00; font-weight: bold; font-size: 14px');
      console.log('%c✅ Using REAL ML models + Threat Intelligence', 'color: #00ff00; font-weight: bold');
    } else {
      console.warn('%c⚠️ Backend is NOT AVAILABLE - extension will use offline heuristics', 'color: #ff6600; font-weight: bold; font-size: 14px');
      console.warn('%c   Make sure the backend is running: cd backend && python main.py', 'color: #ff6600');
      console.warn('%c   Current mode: FALLBACK to hardcoded rules (~60% accuracy)', 'color: #ff6600; font-weight: bold');
    }
  } else {
    console.log('%c🔧 Using MOCK API mode (hardcoded rules for testing)', 'color: #ffaa00; font-weight: bold');
  }
});

// Monitor navigation events
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // Only analyze main frame navigations (not iframes)
  if (details.frameId !== 0) return;
  
  // Skip internal Chrome pages and extension pages
  if (shouldSkipURL(details.url)) {
    return;
  }
  
  console.log('Navigation detected:', details.url);
  
  // Analyze the URL
  await analyzeURL(details.tabId, details.url);
});

// Monitor tab updates (for URL changes without full navigation)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url && !shouldSkipURL(changeInfo.url)) {
    console.log('Tab URL changed:', changeInfo.url);
    await analyzeURL(tabId, changeInfo.url);
  }
});

/**
 * Main URL analysis function
 * Coordinates threat detection and warning display
 */
async function analyzeURL(tabId, url) {
  try {
    // Check if URL is whitelisted
    const { whitelist = [] } = await chrome.storage.local.get('whitelist');
    const urlObj = new URL(url);
    
    if (whitelist.includes(urlObj.hostname)) {
      console.log('URL whitelisted:', url);
      updateTabStatus(tabId, { safe: true, whitelisted: true, score: 0 });
      return;
    }
    
    // Check cache first
    const cached = getCachedResult(url);
    if (cached) {
      console.log('Using cached result for:', url);
      await handleThreatResponse(tabId, url, cached);
      return;
    }
    
    // Update stats
    await incrementStats('totalScans');
    
    // Call backend API for analysis (if not using mock)
    if (!USE_MOCK_API) {
      console.log('%c🚀 Analyzing URL with BACKEND ML API:', 'color: #00aaff; font-weight: bold', url);
      try {
        const threatData = await callBackendAPI(url);
        
        console.log('%c✅ BACKEND RESPONSE RECEIVED (using ML models + Threat Intel):', 'color: #00ff00; font-weight: bold');
        console.log('%c   Threat Score: ' + threatData.threat_score, 'color: #00ff00; font-weight: bold');
        console.log('%c   Risk Level: ' + threatData.risk_level, 'color: #00ff00; font-weight: bold');
        console.log('%c   Full Analysis:', 'color: #00ff00', threatData);
        
        // Cache the result
        cacheResult(url, threatData);
        
        // Handle the response
        await handleThreatResponse(tabId, url, threatData);
        return;
      } catch (apiError) {
        console.error('%c❌ Backend API error:', 'color: #ff0000; font-weight: bold', apiError);
        console.error('%c⚠️ FALLING BACK to offline heuristics (hardcoded rules)', 'color: #ff6600; font-weight: bold; font-size: 13px');
        // Fall through to heuristic fallback
      }
    } else {
      // Use mock API
      console.log('%c🔧 Using MOCK API (hardcoded rules)', 'color: #ffaa00; font-weight: bold');
      const threatData = await callBackendAPI(url);
      cacheResult(url, threatData);
      await handleThreatResponse(tabId, url, threatData);
      return;
    }
    
  } catch (error) {
    console.error('Error analyzing URL:', error);
  }
  
  // Fall back to basic heuristics if API fails
  console.log('%c⚠️ Falling back to offline heuristics (HARDCODED RULES)', 'color: #ff6600; font-weight: bold; font-size: 13px');
  console.log('%c   This mode has ~60% accuracy. For best results, ensure backend is running.', 'color: #ff6600');
  const heuristicScore = performBasicHeuristics(url);
  await handleThreatResponse(tabId, url, {
    threat_score: heuristicScore,
    risk_level: heuristicScore > THREAT_THRESHOLD ? 'high' : heuristicScore > 40 ? 'medium' : 'safe',
    reasons: ['Backend unavailable - using offline analysis'],
    confidence: 0.6
  });
}

/**
 * Mock API for testing (simulates backend responses)
 */
function mockAPIAnalysis(url) {
  // Test URLs for different threat levels
  const phishingKeywords = ['verify', 'login', 'secure', 'account', 'update', 'confirm', 'paypal', 'bank'];
  const urlLower = url.toLowerCase();
  
  let score = 0;
  let reasons = [];
  
  // Check for phishing indicators
  if (phishingKeywords.some(k => urlLower.includes(k))) {
    score += 30;
    reasons.push('URL contains suspicious keywords');
  }
  
  // Check for IP address
  if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
    score += 40;
    reasons.push('Domain is an IP address instead of proper domain name');
  }
  
  // Check URL length
  if (url.length > 75) {
    score += 15;
    reasons.push('Unusually long URL detected');
  }
  
  // Check for suspicious TLDs
  if (/\.(tk|ml|ga|cf|gq|xyz|top)/.test(urlLower)) {
    score += 25;
    reasons.push('Suspicious top-level domain detected');
  }
  
  // Check for @ symbol
  if (url.includes('@')) {
    score += 30;
    reasons.push('URL contains @ symbol (common phishing technique)');
  }
  
  // Simulate known phishing sites
  if (urlLower.includes('paypa1') || urlLower.includes('g00gle') || urlLower.includes('micros0ft')) {
    score = 95;
    reasons = ['Lookalike domain detected (homoglyph attack)', 'Flagged by threat intelligence'];
  }
  
  if (reasons.length === 0) {
    reasons.push('No suspicious indicators detected');
  }
  
  return {
    threat_score: Math.min(score, 100),
    risk_level: score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low',
    reasons: reasons,
    confidence: score > 0 ? 0.85 : 0.95
  };
}

/**
 * Transform backend response to match extension format
 */
function transformBackendResponse(backendResponse) {
  // Extract reasons from analysis.reasons array
  const reasons = backendResponse.analysis?.reasons || [];
  const reasonsList = reasons.map(reason => {
    // Convert reason object to readable string
    if (typeof reason === 'string') {
      return reason;
    }
    // Format: "Factor description (Source: severity)"
    if (reason && typeof reason === 'object') {
      return `${reason.factor || 'Threat detected'} (${reason.source || 'analysis'})`;
    }
    return String(reason);
  });
  
  // If no reasons, provide a default based on score
  if (reasonsList.length === 0) {
    if (backendResponse.threat_score >= 80) {
      reasonsList.push('High threat score detected');
    } else if (backendResponse.threat_score >= 60) {
      reasonsList.push('Suspicious indicators detected');
    } else {
      reasonsList.push('No significant threats detected');
    }
  }
  
  return {
    threat_score: backendResponse.threat_score,
    risk_level: backendResponse.risk_level || 'safe',
    reasons: reasonsList,
    confidence: backendResponse.confidence || 0.8,
    is_phishing: backendResponse.is_phishing || false,
    recommendation: backendResponse.recommendation || 'allow',
    analysis: backendResponse.analysis // Keep full analysis for debugging
  };
}

/**
 * Call backend API for URL analysis
 */
async function callBackendAPI(url) {
  // Use mock API for testing if enabled
  if (USE_MOCK_API) {
    console.log('🔧 Using MOCK API for testing');
    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 200));
    return mockAPIAnalysis(url);
  }
  
  // Validate URL format
  if (!url || typeof url !== 'string') {
    throw new Error('Invalid URL provided');
  }
  
  // Ensure URL has protocol
  let normalizedUrl = url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    normalizedUrl = 'https://' + url;
    console.warn('⚠️ URL missing protocol, assuming https:', normalizedUrl);
  }
  
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), ANALYSIS_TIMEOUT);
  
  try {
    console.log('🔗 Calling backend API:', API_ENDPOINT);
    console.log('📤 Request payload:', { url: normalizedUrl });
    
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: normalizedUrl
      }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`API error ${response.status}:`, errorText);
      throw new Error(`API returned ${response.status}: ${errorText}`);
    }
    
    const data = await response.json();
    console.log('✅ Backend API response received:', data);
    
    // Validate response
    if (!data || typeof data !== 'object') {
      throw new Error('Invalid response format: expected JSON object');
    }
    
    // Transform backend response to match extension format
    const transformed = transformBackendResponse(data);
    console.log('✅ Transformed response:', transformed);
    return transformed;
    
  } catch (error) {
    clearTimeout(timeoutId);
    
    if (error.name === 'AbortError') {
      console.error('⏱️ API request timed out after', ANALYSIS_TIMEOUT, 'ms');
      throw new Error('Request timeout - backend may be slow or unavailable');
    }
    
    if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError') || error.message.includes('ERR_CONNECTION_REFUSED')) {
      console.error('🌐 Network error - backend may be offline');
      console.error('   Make sure the backend is running: cd backend && python main.py');
      throw new Error('Cannot connect to backend - is the server running on port 8000?');
    }
    
    if (error.message.includes('CORS')) {
      console.error('🚫 CORS error - check backend CORS configuration');
      throw new Error('CORS error - backend may not allow extension requests');
    }
    
    console.error('❌ API call failed:', error);
    throw error;
  }
}

/**
 * Handle threat analysis response
 */
async function handleThreatResponse(tabId, url, threatData) {
  const { threat_score, risk_level, reasons = [], confidence = 1.0 } = threatData;
  
  console.log(`🎯 Threat analysis complete: ${url} - Score: ${threat_score}`);
  console.log('🎯 Full threat data:', JSON.stringify(threatData, null, 2));
  
  // Update tab status
  const status = {
    safe: threat_score < THREAT_THRESHOLD,
    score: threat_score,
    riskLevel: risk_level,
    reasons: reasons,
    confidence: confidence,
    url: url,
    timestamp: Date.now()
  };
  
  console.log('🎯 Setting tab status:', JSON.stringify(status, null, 2));
  updateTabStatus(tabId, status);
  
  // If high threat, redirect to warning page
  if (threat_score >= THREAT_THRESHOLD) {
    await handleHighThreat(tabId, url, threatData);
  } else {
    // Notify content script to enable monitoring
    try {
      await chrome.tabs.sendMessage(tabId, {
        action: 'updateStatus',
        status: status
      });
    } catch (error) {
      console.log('Could not send message to content script:', error.message);
    }
  }
  
  // Log to history
  await logThreatEvent(url, threatData);
}

/**
 * Handle high threat scenarios
 */
async function handleHighThreat(tabId, originalUrl, threatData) {
  console.log('HIGH THREAT DETECTED:', originalUrl);
  
  // Increment blocked counter
  await incrementStats('threatsBlocked');
  
  // Create warning page URL with threat data
  const warningUrl = chrome.runtime.getURL('warning.html');
  const params = new URLSearchParams({
    url: originalUrl,
    score: threatData.threat_score,
    risk: threatData.risk_level,
    reasons: JSON.stringify(threatData.reasons),
    confidence: threatData.confidence
  });
  
  // Redirect to warning page
  try {
    await chrome.tabs.update(tabId, {
      url: `${warningUrl}?${params.toString()}`
    });
  } catch (error) {
    console.error('Failed to redirect to warning page:', error);
  }
}

/**
 * Basic heuristic analysis for offline mode
 */
function performBasicHeuristics(url) {
  let score = 0;
  
  try {
    const urlObj = new URL(url);
    
    // Check URL length
    if (url.length > 75) score += 10;
    if (url.length > 100) score += 10;
    
    // Check for IP address in domain
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(urlObj.hostname)) {
      score += 30;
    }
    
    // Check for suspicious keywords
    const suspiciousKeywords = ['verify', 'account', 'update', 'confirm', 'login', 'secure', 'bank'];
    const urlLower = url.toLowerCase();
    suspiciousKeywords.forEach(keyword => {
      if (urlLower.includes(keyword)) score += 5;
    });
    
    // Check for excessive subdomains
    const subdomains = urlObj.hostname.split('.');
    if (subdomains.length > 3) score += 15;
    
    // Check for suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz'];
    if (suspiciousTLDs.some(tld => urlObj.hostname.endsWith(tld))) {
      score += 20;
    }
    
    // Check for @ symbol (can be used for phishing)
    if (url.includes('@')) score += 25;
    
    // Check for excessive dashes or numbers in domain
    const domainDashes = (urlObj.hostname.match(/-/g) || []).length;
    if (domainDashes > 3) score += 10;
    
  } catch (error) {
    console.error('Error in heuristic analysis:', error);
    return 0;
  }
  
  return Math.min(score, 100);
}

/**
 * Cache management
 */
function getCachedResult(url) {
  const cached = urlCache.get(url);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  return null;
}

function cacheResult(url, data) {
  urlCache.set(url, {
    data: data,
    timestamp: Date.now()
  });
  
  // Clean old cache entries
  if (urlCache.size > 1000) {
    const entries = Array.from(urlCache.entries());
    entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
    const toRemove = entries.slice(0, 500);
    toRemove.forEach(([key]) => urlCache.delete(key));
  }
}

/**
 * Tab status management
 */
function updateTabStatus(tabId, status) {
  console.log(`💾 Updating status for tab ${tabId}:`, JSON.stringify(status, null, 2));
  tabThreatStatus.set(tabId, status);
  console.log(`💾 Status updated. Map now has ${tabThreatStatus.size} entries`);
}

function getTabStatus(tabId) {
  const status = tabThreatStatus.get(tabId) || { safe: true, score: 0 };
  console.log(`🔍 Getting status for tab ${tabId}:`, JSON.stringify(status, null, 2));
  return status;
}

// Clean up closed tabs
chrome.tabs.onRemoved.addListener((tabId) => {
  tabThreatStatus.delete(tabId);
});

/**
 * Storage utilities
 */
async function incrementStats(key) {
  const result = await chrome.storage.local.get(key);
  const newValue = (result[key] || 0) + 1;
  await chrome.storage.local.set({ [key]: newValue });
}

async function logThreatEvent(url, threatData) {
  try {
    const { threatHistory = [] } = await chrome.storage.local.get('threatHistory');
    
    const event = {
      url: url,
      score: threatData.threat_score,
      risk: threatData.risk_level,
      reasons: threatData.reasons,
      timestamp: Date.now(),
      blocked: threatData.threat_score >= THREAT_THRESHOLD
    };
    
    // Keep only last 100 events to avoid quota issues
    threatHistory.unshift(event);
    if (threatHistory.length > 100) {
      threatHistory.splice(100); // Remove all items after index 100
    }
    
    await chrome.storage.local.set({ threatHistory });
  } catch (error) {
    console.error('Error logging threat event:', error);
    // If quota exceeded, clear old history
    if (error.message.includes('quota')) {
      console.log('Storage quota exceeded, clearing old history...');
      await chrome.storage.local.set({ threatHistory: [] });
    }
  }
}

/**
 * Message handling from popup and content scripts
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getStatus') {
    // Popup requesting current tab status
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        const status = getTabStatus(tabs[0].id);
        sendResponse(status);
      }
    });
    return true; // Async response
  }
  
  if (request.action === 'updateThreatScore') {
    // Content script reports enhanced threat score from form analysis
    const tabId = sender.tab?.id;
    if (tabId) {
      const currentStatus = getTabStatus(tabId);
      const updatedStatus = {
        ...currentStatus,
        score: request.enhancedScore,
        originalScore: currentStatus.score,
        formSuspicionScore: request.formSuspicionScore,
        formAnalysis: request.formAnalysis,
        enhancedByFormAnalysis: true
      };
      
      // Add form analysis reasons to threat reasons
      if (request.formAnalysis?.flags) {
        const formReasons = request.formAnalysis.flags.map(flag => 
          `Form Analysis: ${flag.message}`
        );
        updatedStatus.reasons = [...(currentStatus.reasons || []), ...formReasons];
      }
      
      updateTabStatus(tabId, updatedStatus);
      
      console.log('%c📊 Threat Score Enhanced by Form Analysis:', 'color: #ea580c; font-weight: bold');
      console.log(`   Tab ${tabId}: ${currentStatus.score} → ${request.enhancedScore}`);
      console.log(`   Form Suspicion: +${request.formSuspicionScore}`);
      
      sendResponse({ success: true, updatedScore: request.enhancedScore });
    }
    return true;
  }
  
  if (request.action === 'whitelistDomain') {
    // Add domain to whitelist
    chrome.storage.local.get('whitelist', (result) => {
      const whitelist = result.whitelist || [];
      if (!whitelist.includes(request.domain)) {
        whitelist.push(request.domain);
        chrome.storage.local.set({ whitelist }, () => {
          sendResponse({ success: true });
        });
      } else {
        sendResponse({ success: true, alreadyWhitelisted: true });
      }
    });
    return true; // Async response
  }
  
  if (request.action === 'removeFromWhitelist') {
    // Remove domain from whitelist
    chrome.storage.local.get('whitelist', (result) => {
      const whitelist = result.whitelist || [];
      const index = whitelist.indexOf(request.domain);
      if (index > -1) {
        whitelist.splice(index, 1);
        chrome.storage.local.set({ whitelist }, () => {
          sendResponse({ success: true, removed: true });
        });
      } else {
        sendResponse({ success: false, notFound: true });
      }
    });
    return true; // Async response
  }
  
  if (request.action === 'getWhitelist') {
    // Get all whitelisted domains
    chrome.storage.local.get('whitelist', (result) => {
      sendResponse({ whitelist: result.whitelist || [] });
    });
    return true; // Async response
  }
  
  if (request.action === 'clearWhitelist') {
    // Clear all whitelisted domains
    chrome.storage.local.set({ whitelist: [] }, () => {
      sendResponse({ success: true });
    });
    return true; // Async response
  }
  
  if (request.action === 'proceedAnyway') {
    // User chose to proceed despite warning
    const url = request.url;
    console.log('User proceeding to flagged site:', url);
    
    // Log the override decision
    logThreatEvent(url, {
      threat_score: request.score,
      risk_level: 'user_override',
      reasons: ['User chose to proceed'],
    });
    
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'credentialDetected') {
    // Content script detected credential form on risky page
    console.log('Credential form detected on risky page');
    const tabId = sender.tab.id;
    
    // Send blocking command
    chrome.tabs.sendMessage(tabId, {
      action: 'blockCredentials',
      message: 'Credential submission blocked for your safety'
    });
  }
});

console.log('PhishGuard AI background service worker loaded');
