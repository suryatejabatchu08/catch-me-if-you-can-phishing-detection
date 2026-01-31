// PhishGuard AI - Content Script
// Monitors page for credential forms, injects warnings, blocks submissions

let currentPageStatus = { safe: true, score: 0 };
let credentialFormDetected = false;
let warningOverlayActive = false;

// Initialize
console.log('PhishGuard AI content script loaded on:', window.location.href);

/**
 * Listen for status updates from background script
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'updateStatus') {
    currentPageStatus = request.status;
    console.log('Page status updated:', currentPageStatus);
    
    // If risky, scan for credential forms
    if (!currentPageStatus.safe) {
      scanForCredentialForms();
    }
  }
  
  if (request.action === 'blockCredentials') {
    showCredentialBlockWarning(request.message);
  }
  
  sendResponse({ received: true });
});

/**
 * Analyze form behavior for suspicious patterns
 */
function analyzeFormBehavior(form) {
  const analysis = {
    suspiciousScore: 0,
    flags: [],
    details: {}
  };
  
  try {
    const currentDomain = window.location.hostname;
    const currentProtocol = window.location.protocol;
    
    // 1. Check form action URL
    if (form.action) {
      try {
        const actionUrl = new URL(form.action, window.location.href);
        const actionDomain = actionUrl.hostname;
        
        analysis.details.actionDomain = actionDomain;
        analysis.details.actionProtocol = actionUrl.protocol;
        
        // External domain submission
        if (actionDomain !== currentDomain) {
          analysis.suspiciousScore += 30;
          analysis.flags.push({
            type: 'external_submission',
            severity: 'high',
            message: `Form submits to external domain: ${actionDomain}`
          });
        }
        
        // HTTP submission (insecure)
        if (actionUrl.protocol === 'http:') {
          analysis.suspiciousScore += 25;
          analysis.flags.push({
            type: 'insecure_submission',
            severity: 'high',
            message: 'Form submits credentials over HTTP (unencrypted)'
          });
        }
        
        // HTTPS page with HTTP form submission (mixed content)
        if (currentProtocol === 'https:' && actionUrl.protocol === 'http:') {
          analysis.suspiciousScore += 35;
          analysis.flags.push({
            type: 'mixed_content',
            severity: 'critical',
            message: 'HTTPS page submitting to HTTP endpoint (security downgrade)'
          });
        }
        
      } catch (e) {
        console.warn('Could not parse form action URL:', e);
      }
    } else {
      // No action attribute - might use JavaScript
      analysis.details.noAction = true;
    }
    
    // 2. Check for suspicious hidden fields
    const hiddenFields = form.querySelectorAll('input[type="hidden"]');
    if (hiddenFields.length > 5) {
      analysis.suspiciousScore += 10;
      analysis.flags.push({
        type: 'excessive_hidden_fields',
        severity: 'medium',
        message: `Form contains ${hiddenFields.length} hidden fields`
      });
    }
    
    // Check for suspicious hidden field names
    hiddenFields.forEach(field => {
      const suspiciousNames = ['redirect', 'return', 'callback', 'continue', 'next', 'goto'];
      if (suspiciousNames.some(name => field.name.toLowerCase().includes(name))) {
        analysis.suspiciousScore += 5;
        analysis.flags.push({
          type: 'suspicious_redirect',
          severity: 'medium',
          message: `Suspicious hidden field: ${field.name}`
        });
      }
    });
    
    // 3. Check for JavaScript form handlers
    const hasOnSubmit = form.hasAttribute('onsubmit') || form.onsubmit;
    if (hasOnSubmit) {
      analysis.details.jsHandler = true;
      // JavaScript handlers can be legitimate (validation) but also used to hide malicious behavior
      const onsubmitCode = form.getAttribute('onsubmit') || '';
      
      // Check for suspicious patterns in handler
      if (onsubmitCode.includes('eval') || onsubmitCode.includes('document.write')) {
        analysis.suspiciousScore += 20;
        analysis.flags.push({
          type: 'suspicious_javascript',
          severity: 'high',
          message: 'Form uses suspicious JavaScript methods (eval/document.write)'
        });
      }
    }
    
    // 4. Check for forms without method or using GET for credentials
    const method = (form.method || 'get').toLowerCase();
    if (method === 'get' && form.querySelector('input[type="password"]')) {
      analysis.suspiciousScore += 40;
      analysis.flags.push({
        type: 'password_in_get',
        severity: 'critical',
        message: 'Password field submitted via GET method (visible in URL)'
      });
    }
    
    // 5. Check target attribute (opening in new window)
    if (form.target === '_blank') {
      analysis.suspiciousScore += 15;
      analysis.flags.push({
        type: 'new_window_submission',
        severity: 'medium',
        message: 'Form submits to new window/tab'
      });
    }
    
    // 6. Check autocomplete settings
    const autocomplete = form.getAttribute('autocomplete');
    if (autocomplete === 'off' && form.querySelector('input[type="password"]')) {
      // Legitimate sites often disable autocomplete for security
      // But phishing sites also do this
      analysis.details.autocompleteOff = true;
    }
    
  } catch (error) {
    console.error('Error analyzing form behavior:', error);
  }
  
  return analysis;
}

/**
 * Check for external scripts that might be malicious
 */
function detectExternalScripts() {
  const scripts = document.querySelectorAll('script[src]');
  const currentDomain = window.location.hostname;
  const externalScripts = [];
  
  scripts.forEach(script => {
    try {
      const scriptUrl = new URL(script.src, window.location.href);
      if (scriptUrl.hostname !== currentDomain) {
        externalScripts.push({
          src: script.src,
          domain: scriptUrl.hostname,
          async: script.async,
          defer: script.defer
        });
      }
    } catch (e) {
      // Invalid URL
    }
  });
  
  return externalScripts;
}

/**
 * Scan page for credential harvesting indicators
 */
function scanForCredentialForms() {
  // Look for password fields
  const passwordFields = document.querySelectorAll('input[type="password"]');
  
  // Look for forms with email/username fields
  const emailFields = document.querySelectorAll('input[type="email"], input[name*="email"], input[name*="user"]');
  
  // Look for login-related text
  const loginKeywords = ['sign in', 'log in', 'login', 'password', 'authenticate'];
  const pageText = document.body.innerText.toLowerCase();
  const hasLoginText = loginKeywords.some(keyword => pageText.includes(keyword));
  
  if (passwordFields.length > 0 || (emailFields.length > 0 && hasLoginText)) {
    credentialFormDetected = true;
    console.log('⚠️ Credential form detected on risky page!');
    
    // Analyze form behavior
    const forms = document.querySelectorAll('form');
    let totalFormSuspicionScore = 0;
    const formAnalysisResults = [];
    
    forms.forEach(form => {
      // Only analyze forms with password or email fields
      if (form.querySelector('input[type="password"]') || 
          form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]')) {
        
        const analysis = analyzeFormBehavior(form);
        formAnalysisResults.push(analysis);
        totalFormSuspicionScore += analysis.suspiciousScore;
        
        // Log findings
        if (analysis.flags.length > 0) {
          console.log('%c🔍 Form Behavior Analysis:', 'color: #f59e0b; font-weight: bold');
          analysis.flags.forEach(flag => {
            const color = flag.severity === 'critical' ? '#dc2626' : 
                         flag.severity === 'high' ? '#ea580c' : '#f59e0b';
            console.log(`%c  ⚠️ ${flag.type}: ${flag.message}`, `color: ${color}`);
          });
        }
      }
    });
    
    // Check for external scripts
    const externalScripts = detectExternalScripts();
    if (externalScripts.length > 0) {
      console.log('%c📜 External Scripts Detected:', 'color: #8b5cf6; font-weight: bold', externalScripts.length);
      externalScripts.slice(0, 5).forEach(script => {
        console.log(`  • ${script.domain}`);
      });
    }
    
    // Store analysis results for later use
    currentPageStatus.formAnalysis = {
      totalSuspicionScore: totalFormSuspicionScore,
      forms: formAnalysisResults,
      externalScripts: externalScripts.length,
      timestamp: Date.now()
    };
    
    // Enhance threat score based on form behavior
    const enhancedScore = Math.min(100, currentPageStatus.score + totalFormSuspicionScore);
    
    console.log('%c🎯 Enhanced Threat Score:', 'color: #dc2626; font-weight: bold; font-size: 14px');
    console.log(`   Original: ${currentPageStatus.score}/100`);
    console.log(`   Form Suspicion: +${totalFormSuspicionScore}`);
    console.log(`   Final: ${enhancedScore}/100`);
    
    // Update current page status with enhanced score
    currentPageStatus.score = enhancedScore;
    currentPageStatus.originalScore = currentPageStatus.score - totalFormSuspicionScore;
    
    // Show inline warning with enhanced details
    showInlineWarning(formAnalysisResults);
    
    // Block form submissions
    setupFormInterception();
    
    // Notify background script with enhanced score
    chrome.runtime.sendMessage({
      action: 'updateThreatScore',
      url: window.location.href,
      enhancedScore: enhancedScore,
      formSuspicionScore: totalFormSuspicionScore,
      formAnalysis: {
        suspicionScore: totalFormSuspicionScore,
        flagCount: formAnalysisResults.reduce((sum, r) => sum + r.flags.length, 0),
        externalScripts: externalScripts.length,
        flags: formAnalysisResults.flatMap(r => r.flags)
      }
    });
    
    // If enhanced score exceeds threshold, trigger high threat handling
    if (enhancedScore >= 60 && !currentPageStatus.highThreatTriggered) {
      currentPageStatus.highThreatTriggered = true;
      console.log('%c🚨 THREAT THRESHOLD EXCEEDED DUE TO FORM BEHAVIOR!', 'color: #dc2626; font-weight: bold; font-size: 16px');
      
      chrome.runtime.sendMessage({
        action: 'credentialDetected',
        url: window.location.href,
        enhancedScore: enhancedScore,
        formAnalysis: {
          suspicionScore: totalFormSuspicionScore,
          flagCount: formAnalysisResults.reduce((sum, r) => sum + r.flags.length, 0),
          externalScripts: externalScripts.length
        }
      });
    }
  }
}

/**
 * Show inline warning banner at top of page
 */
function showInlineWarning(formAnalysisResults = []) {
  if (warningOverlayActive) return;
  
  // Extract critical flags from form analysis
  const criticalFlags = [];
  formAnalysisResults.forEach(result => {
    result.flags.forEach(flag => {
      if (flag.severity === 'critical' || flag.severity === 'high') {
        criticalFlags.push(flag.message);
      }
    });
  });
  
  const banner = document.createElement('div');
  banner.id = 'phishguard-warning-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    color: white;
    padding: 16px 24px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    font-weight: 600;
    z-index: 2147483647;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    display: flex;
    align-items: center;
    justify-content: space-between;
    animation: slideDown 0.3s ease;
  `;
  
  const warningText = criticalFlags.length > 0 
    ? criticalFlags[0] 
    : `This site has been flagged as potentially dangerous (Threat Score: ${currentPageStatus.score}/100).`;
  
  banner.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px;">
      <span style="font-size: 24px;">🛡️</span>
      <div>
        <div style="font-size: 16px; margin-bottom: 4px;">⚠️ PhishGuard Protection Active</div>
        <div style="font-size: 13px; opacity: 0.9;">
          ${warningText} Credential submission is blocked.
        </div>
      </div>
    </div>
    <button id="phishguard-details-btn" style="
      background: rgba(255,255,255,0.2);
      border: 1px solid rgba(255,255,255,0.4);
      color: white;
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
    ">Details</button>
  `;
  
  document.body.insertBefore(banner, document.body.firstChild);
  warningOverlayActive = true;
  
  // Add animation keyframes
  if (!document.getElementById('phishguard-animations')) {
    const style = document.createElement('style');
    style.id = 'phishguard-animations';
    style.textContent = `
      @keyframes slideDown {
        from { transform: translateY(-100%); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);
  }
  
  // Details button handler
  document.getElementById('phishguard-details-btn')?.addEventListener('click', () => {
    showDetailedWarningModal();
  });
}

/**
 * Show detailed warning modal
 */
function showDetailedWarningModal() {
  const modal = document.createElement('div');
  modal.id = 'phishguard-modal';
  modal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0,0,0,0.85);
    z-index: 2147483647;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    animation: fadeIn 0.2s ease;
  `;
  
  // Add form behavior analysis results
  let formBehaviorSection = '';
  if (currentPageStatus.formAnalysis && currentPageStatus.formAnalysis.forms.length > 0) {
    const allFlags = currentPageStatus.formAnalysis.forms.flatMap(f => f.flags);
    if (allFlags.length > 0) {
      const formFlagsList = allFlags.map(flag => {
        const icon = flag.severity === 'critical' ? '🚨' : flag.severity === 'high' ? '⚠️' : '⚡';
        return `<li style="margin: 8px 0; color: ${flag.severity === 'critical' ? '#dc2626' : '#ea580c'};">
          ${icon} ${flag.message}
        </li>`;
      }).join('');
      
      formBehaviorSection = `
        <div style="margin: 24px 0;">
          <h3 style="font-size: 16px; color: #111827; margin-bottom: 12px;">🔍 Form Behavior Analysis</h3>
          <ul style="font-size: 14px; line-height: 1.6; padding-left: 24px;">
            ${formFlagsList}
          </ul>
        </div>
      `;
    }
  }
  
  const reasons = currentPageStatus.reasons || [];
  const reasonsList = reasons.map(r => `<li style="margin: 8px 0;">${r}</li>`).join('');
  
  modal.innerHTML = `
    <div style="
      background: white;
      border-radius: 16px;
      ${formBehaviorSection}
      
      padding: 32px;
      max-width: 500px;
      width: 90%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      animation: scaleIn 0.3s ease;
    ">
      <div style="text-align: center; margin-bottom: 24px;">
        <div style="font-size: 64px; margin-bottom: 16px;">🚨</div>
        <h2 style="margin: 0; font-size: 24px; color: #dc2626;">Potential Phishing Site Detected</h2>
      </div>
      
      <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 16px; margin: 20px 0; border-radius: 8px;">
        <div style="font-weight: 600; color: #991b1b; margin-bottom: 8px;">Threat Score: ${currentPageStatus.score}/100</div>
        <div style="color: #7f1d1d; font-size: 14px;">Risk Level: ${currentPageStatus.riskLevel?.toUpperCase() || 'HIGH'}</div>
      </div>
      
      <div style="margin: 24px 0;">
        <h3 style="font-size: 16px; color: #111827; margin-bottom: 12px;">Why was this site flagged?</h3>
        <ul style="color: #374151; font-size: 14px; line-height: 1.6; padding-left: 24px;">
          ${reasonsList || '<li>Suspicious URL patterns detected</li>'}
        </ul>
      </div>
      
      <div style="background: #eff6ff; padding: 16px; border-radius: 8px; margin: 20px 0;">
        <div style="font-weight: 600; color: #1e40af; margin-bottom: 8px;">🛡️ Protection Enabled</div>
        <div style="color: #1e3a8a; font-size: 13px;">
          PhishGuard has blocked credential submission on this page to protect your account.
        </div>
      </div>
      
      <div style="display: flex; gap: 12px; margin-top: 24px;">
        <button id="phishguard-modal-close" style="
          flex: 1;
          background: #dc2626;
          color: white;
          border: none;
          padding: 12px;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s;
        ">Close</button>
        <button id="phishguard-modal-back" style="
          flex: 1;
          background: #374151;
          color: white;
          border: none;
          padding: 12px;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s;
        ">Go Back (Safe)</button>
      </div>
    </div>
  `;
  
  // Add animations
  const style = document.createElement('style');
  style.textContent = `
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    @keyframes scaleIn {
      from { transform: scale(0.9); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    #phishguard-modal-close:hover { background: #b91c1c; }
    #phishguard-modal-back:hover { background: #1f2937; }
  `;
  document.head.appendChild(style);
  
  document.body.appendChild(modal);
  
  // Event handlers
  document.getElementById('phishguard-modal-close')?.addEventListener('click', () => {
    modal.remove();
  });
  
  document.getElementById('phishguard-modal-back')?.addEventListener('click', () => {
    window.history.back();
  });
}

/**
 * Block form submissions on risky pages
 */
function setupFormInterception() {
  // Intercept all form submissions
  document.addEventListener('submit', (e) => {
    if (!currentPageStatus.safe && credentialFormDetected) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      
      console.log('🛑 Form submission blocked by PhishGuard');
      showCredentialBlockWarning('Form submission blocked for your protection');
      
      return false;
    }
  }, true);
  
  // Also monitor password field interactions
  const passwordFields = document.querySelectorAll('input[type="password"]');
  passwordFields.forEach(field => {
    field.addEventListener('focus', () => {
      if (!currentPageStatus.safe) {
        showPasswordFieldWarning(field);
      }
    });
  });
}

/**
 * Show warning when user focuses on password field
 */
function showPasswordFieldWarning(field) {
  // Create tooltip warning
  const tooltip = document.createElement('div');
  tooltip.style.cssText = `
    position: absolute;
    background: #dc2626;
    color: white;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    z-index: 2147483646;
    pointer-events: none;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  `;
  tooltip.textContent = '⚠️ Warning: This site may be unsafe';
  
  const rect = field.getBoundingClientRect();
  tooltip.style.top = (rect.top + window.scrollY - 40) + 'px';
  tooltip.style.left = (rect.left + window.scrollX) + 'px';
  
  document.body.appendChild(tooltip);
  
  // Remove after 3 seconds
  setTimeout(() => tooltip.remove(), 3000);
}

/**
 * Show credential blocking confirmation
 */
function showCredentialBlockWarning(message) {
  const notification = document.createElement('div');
  notification.style.cssText = `
    position: fixed;
    top: 80px;
    left: 50%;
    transform: translateX(-50%);
    background: #dc2626;
    color: white;
    padding: 16px 24px;
    border-radius: 12px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 14px;
    font-weight: 600;
    z-index: 2147483647;
    box-shadow: 0 8px 24px rgba(0,0,0,0.4);
    animation: bounceIn 0.4s ease;
  `;
  
  notification.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px;">
      <span style="font-size: 24px;">🛑</span>
      <span>${message}</span>
    </div>
  `;
  
  document.body.appendChild(notification);
  
  // Auto-remove after 4 seconds
  setTimeout(() => {
    notification.style.animation = 'fadeOut 0.3s ease';
    setTimeout(() => notification.remove(), 300);
  }, 4000);
}

/**
 * Monitor for dynamically added forms
 */
const observer = new MutationObserver((mutations) => {
  if (!currentPageStatus.safe && !credentialFormDetected) {
    scanForCredentialForms();
  }
});

// Start observing
observer.observe(document.body, {
  childList: true,
  subtree: true
});

// Initial scan when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
      if (!currentPageStatus.safe) {
        scanForCredentialForms();
      }
    }, 1000);
  });
} else {
  // Page already loaded
  setTimeout(() => {
    if (!currentPageStatus.safe) {
      scanForCredentialForms();
    }
  }, 1000);
}

console.log('PhishGuard AI content script initialized');
