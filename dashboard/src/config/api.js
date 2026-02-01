/**
 * API Configuration
 * Backend API connection settings
 */

const API_CONFIG = {
  // Backend API base URL
  baseURL: 'https://suryateja008-catch-me-if-you-can-phishing-detection.hf.space' || 'http://localhost:8000',
  
  // API endpoints
  endpoints: {
    analyzeUrl: '/api/v1/analyze/url',
    analyzeEmail: '/api/v1/analyze/email',
    threatIntel: '/api/v1/threat-intel/domain',
    health: '/api/v1/health',
  },
  
  // Request timeout (ms)
  timeout: 30000,
};

/**
 * Analyze URL for phishing threats
 */
export async function analyzeUrl(url, options = {}) {
  try {
    const response = await fetch(`${API_CONFIG.baseURL}${API_CONFIG.endpoints.analyzeUrl}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        url: url,
        page_title: options.pageTitle || null,
        page_text: options.pageText || null,
        css_colors: options.cssColors || null,
        user_id: options.userId || null,
      }),
      signal: AbortSignal.timeout(API_CONFIG.timeout),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(error.detail?.message || error.detail || 'Analysis failed');
    }

    return await response.json();
  } catch (error) {
    if (error.name === 'TimeoutError') {
      throw new Error('Request timed out. Please try again.');
    }
    throw error;
  }
}

/**
 * Analyze email for phishing threats
 */
export async function analyzeEmail(emailData) {
  try {
    const response = await fetch(`${API_CONFIG.baseURL}${API_CONFIG.endpoints.analyzeEmail}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(emailData),
      signal: AbortSignal.timeout(API_CONFIG.timeout),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(error.detail?.message || error.detail || 'Analysis failed');
    }

    return await response.json();
  } catch (error) {
    if (error.name === 'TimeoutError') {
      throw new Error('Request timed out. Please try again.');
    }
    throw error;
  }
}

/**
 * Get domain reputation from threat intelligence
 */
export async function getDomainReputation(domain) {
  try {
    const response = await fetch(
      `${API_CONFIG.baseURL}${API_CONFIG.endpoints.threatIntel}/${domain}`,
      {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
        },
        signal: AbortSignal.timeout(API_CONFIG.timeout),
      }
    );

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(error.detail?.message || error.detail || 'Lookup failed');
    }

    return await response.json();
  } catch (error) {
    if (error.name === 'TimeoutError') {
      throw new Error('Request timed out. Please try again.');
    }
    throw error;
  }
}

/**
 * Check API health status
 */
export async function checkHealth() {
  try {
    const response = await fetch(`${API_CONFIG.baseURL}${API_CONFIG.endpoints.health}`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      return { status: 'unhealthy', error: 'API not responding' };
    }

    return await response.json();
  } catch (error) {
    return { status: 'unhealthy', error: error.message };
  }
}

export default API_CONFIG;
