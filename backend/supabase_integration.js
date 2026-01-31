/**
 * PhishGuard AI - Supabase Integration Module
 * Handles all cloud sync operations for threat logs
 */

import { createClient } from '@supabase/supabase-js';

// Supabase Configuration
const SUPABASE_URL = 'https://ngmsircoglpuafmsbfno.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5nbXNpcmNvZ2xwdWFmbXNiZm5vIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njk4MzY3NTgsImV4cCI6MjA4NTQxMjc1OH0.QedPuNP4_FRW_V_GYkYA8bUxacdsuuUWeyeTt_iMepQ';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

/**
 * Get or create anonymous user ID
 */
function getUserId() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['user_id'], (result) => {
      if (result.user_id) {
        resolve(result.user_id);
      } else {
        const newUserId = `anon_${crypto.randomUUID()}`;
        chrome.storage.local.set({ user_id: newUserId }, () => {
          resolve(newUserId);
        });
      }
    });
  });
}

/**
 * Log threat to Supabase
 */
export async function logThreatToSupabase(threatData) {
  try {
    const userId = await getUserId();
    
    // Get user settings
    const settings = await chrome.storage.local.get(['settings']);
    const autoSync = settings.settings?.auto_sync !== false; // Default true
    
    if (!autoSync) {
      console.log('Auto-sync disabled, threat not logged to cloud');
      return { success: false, reason: 'auto_sync_disabled' };
    }

    const threatLog = {
      user_id: userId,
      timestamp: new Date().toISOString(),
      url: threatData.url,
      domain: threatData.domain,
      page_title: threatData.pageTitle || null,
      threat_score: threatData.threatScore,
      risk_level: getRiskLevel(threatData.threatScore),
      threat_reasons: threatData.reasons || [],
      attack_vector: threatData.attackVector || 'web',
      user_action: threatData.userAction || 'auto_blocked',
      ml_confidence: threatData.mlConfidence || null,
      threat_intel_sources: threatData.threatIntelSources || {},
      credential_detected: threatData.credentialDetected || false,
      form_action_url: threatData.formActionUrl || null,
      external_links_count: threatData.externalLinksCount || 0
    };

    const { data, error } = await supabase
      .from('threat_logs')
      .insert([threatLog])
      .select();

    if (error) {
      console.error('Supabase insert error:', error);
      return { success: false, error: error.message };
    }

    // Update community reports if enabled
    const communitySharing = settings.settings?.community_sharing === true;
    if (communitySharing && threatData.threatScore >= 60) {
      await updateCommunityReport(threatData.domain, threatData.threatScore);
    }

    // Check for badge achievements
    await checkAndAwardBadges(userId);

    return { success: true, data: data[0] };
  } catch (error) {
    console.error('Error logging threat to Supabase:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Update community threat report
 */
async function updateCommunityReport(domain, threatScore) {
  try {
    const { error } = await supabase
      .rpc('update_community_report', {
        p_domain: domain,
        p_threat_score: threatScore
      });

    if (error) {
      console.error('Community report update error:', error);
    }
  } catch (error) {
    console.error('Error updating community report:', error);
  }
}

/**
 * Check and award achievement badges
 */
async function checkAndAwardBadges(userId) {
  try {
    // Get threat count
    const { data: threats, error } = await supabase
      .from('threat_logs')
      .select('id, user_action')
      .eq('user_id', userId);

    if (error || !threats) return;

    const blockedCount = threats.filter(t => t.user_action === 'blocked').length;

    // Award badges based on milestones
    if (blockedCount === 1) {
      await awardBadge(userId, 'first_threat_blocked', 'Blocked your first threat!');
    }
    if (blockedCount === 100) {
      await awardBadge(userId, 'guardian_angel', '100+ threats blocked!');
    }
  } catch (error) {
    console.error('Error checking badges:', error);
  }
}

/**
 * Award badge to user
 */
async function awardBadge(userId, badgeName, description) {
  try {
    const { error } = await supabase
      .from('achievement_badges')
      .insert([{
        user_id: userId,
        badge_name: badgeName,
        badge_description: description
      }]);

    if (!error) {
      // Show notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: '🏆 Achievement Unlocked!',
        message: description
      });
    }
  } catch (error) {
    console.error('Error awarding badge:', error);
  }
}

/**
 * Get risk level from threat score
 */
function getRiskLevel(score) {
  if (score >= 86) return 'Critical';
  if (score >= 61) return 'Dangerous';
  if (score >= 31) return 'Suspicious';
  return 'Safe';
}

/**
 * Add domain to whitelist
 */
export async function addToWhitelist(domain, reason = null) {
  try {
    const userId = await getUserId();

    const { data, error } = await supabase
      .from('whitelists')
      .insert([{
        user_id: userId,
        domain: domain,
        reason: reason
      }])
      .select();

    if (error) {
      console.error('Whitelist insert error:', error);
      return { success: false, error: error.message };
    }

    return { success: true, data: data[0] };
  } catch (error) {
    console.error('Error adding to whitelist:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Check if domain is whitelisted
 */
export async function isWhitelisted(domain) {
  try {
    const userId = await getUserId();

    const { data, error } = await supabase
      .from('whitelists')
      .select('*')
      .eq('user_id', userId)
      .eq('domain', domain)
      .single();

    return !error && data !== null;
  } catch (error) {
    return false;
  }
}

/**
 * Get community threat intelligence for domain
 */
export async function getCommunityIntel(domain) {
  try {
    const { data, error } = await supabase
      .from('community_reports')
      .select('*')
      .eq('domain', domain)
      .single();

    if (error || !data) return null;

    return {
      reportCount: data.report_count,
      avgThreatScore: data.avg_threat_score,
      confidenceLevel: data.confidence_level,
      lastReported: data.last_reported
    };
  } catch (error) {
    console.error('Error fetching community intel:', error);
    return null;
  }
}

/**
 * Log simulation result
 */
export async function logSimulationResult(simulationData) {
  try {
    const userId = await getUserId();

    const { data, error } = await supabase
      .from('simulation_results')
      .insert([{
        user_id: userId,
        simulation_type: simulationData.type,
        simulation_url: simulationData.url,
        clicked: simulationData.clicked,
        time_to_decision: simulationData.decisionTime,
        correct_identification: simulationData.correct,
        threat_score_shown: simulationData.threatScore
      }])
      .select();

    if (error) {
      console.error('Simulation log error:', error);
      return { success: false, error: error.message };
    }

    // Check for simulation badges
    const { data: simulations } = await supabase
      .from('simulation_results')
      .select('correct_identification')
      .eq('user_id', userId)
      .order('completed_at', { ascending: false })
      .limit(10);

    if (simulations) {
      if (simulations.length === 1 && simulations[0].correct_identification) {
        await awardBadge(userId, 'first_simulation_passed', 'Passed your first simulation!');
      }

      // Check for 10-streak
      if (simulations.length >= 10 && simulations.slice(0, 10).every(s => s.correct_identification)) {
        await awardBadge(userId, 'phishing_expert', '10 simulations passed in a row!');
      }
    }

    return { success: true, data: data[0] };
  } catch (error) {
    console.error('Error logging simulation:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Sync local storage to Supabase
 */
export async function syncLocalToCloud() {
  try {
    const { threat_history } = await chrome.storage.local.get(['threat_history']);
    
    if (!threat_history || threat_history.length === 0) {
      return { success: true, synced: 0 };
    }

    let synced = 0;
    for (const threat of threat_history) {
      if (!threat.synced) {
        const result = await logThreatToSupabase(threat);
        if (result.success) {
          threat.synced = true;
          synced++;
        }
      }
    }

    // Update local storage
    await chrome.storage.local.set({ threat_history });

    return { success: true, synced };
  } catch (error) {
    console.error('Sync error:', error);
    return { success: false, error: error.message };
  }
}

export default {
  logThreatToSupabase,
  addToWhitelist,
  isWhitelisted,
  getCommunityIntel,
  logSimulationResult,
  syncLocalToCloud
};
