"""
PhishGuard AI - Sample Data Seeding Script
Generates realistic threat data for dashboard demo
"""

import random
import json
import uuid
from datetime import datetime, timedelta
from supabase import create_client, Client

# Supabase Configuration
SUPABASE_URL = "https://ngmsircoglpuafmsbfno.supabase.co"
SUPABASE_KEY = "sb_secret_S7n2lcA9xvkqlGzo2fq08g_bV8_EAZd"  # Use service key for admin access

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Sample data pools
PHISHING_DOMAINS = [
    "paypaI-verify.com",
    "microsοft-login.com",
    "google-accounts-verify.net",
    "chase-secure-banking.com",
    "amazon-account-update.info",
    "facebook-security-check.org",
    "netflix-billing-update.com",
    "apple-id-verification.net",
    "linkedin-security.com",
    "dropbox-storage-upgrade.net"
]

LEGITIMATE_DOMAINS = [
    "google.com",
    "microsoft.com",
    "github.com",
    "stackoverflow.com",
    "reddit.com",
    "youtube.com",
    "twitter.com",
    "linkedin.com",
    "amazon.com",
    "wikipedia.org"
]

THREAT_REASONS = [
    {"factor": "Lookalike domain detected", "weight": 35},
    {"factor": "VirusTotal: 8 vendors flagged malicious", "weight": 30},
    {"factor": "Suspicious URL patterns detected", "weight": 15},
    {"factor": "Domain age < 30 days", "weight": 10},
    {"factor": "HTTPS certificate mismatch", "weight": 8},
    {"factor": "Urgent language detected in page", "weight": 7},
    {"factor": "Multiple redirects detected", "weight": 5},
    {"factor": "Form action points to external domain", "weight": 25},
    {"factor": "Hidden iframe detected", "weight": 12},
    {"factor": "OpenPhish: Known phishing site", "weight": 40}
]

SIMULATION_TYPES = ["fake_login", "lookalike_domain", "urgent_email", "mixed_threat"]

def generate_user_id():
    """Generate a proper UUID for user_id"""
    return str(uuid.uuid4())

def generate_threat_logs(user_id, count=50):
    """Generate realistic threat logs"""
    threat_logs = []
    
    for i in range(count):
        # Random date in last 30 days
        days_ago = random.randint(0, 30)
        timestamp = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23), minutes=random.randint(0, 59))
        
        # 70% phishing, 30% legitimate
        is_phishing = random.random() < 0.7
        
        if is_phishing:
            domain = random.choice(PHISHING_DOMAINS)
            threat_score = random.randint(60, 100)
            user_action = random.choice(['blocked', 'blocked', 'blocked', 'proceeded'])
            credential_detected = random.random() < 0.6
            num_reasons = random.randint(2, 5)
        else:
            domain = random.choice(LEGITIMATE_DOMAINS)
            threat_score = random.randint(0, 40)
            user_action = 'auto_blocked' if threat_score < 10 else 'whitelisted'
            credential_detected = False
            num_reasons = random.randint(0, 2)
        
        # Risk level
        if threat_score >= 86:
            risk_level = "Critical"
        elif threat_score >= 61:
            risk_level = "Dangerous"
        elif threat_score >= 31:
            risk_level = "Suspicious"
        else:
            risk_level = "Safe"
        
        threat_log = {
            "user_id": user_id,
            "timestamp": timestamp.isoformat(),
            "url": f"https://{domain}/login" if is_phishing else f"https://{domain}",
            "domain": domain,
            "page_title": f"{domain.split('.')[0].capitalize()} Login" if is_phishing else f"{domain.split('.')[0].capitalize()}",
            "threat_score": threat_score,
            "risk_level": risk_level,
            "threat_reasons": random.sample(THREAT_REASONS, num_reasons) if num_reasons > 0 else [],
            "attack_vector": random.choice(['web', 'email']) if is_phishing else 'web',
            "user_action": user_action,
            "ml_confidence": round(random.uniform(0.7, 0.99), 2) if is_phishing else round(random.uniform(0.3, 0.7), 2),
            "threat_intel_sources": {
                "virustotal": random.randint(5, 15) if is_phishing else 0,
                "abuseipdb": random.randint(50, 100) if is_phishing else 0,
                "openphish": is_phishing
            },
            "credential_detected": credential_detected,
            "form_action_url": f"https://malicious-collector.com/steal" if credential_detected else None,
            "external_links_count": random.randint(5, 20) if is_phishing else random.randint(0, 5)
        }
        
        threat_logs.append(threat_log)
    
    return threat_logs

def generate_simulation_results(user_id, count=15):
    """Generate training simulation results"""
    simulations = []
    
    # 80% success rate
    for i in range(count):
        days_ago = random.randint(0, 30)
        timestamp = datetime.now() - timedelta(days=days_ago, hours=random.randint(0, 23))
        
        correct = random.random() < 0.8
        clicked = not correct if random.random() < 0.9 else correct
        
        simulation = {
            "user_id": user_id,
            "simulation_type": random.choice(SIMULATION_TYPES),
            "simulation_url": f"https://simulation-{random.randint(1000, 9999)}.phishguard.test",
            "clicked": clicked,
            "time_to_decision": random.randint(3, 45),
            "correct_identification": correct,
            "threat_score_shown": random.randint(65, 95),
            "completed_at": timestamp.isoformat()
        }
        
        simulations.append(simulation)
    
    return simulations

def generate_achievement_badges(user_id):
    """Generate achievement badges"""
    badges = [
        {
            "user_id": user_id,
            "badge_name": "first_threat_blocked",
            "badge_description": "Blocked your first threat"
        },
        {
            "user_id": user_id,
            "badge_name": "first_simulation_passed",
            "badge_description": "Passed your first simulation"
        },
        {
            "user_id": user_id,
            "badge_name": "early_adopter",
            "badge_description": "Joined PhishGuard AI early"
        }
    ]
    
    # Randomly add more badges
    if random.random() < 0.5:
        badges.append({
            "user_id": user_id,
            "badge_name": "guardian_angel",
            "badge_description": "100+ threats blocked"
        })
    
    return badges

def generate_community_reports():
    """Generate community threat reports"""
    reports = []
    
    for domain in PHISHING_DOMAINS[:7]:  # Use subset
        report = {
            "domain": domain,
            "threat_score": random.randint(70, 95),
            "report_count": random.randint(50, 500),
            "avg_threat_score": round(random.uniform(75.0, 95.0), 2),
            "confidence_level": random.choice(['medium', 'high', 'verified'])
        }
        reports.append(report)
    
    return reports

def seed_database():
    """Seed the database with sample data"""
    print("🌱 Starting database seeding...")
    
    # Generate user ID
    user_id = generate_user_id()
    print(f"📝 Using user ID: {user_id}")
    
    # Create user account first (optional, since user_id can be null)
    print("👤 Creating user account...")
    try:
        user_account = {
            "id": user_id,
            "email": f"demo_{user_id[:8]}@phishguard.test",
            "settings": {
                "notifications_enabled": True,
                "dark_mode": False,
                "auto_sync": True,
                "training_mode": True,
                "community_sharing": True
            }
        }
        supabase.table('user_accounts').insert([user_account]).execute()
        print(f"✅ Created user account")
    except Exception as e:
        print(f"⚠️  User account creation skipped (may already exist): {e}")
    
    # Insert threat logs
    print("📊 Generating threat logs...")
    threat_logs = generate_threat_logs(user_id, count=50)
    result = supabase.table('threat_logs').insert(threat_logs).execute()
    print(f"✅ Inserted {len(result.data)} threat logs")
    
    # Insert simulation results
    print("🎯 Generating simulation results...")
    simulations = generate_simulation_results(user_id, count=15)
    result = supabase.table('simulation_results').insert(simulations).execute()
    print(f"✅ Inserted {len(result.data)} simulation results")
    
    # Insert badges
    print("🏆 Generating achievement badges...")
    badges = generate_achievement_badges(user_id)
    result = supabase.table('achievement_badges').insert(badges).execute()
    print(f"✅ Inserted {len(result.data)} badges")
    
    # Insert community reports
    print("🌐 Generating community reports...")
    reports = generate_community_reports()
    result = supabase.table('community_reports').insert(reports).execute()
    print(f"✅ Inserted {len(result.data)} community reports")
    
    print("\n🎉 Database seeding completed!")
    print(f"🔑 Save this user ID for dashboard testing: {user_id}")
    print(f"💡 Update localStorage in browser: localStorage.setItem('phishguard_user_id', '{user_id}')")

if __name__ == "__main__":
    try:
        seed_database()
    except Exception as e:
        print(f"❌ Error seeding database: {e}")
        import traceback
        traceback.print_exc()
