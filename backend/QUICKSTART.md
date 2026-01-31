# 🚀 QUICK START - Get Running in 5 Minutes

## Step 1: Install Dependencies (1 min)

```powershell
cd backend
pip install -r requirements.txt
```

## Step 2: Create Environment File (1 min)

```powershell
# Copy template
copy .env.example .env

# Edit with your API keys (optional for basic testing)
notepad .env
```

**Minimum .env (works without API keys):**
```env
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
REDIS_HOST=localhost
REDIS_PORT=6379
```

## Step 3: Train ML Models (1 min)

```powershell
python train_model.py
```

**Expected Output:**
```
📊 PRIMARY MODEL (Random Forest):
  Accuracy: 0.9542
  AUC-ROC: 0.9781
✅ Training complete!
💾 Models saved to models/
```

## Step 4: Start Server (1 min)

```powershell
uvicorn main:app --reload
```

**Server running at:** http://localhost:8000

**API Docs:** http://localhost:8000/docs

## Step 5: Test It! (1 min)

### Option A: Browser
Visit http://localhost:8000/docs and click "Try it out"

### Option B: PowerShell
```powershell
$body = @{
    url = "https://google.com"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze/url" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"
```

### Option C: Python
```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/analyze/url",
    json={"url": "https://google.com"}
)

result = response.json()
print(f"Threat Score: {result['threat_score']}")
print(f"Risk Level: {result['risk_level']}")
print(f"Is Phishing: {result['is_phishing']}")
```

---

## 🧪 Test with Phishing-Like URL

```powershell
$body = @{
    url = "https://paypa1.com/login"
    page_title = "PayPal Login"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/api/v1/analyze/url" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"
```

**Expected Response:**
```json
{
  "threat_score": 85,
  "risk_level": "dangerous",
  "is_phishing": true,
  "confidence": 0.92,
  "recommendation": "block",
  "analysis": {
    "lookalike_detected": true,
    "lookalike_brand": "paypal.com",
    "reasons": [
      {
        "factor": "Lookalike domain: Uses '1' instead of 'l' (impersonating paypal.com)",
        "severity": "critical",
        "weight": 35
      }
    ]
  }
}
```

---

## 🎯 All Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/analyze/url` | POST | Analyze URL for phishing |
| `/api/v1/analyze/email` | POST | Analyze email (bonus) |
| `/api/v1/threat-intel/domain/{domain}` | GET | Domain reputation |
| `/api/v1/health` | GET | Health check |
| `/` | GET | API info |
| `/docs` | GET | Interactive API docs |

---

## 🔑 Optional: Add API Keys for Full Power

### VirusTotal (Free)
1. Sign up: https://www.virustotal.com/gui/join-us
2. Get API key: https://www.virustotal.com/gui/my-apikey
3. Add to `.env`: `VIRUSTOTAL_API_KEY=your_key_here`

### AbuseIPDB (Free)
1. Sign up: https://www.abuseipdb.com/register
2. Get API key: https://www.abuseipdb.com/account/api
3. Add to `.env`: `ABUSEIPDB_API_KEY=your_key_here`

**Note:** Works great without API keys using heuristics + ML + lookalike detection!

---

## 🐛 Troubleshooting

### "Module not found"
```powershell
pip install -r requirements.txt
```

### "Models not found"
```powershell
python train_model.py
```

### "Port 8000 already in use"
```powershell
uvicorn main:app --reload --port 8001
```

### "Redis connection failed"
Don't worry! It automatically uses in-memory cache fallback.

---

## ✅ You're Ready!

Backend is running with:
- ✅ 500+ brand protection
- ✅ ML phishing detection
- ✅ Threat intelligence
- ✅ Explainable scoring
- ✅ <200ms response time

**Connect your Chrome extension and start catching phishers! 🎣**
