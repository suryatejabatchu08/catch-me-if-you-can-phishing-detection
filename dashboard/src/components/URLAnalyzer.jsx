import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Loader, Globe } from 'lucide-react';
import { analyzeUrl } from '../config/api';

export default function URLAnalyzer() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeUrl(url);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Failed to analyze URL');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case 'safe':
        return 'border-emerald-500/40 bg-emerald-500/10';
      case 'suspicious':
        return 'border-yellow-500/40 bg-yellow-500/10';
      case 'dangerous':
        return 'border-orange-500/40 bg-orange-500/10';
      case 'critical':
        return 'border-red-500/40 bg-red-500/10';
      default:
        return 'border-cyan-500/20 bg-cyan-500/5';
    }
  };

  const getRiskBadgeColor = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case 'safe':
        return 'badge-safe';
      case 'suspicious':
        return 'badge-suspicious';
      case 'dangerous':
      case 'critical':
        return 'badge-critical';
      default:
        return 'badge-suspicious';
    }
  };

  const getRiskIcon = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case 'safe':
        return <CheckCircle className="w-6 h-6 text-emerald-400" />;
      case 'suspicious':
        return <AlertTriangle className="w-6 h-6 text-yellow-400" />;
      case 'dangerous':
      case 'critical':
        return <XCircle className="w-6 h-6 text-red-400" />;
      default:
        return <Shield className="w-6 h-6 text-cyan-400" />;
    }
  };

  return (
    <div className="card card-hover">
      {/* Header */}
      <div className="flex items-center gap-3 mb-8">
        <Globe className="w-8 h-8 glow-cyan" />
        <div>
          <h2 className="text-3xl font-bold text-white glow-cyan">
            Analyze URL
          </h2>
          <p className="text-sm text-cyan-400/60">
            Check if a website is safe or potentially malicious
          </p>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleAnalyze} className="mb-8">
        <div className="flex gap-3">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter URL to scan..."
            className="flex-1 px-5 py-4 border border-cyan-500/20 rounded-xl 
                     focus:ring-2 focus:ring-cyan-500 focus:border-transparent focus:outline-none
                     bg-slate-800/50 text-white placeholder-slate-400
                     transition-all"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading}
            className="btn-primary flex items-center gap-2 disabled:opacity-50"
          >
            {loading ? (
              <>
                <Loader className="w-5 h-5 animate-spin" />
              </>
            ) : (
              'Analyze'
            )}
          </button>
        </div>
      </form>

      {/* Error Message */}
      {error && (
        <div className="mb-6 p-4 bg-red-500/10 border border-red-500/40 rounded-xl">
          <div className="flex items-center gap-2 text-red-300">
            <XCircle className="w-5 h-5" />
            <span className="font-medium">{error}</span>
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Threat Score Card */}
          <div className={`p-8 rounded-2xl border-2 ${getRiskColor(result.risk_level)} backdrop-blur-sm`}>
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-4">
                {getRiskIcon(result.risk_level)}
                <div>
                  <div className={`badge ${getRiskBadgeColor(result.risk_level)}`}>
                    {result.risk_level.toUpperCase()}
                  </div>
                  <p className="text-sm text-cyan-400/60 mt-2">
                    Threat Score: {result.threat_score}/100
                  </p>
                </div>
              </div>
              <div className="text-right">
                <div className="text-4xl font-bold text-cyan-400">{result.threat_score}%</div>
                <div className="text-xs text-cyan-400/60">
                  {Math.round(result.confidence * 100)}% confidence
                </div>
              </div>
            </div>
            
            {/* Progress Bar */}
            <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden">
              <div
                className="h-3 rounded-full transition-all duration-500 shadow-lg"
                style={{
                  width: `${result.threat_score}%`,
                  backgroundColor: result.threat_score >= 85 ? '#ef4444' :
                                   result.threat_score >= 60 ? '#f97316' :
                                   result.threat_score >= 30 ? '#eab308' : '#22c55e',
                  boxShadow: result.threat_score >= 85 ? '0 0 20px rgba(239, 68, 68, 0.5)' :
                            result.threat_score >= 60 ? '0 0 20px rgba(249, 115, 22, 0.5)' :
                            result.threat_score >= 30 ? '0 0 20px rgba(234, 179, 8, 0.5)' : '0 0 20px rgba(34, 197, 94, 0.5)'
                }}
              />
            </div>
          </div>

          {/* Analysis Details */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-slate-800/50 p-4 rounded-xl border border-cyan-500/10">
              <div className="text-xs text-cyan-400/60 mb-1">ML Score</div>
              <div className="text-2xl font-bold text-cyan-400">
                {result.analysis.ml_contribution.toFixed(1)}
              </div>
            </div>
            <div className="bg-slate-800/50 p-4 rounded-xl border border-cyan-500/10">
              <div className="text-xs text-cyan-400/60 mb-1">Heuristic</div>
              <div className="text-2xl font-bold text-cyan-400">
                {result.analysis.heuristic_contribution.toFixed(1)}
              </div>
            </div>
            <div className="bg-slate-800/50 p-4 rounded-xl border border-cyan-500/10">
              <div className="text-xs text-cyan-400/60 mb-1">Threat Intel</div>
              <div className="text-2xl font-bold text-cyan-400">
                {result.analysis.threat_intel_contribution.toFixed(1)}
              </div>
            </div>
            <div className="bg-slate-800/50 p-4 rounded-xl border border-cyan-500/10">
              <div className="text-xs text-cyan-400/60 mb-1">Lookalike</div>
              <div className="text-2xl font-bold text-cyan-400">
                {result.analysis.lookalike_contribution.toFixed(1)}
              </div>
            </div>
          </div>

          {/* Lookalike Detection */}
          {result.analysis.lookalike_detected && (
            <div className="bg-orange-500/10 border border-orange-500/40 p-4 rounded-xl">
              <div className="flex items-center gap-2 text-orange-300 mb-2">
                <AlertTriangle className="w-5 h-5" />
                <span className="font-bold">Lookalike Domain Detected!</span>
              </div>
              <p className="text-sm text-orange-300/80">
                This domain appears to impersonate: <strong>{result.analysis.lookalike_brand}</strong>
              </p>
            </div>
          )}

          {/* Recommendation */}
          <div className={`p-6 rounded-xl border ${
            result.recommendation === 'block' ? 'bg-red-500/10 border-red-500/40' :
            result.recommendation === 'warn' ? 'bg-yellow-500/10 border-yellow-500/40' :
            'bg-emerald-500/10 border-emerald-500/40'
          }`}>
            <div className={`font-bold mb-1 ${
              result.recommendation === 'block' ? 'text-red-300' :
              result.recommendation === 'warn' ? 'text-yellow-300' :
              'text-emerald-300'
            }`}>
              Status: {result.recommendation.toUpperCase()}
            </div>
            <div className="text-sm text-slate-300">
              {result.recommendation === 'block' && 'This URL should be blocked. Do not proceed.'}
              {result.recommendation === 'warn' && 'Exercise caution. Verify before proceeding.'}
              {result.recommendation === 'allow' && 'This URL appears safe to visit.'}
            </div>
          </div>
        </div>
      )}

      {/* Quick Test Links */}
      {!result && (
        <div className="mt-8 pt-8 border-t border-cyan-500/10">
          <p className="text-xs text-cyan-400/60 mb-3 uppercase font-semibold">Quick test examples:</p>
          <div className="flex flex-wrap gap-2">
            {[
              'https://example.com',
              'https://github.com/login',
              'https://google.com'
            ].map((testUrl) => (
              <button
                key={testUrl}
                onClick={() => setUrl(testUrl)}
                className="text-xs px-3 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/20 
                         hover:border-cyan-500/40 text-cyan-300 rounded-lg transition-all"
              >
                {testUrl}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
