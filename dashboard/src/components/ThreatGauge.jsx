import React from 'react';

export default function ThreatGauge({ score = 85 }) {
  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  
  const getColor = () => {
    if (score >= 85) return '#ef4444';
    if (score >= 60) return '#f97316';
    if (score >= 30) return '#eab308';
    return '#22c55e';
  };

  const getRiskLevel = () => {
    if (score >= 85) return 'High Risk';
    if (score >= 60) return 'Medium Risk';
    if (score >= 30) return 'Low Risk';
    return 'Safe';
  };

  return (
    <div className="card card-hover flex flex-col items-center justify-center py-8">
      <h3 className="text-lg font-semibold text-cyan-400/60 mb-6">Live Threat Score</h3>
      
      <div className="relative w-48 h-48 mb-6">
        <svg width="100%" height="100%" viewBox="0 0 120 120" style={{ transform: 'rotate(-90deg)' }}>
          {/* Background circle */}
          <circle
            cx="60"
            cy="60"
            r="45"
            fill="none"
            stroke="#334155"
            strokeWidth="8"
          />
          
          {/* Progress circle with gradient */}
          <defs>
            <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#06b6d4" />
              <stop offset="100%" stopColor={getColor()} />
            </linearGradient>
          </defs>
          
          <circle
            cx="60"
            cy="60"
            r="45"
            fill="none"
            stroke="url(#gaugeGradient)"
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{
              transition: 'stroke-dashoffset 0.5s ease',
              filter: `drop-shadow(0 0 10px ${getColor()}80)`
            }}
          />
        </svg>
        
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-4xl font-bold text-cyan-400">{score}%</div>
          <div className="text-sm font-semibold mt-2" style={{ color: getColor() }}>
            {getRiskLevel()}
          </div>
        </div>
      </div>

      {/* Status indicator */}
      <div className="flex items-center gap-2 text-sm">
        <span className="w-3 h-3 rounded-full animate-pulse" style={{ backgroundColor: getColor() }} />
        <span className="text-cyan-400/60">
          {score >= 85 ? 'Critical threat detected' : 
           score >= 60 ? 'Threat warning' :
           score >= 30 ? 'Minor threats' : 
           'System secure'}
        </span>
      </div>
    </div>
  );
}
