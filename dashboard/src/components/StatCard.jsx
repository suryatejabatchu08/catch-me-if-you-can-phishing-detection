import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';

export default function StatCard({ title, value, subtitle, icon: Icon, trend, trendValue }) {
  const isPositive = trend === 'up';
  
  return (
    <div className="card card-hover group">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-xs font-semibold text-cyan-400/60 uppercase tracking-wider">
            {title}
          </p>
          <p className="text-4xl font-bold text-white mt-3 group-hover:text-cyan-400 transition-colors">
            {value}
          </p>
          {subtitle && (
            <p className="text-xs text-cyan-400/50 mt-2">
              {subtitle}
            </p>
          )}
        </div>
        
        {Icon && (
          <div className="p-4 bg-gradient-to-br from-cyan-500/20 to-transparent rounded-xl border border-cyan-500/20 group-hover:border-cyan-500/40 transition-all">
            <Icon className="w-7 h-7 glow-cyan" />
          </div>
        )}
      </div>
      
      {trend && (
        <div className={`flex items-center gap-2 mt-6 text-sm font-semibold ${
          isPositive ? 'text-emerald-400' : 'text-red-400'
        }`}>
          {isPositive ? (
            <TrendingUp className="w-4 h-4" />
          ) : (
            <TrendingDown className="w-4 h-4" />
          )}
          <span>{trendValue}</span>
        </div>
      )}
    </div>
  );
}
