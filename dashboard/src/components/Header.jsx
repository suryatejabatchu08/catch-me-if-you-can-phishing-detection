import React from 'react';
import { Bell, AlertCircle } from 'lucide-react';

export default function Header() {
  return (
    <header className="bg-gradient-to-r from-slate-900 to-slate-800 border-b border-cyan-500/20 px-8 py-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white glow-cyan">
            Threat Analytics
          </h2>
          <p className="text-sm text-cyan-400/60 mt-1">
            Real-time phishing protection dashboard
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="relative">
            <button className="relative p-3 text-cyan-400 hover:bg-slate-800 rounded-lg transition-all hover:border border-cyan-500/30">
              <Bell className="w-6 h-6" />
              <span className="absolute top-2 right-2 w-3 h-3 bg-red-500 rounded-full animate-pulse shadow-lg shadow-red-500/50"></span>
            </button>
            <div className="absolute top-full right-0 mt-2 bg-slate-800 rounded-lg p-3 text-sm text-white min-w-max hidden">
              <p className="text-cyan-400 font-semibold">New threat detected!</p>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
