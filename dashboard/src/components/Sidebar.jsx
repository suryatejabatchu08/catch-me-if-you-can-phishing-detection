import React from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, BarChart3, History, GraduationCap, Settings } from 'lucide-react';

export default function Sidebar() {
  const navItems = [
    { to: '/dashboard', icon: BarChart3, label: 'Dashboard' },
    { to: '/threats', icon: History, label: 'History' },
    { to: '/training', icon: GraduationCap, label: 'Training' },
    { to: '/settings', icon: Settings, label: 'Settings' }
  ];

  return (
    <aside className="w-80 bg-gradient-to-b from-slate-900 to-slate-950 border-r border-cyan-500/20">
      <div className="flex items-center gap-3 p-8 border-b border-cyan-500/20">
        <div className="relative">
          <Shield className="w-10 h-10 glow-cyan" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white glow-cyan">PhishGuard AI</h1>
          <p className="text-xs text-cyan-400/60">Realtime Phishing Protection</p>
        </div>
      </div>
      
      <nav className="p-6 space-y-3">
        {navItems.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-4 px-5 py-4 rounded-xl transition-all duration-300 ${
                isActive
                  ? 'bg-gradient-to-r from-cyan-500/30 to-transparent border border-cyan-500/40 text-cyan-300 shadow-lg shadow-cyan-500/10'
                  : 'text-slate-300 hover:bg-slate-800/50 border border-transparent hover:border-cyan-500/20'
              }`
            }
          >
            <Icon className="w-5 h-5" />
            <span className="font-medium text-lg">{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="absolute bottom-8 left-6 right-6 p-4 bg-slate-800/50 rounded-xl border border-cyan-500/10">
        <p className="text-xs text-slate-400 mb-2">Threats Blocked</p>
        <p className="text-2xl font-bold text-cyan-400">1,245</p>
      </div>
    </aside>
  );
}
