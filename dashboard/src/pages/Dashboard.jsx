import React, { useState, useEffect } from 'react';
import { supabase, getUserId } from '../config/supabase';
import StatCard from '../components/StatCard';
import URLAnalyzer from '../components/URLAnalyzer';
import ThreatGauge from '../components/ThreatGauge';
import { Shield, AlertTriangle, Target, DollarSign, Users, Award, TrendingUp, Activity } from 'lucide-react';
import { LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart, Area } from 'recharts';
import { format, subDays } from 'date-fns';

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalThreats: 0,
    threatsLast30Days: 0,
    threatsBlocked: 0,
    credentialTheftPrevented: 0,
    highestThreatScore: 0,
    avgThreatScore: 0
  });
  
  const [timelineData, setTimelineData] = useState([]);
  const [attackVectorData, setAttackVectorData] = useState([]);
  const [riskLevelData, setRiskLevelData] = useState([]);
  const [protectionSavings, setProtectionSavings] = useState(0);
  const [percentile, setPercentile] = useState(50);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const userId = getUserId();
      
      // Fetch basic stats from view
      const { data: statsData } = await supabase
        .from('user_dashboard_stats')
        .select('*')
        .eq('user_id', userId)
        .single();
      
      if (statsData) {
        setStats({
          totalThreats: statsData.total_threats || 0,
          threatsLast30Days: statsData.threats_last_30_days || 0,
          threatsBlocked: statsData.threats_blocked || 0,
          credentialTheftPrevented: statsData.credential_theft_prevented || 0,
          highestThreatScore: statsData.highest_threat_score || 0,
          avgThreatScore: Math.round(statsData.avg_threat_score || 0)
        });
      }
      
      // Fetch timeline data
      const { data: timeline } = await supabase
        .rpc('get_daily_threat_timeline', { p_user_id: userId, p_days: 30 });
      
      if (timeline) {
        setTimelineData(timeline.map(item => ({
          date: format(new Date(item.date), 'MMM dd'),
          threats: item.threat_count,
          avgScore: parseFloat(item.avg_score)
        })).reverse());
      }
      
      // Fetch attack vector breakdown
      const { data: attackVectors } = await supabase
        .rpc('get_attack_vector_breakdown', { p_user_id: userId });
      
      if (attackVectors) {
        setAttackVectorData(attackVectors.map(item => ({
          name: item.attack_vector === 'web' ? 'Web Phishing' : 'Email Phishing',
          value: parseInt(item.count)
        })));
      }
      
      // Fetch risk level distribution
      const { data: riskLevels } = await supabase
        .rpc('get_risk_level_distribution', { p_user_id: userId });
      
      if (riskLevels) {
        setRiskLevelData(riskLevels.map(item => ({
          name: item.risk_level,
          value: parseInt(item.count)
        })));
      }
      
      // Calculate protection savings
      const { data: savings } = await supabase
        .rpc('calculate_protection_savings', { p_user_id: userId });
      
      if (savings !== null) {
        setProtectionSavings(savings);
      }
      
      // Get user percentile
      const { data: userPercentile } = await supabase
        .rpc('get_user_percentile', { p_user_id: userId });
      
      if (userPercentile !== null) {
        setPercentile(userPercentile);
      }
      
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const COLORS = {
    Safe: '#10b981',
    Suspicious: '#f59e0b',
    Dangerous: '#f97316',
    Critical: '#ef4444'
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500 mx-auto"></div>
          <p className="mt-4 text-cyan-400/60">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* URL Analyzer - Top Section */}
      <URLAnalyzer />
      
      {/* Main Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Threats Blocked"
          value={stats.threatsBlocked}
          subtitle={`${stats.threatsLast30Days} this month`}
          icon={Shield}
          trend="up"
          trendValue="+12% vs last month"
        />
        
        <StatCard
          title="Credential Theft Prevented"
          value={stats.credentialTheftPrevented}
          subtitle="Login forms blocked"
          icon={AlertTriangle}
          trend="down"
          trendValue="-5% reduction"
        />
        
        <StatCard
          title="Highest Threat Score"
          value={`${stats.highestThreatScore}%`}
          subtitle="Most dangerous encounter"
          icon={Target}
        />
        
        <StatCard
          title="Protection Savings"
          value={`$${(protectionSavings / 1000).toFixed(1)}K`}
          subtitle="Estimated value protected"
          icon={DollarSign}
          trend="up"
          trendValue="+$2.5K this month"
        />
      </div>

      {/* Live Threat Score & Insights */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <ThreatGauge score={stats.avgThreatScore} />
        </div>

        <div className="lg:col-span-2 space-y-6">
          {/* Real-Time Activity */}
          <div className="card card-hover">
            <div className="flex items-center gap-3 mb-6">
              <Activity className="w-6 h-6 glow-cyan" />
              <h3 className="text-xl font-semibold text-white glow-cyan">Real-Time Activity</h3>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-cyan-400/60 mb-2">Attacks Detected</p>
                <p className="text-3xl font-bold text-cyan-400">1,245</p>
                <p className="text-xs text-cyan-400/50 mt-1">Last 24 hours</p>
              </div>
              <div>
                <p className="text-sm text-cyan-400/60 mb-2">Protection Score</p>
                <p className="text-3xl font-bold text-emerald-400">98%</p>
                <p className="text-xs text-cyan-400/50 mt-1">All systems operational</p>
              </div>
            </div>
          </div>

          {/* Community Ranking */}
          <div className="card card-hover">
            <div className="flex items-center gap-3 mb-4">
              <Users className="w-6 h-6 glow-cyan" />
              <h3 className="text-lg font-semibold text-white">Community Ranking</h3>
            </div>
            <div className="text-center py-4">
              <p className="text-4xl font-bold text-cyan-400">{percentile}%</p>
              <p className="text-sm text-cyan-400/60 mt-2">
                Safer than <span className="font-semibold text-cyan-300">{percentile}%</span> of users
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Threats & Health Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Threats */}
        <div className="card card-hover">
          <h3 className="text-xl font-semibold text-white glow-cyan mb-6">Recent Threats</h3>
          <div className="space-y-4">
            {[
              { url: 'suspicious-link.com/login', status: 'Unsafe' },
              { url: 'suspicious-link.com/login', status: 'Unsafe' },
            ].map((threat, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg border border-red-500/20">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-red-500"></div>
                  <p className="text-sm text-slate-300">{threat.url}</p>
                </div>
                <span className="badge badge-critical text-xs">{threat.status}</span>
              </div>
            ))}
          </div>
        </div>

        {/* System Health */}
        <div className="card card-hover">
          <h3 className="text-xl font-semibold text-white glow-cyan mb-6">System Health</h3>
          <div className="space-y-5">
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm text-cyan-400/60">Database Updates</p>
                <p className="text-sm font-semibold text-cyan-400">98%</p>
              </div>
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-cyan-500 to-cyan-400 rounded-full" style={{ width: '98%' }}></div>
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm text-cyan-400/60">AI Model Training</p>
                <span className="text-xs px-2 py-1 bg-emerald-500/20 text-emerald-300 rounded border border-emerald-500/30">Active</span>
              </div>
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-emerald-500 to-emerald-400 rounded-full" style={{ width: '75%' }}></div>
              </div>
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-sm text-cyan-400/60">Threat Intelligence</p>
                <p className="text-sm font-semibold text-cyan-400">75%</p>
              </div>
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-yellow-500 to-orange-400 rounded-full" style={{ width: '75%' }}></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Timeline Chart */}
        <div className="card card-hover">
          <h3 className="text-xl font-semibold text-white glow-cyan mb-6">Threat Timeline (30 Days)</h3>
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.01}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="date" stroke="#64748b" />
              <YAxis stroke="#64748b" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1e293b', 
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  boxShadow: '0 0 20px rgba(6, 182, 212, 0.2)'
                }}
              />
              <Area 
                type="monotone" 
                dataKey="threats" 
                stroke="#06b6d4" 
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorThreats)"
                name="Threats Detected"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Risk Level Distribution */}
        <div className="card card-hover">
          <h3 className="text-xl font-semibold text-white glow-cyan mb-6">Risk Level Distribution</h3>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={riskLevelData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={90}
                fill="#8884d8"
                dataKey="value"
              >
                {riskLevelData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={COLORS[entry.name]} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1e293b', 
                  border: '1px solid #334155',
                  borderRadius: '8px'
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Attack Vector Breakdown */}
      {attackVectorData.length > 0 && (
        <div className="card card-hover">
          <h3 className="text-xl font-semibold text-white glow-cyan mb-6">Attack Vector Breakdown</h3>
          <div className="grid grid-cols-2 gap-4">
            {attackVectorData.map((vector, index) => (
              <div key={index} className="flex items-center justify-between p-5 bg-slate-800/50 rounded-xl border border-cyan-500/10">
                <span className="font-medium text-slate-300">{vector.name}</span>
                <span className="text-2xl font-bold text-cyan-400">{vector.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Update Status */}
      <div className="fixed bottom-8 right-8 bg-slate-900 border border-emerald-500/30 rounded-lg px-4 py-3 text-sm text-emerald-300 flex items-center gap-2">
        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
        <span>Update complete!</span>
      </div>
    </div>
  );
}

