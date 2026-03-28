import React, { useState, useEffect, useCallback } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, Legend,
} from 'recharts';

const CATEGORY_COLORS = { PII: '#22d3ee', PHI: '#ef4444', PCI: '#f59e0b', FINANCIAL: '#a855f7', IP_CODE: '#f43f5e', CUSTOM: '#64748b' };
const SURFACE_ICONS = {
  MCP: 'M13 10V3L4 14h7v7l9-11h-7z',
  A2A: 'M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4',
  LLM_API: 'M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z',
  RAG: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4',
};
const SEV_COLORS = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' };
const TOOLTIP_STYLE = { background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' };

function riskColor(score) {
  if (score >= 0.7) return 'bg-red-500/70';
  if (score >= 0.4) return 'bg-yellow-500/60';
  return 'bg-emerald-500/50';
}

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [entityDist, setEntityDist] = useState({ by_category: [], by_type: [] });
  const [riskHeatmap, setRiskHeatmap] = useState([]);
  const [agentActivity, setAgentActivity] = useState([]);
  const [surfaceActivity, setSurfaceActivity] = useState([]);
  const [threatSummary, setThreatSummary] = useState({ by_severity: [], trend: 'stable' });
  const [topEntities, setTopEntities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAll = useCallback(async () => {
    try {
      const endpoints = [
        '/api/dashboard/stats',
        '/api/dashboard/timeline',
        '/api/dashboard/entity-distribution',
        '/api/dashboard/risk-heatmap',
        '/api/dashboard/agent-activity',
        '/api/dashboard/surface-activity',
        '/api/dashboard/threat-summary',
        '/api/dashboard/top-entities',
      ];
      const results = await Promise.allSettled(endpoints.map((e) => fetch(e).then((r) => r.ok ? r.json() : Promise.reject())));
      const get = (i) => results[i].status === 'fulfilled' ? results[i].value : null;

      setStats(get(0) || { total_scans: 0, entities_protected: 0, active_sessions: 0, threats_blocked: 0, avg_latency_ms: 0, compliance_score: 0 });
      setTimeline(get(1) || []);
      setEntityDist(get(2) || { by_category: [], by_type: [] });
      const hm = get(3);
      setRiskHeatmap(Array.isArray(hm) ? hm : (hm?.cells || []));
      setAgentActivity(get(4) || []);
      setSurfaceActivity(get(5) || []);
      const ts = get(6) || {};
      setThreatSummary({ by_severity: ts.severity_distribution || ts.by_severity || [], trend: ts.trend || 'stable' });
      setTopEntities(get(7) || []);
      setError(null);
    } catch (err) {
      setError('Failed to fetch dashboard data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 30000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="flex flex-col items-center gap-4">
          <svg className="w-8 h-8 text-emerald-400 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <span className="text-slate-400">Loading dashboard...</span>
        </div>
      </div>
    );
  }

  const statCards = [
    { label: 'Total Scans', value: stats?.total_scans?.toLocaleString() || '0', color: 'text-emerald-400', bg: 'bg-emerald-500/10', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2' },
    { label: 'Entities Protected', value: stats?.entities_protected?.toLocaleString() || '0', color: 'text-cyan-400', bg: 'bg-cyan-500/10', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
    { label: 'Active Sessions', value: stats?.active_sessions || '0', color: 'text-purple-400', bg: 'bg-purple-500/10', icon: 'M15 12a3 3 0 11-6 0 3 3 0 016 0z' },
    { label: 'Threats Blocked', value: stats?.threats_blocked || '0', color: 'text-red-400', bg: 'bg-red-500/10', icon: 'M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
    { label: 'Avg Latency', value: `${stats?.avg_latency_ms || 0}ms`, color: 'text-amber-400', bg: 'bg-amber-500/10', icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
    { label: 'Compliance Score', value: `${stats?.compliance_score || 0}%`, color: 'text-emerald-400', bg: 'bg-emerald-500/10', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  ];

  // Derive unique entity types for heatmap columns
  const heatmapEntityTypes = [...new Set(riskHeatmap.flatMap((r) => Object.keys(r.entities || {})))];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <div className="flex items-center gap-2 text-sm text-slate-400">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Live -- refreshes every 30s
          {error && <span className="text-red-400 ml-3">{error}</span>}
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {statCards.map((s) => (
          <div key={s.label} className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-4 hover:border-emerald-500/30 transition-all duration-300 hover:scale-[1.02]">
            <div className="flex items-center gap-2 mb-2">
              <div className={`w-8 h-8 rounded-lg ${s.bg} flex items-center justify-center ${s.color}`}>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d={s.icon} />
                </svg>
              </div>
            </div>
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-400 mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Timeline + Entity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Entities Protected (Last 24h)</h3>
          {timeline.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <AreaChart data={timeline}>
                <defs>
                  {Object.entries(CATEGORY_COLORS).map(([cat, color]) => (
                    <linearGradient key={cat} id={`grad-${cat}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                      <stop offset="95%" stopColor={color} stopOpacity={0} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} />
                <YAxis tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                {Object.entries(CATEGORY_COLORS).map(([cat, color]) => (
                  <Area key={cat} type="monotone" dataKey={cat} stackId="1" stroke={color} fill={`url(#grad-${cat})`} strokeWidth={1.5} />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[280px] flex items-center justify-center text-slate-500 text-sm">No timeline data available</div>
          )}
        </div>

        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Entity Distribution</h3>
          {entityDist.by_category.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={entityDist.by_category} cx="50%" cy="50%" innerRadius={40} outerRadius={75} dataKey="count" nameKey="category" paddingAngle={2}>
                    {entityDist.by_category.map((d) => (
                      <Cell key={d.category} fill={CATEGORY_COLORS[d.category] || '#64748b'} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={TOOLTIP_STYLE} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1 mt-2">
                {entityDist.by_type?.slice(0, 8).map((d) => (
                  <div key={d.type} className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 truncate">{d.type}</span>
                    <span className="text-slate-300 font-mono">{d.count}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="h-[280px] flex items-center justify-center text-slate-500 text-sm">No entity data</div>
          )}
        </div>
      </div>

      {/* Risk Heatmap + Agent Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Heatmap */}
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Risk Heatmap</h3>
          {riskHeatmap.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr>
                    <th className="text-left py-2 px-2 text-slate-500 font-medium">Agent</th>
                    {heatmapEntityTypes.map((t) => (
                      <th key={t} className="text-center py-2 px-1 text-slate-500 font-medium">{t}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {riskHeatmap.map((row) => (
                    <tr key={row.agent_id} className="border-t border-slate-700/30">
                      <td className="py-2 px-2 text-slate-400 font-mono whitespace-nowrap">{row.agent_id}</td>
                      {heatmapEntityTypes.map((t) => {
                        const score = row.entities?.[t] ?? 0;
                        return (
                          <td key={t} className="py-2 px-1 text-center">
                            <div className={`w-6 h-6 mx-auto rounded ${riskColor(score)} flex items-center justify-center text-[10px] text-white font-mono`}>
                              {score > 0 ? score.toFixed(1) : ''}
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="h-40 flex items-center justify-center text-slate-500 text-sm">No risk data available</div>
          )}
        </div>

        {/* Agent Activity */}
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Agent Activity</h3>
          {agentActivity.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                    <th className="text-left py-2 font-medium">Agent</th>
                    <th className="text-right py-2 font-medium">Scans</th>
                    <th className="text-right py-2 font-medium">Entities</th>
                    <th className="text-right py-2 font-medium">Threats</th>
                  </tr>
                </thead>
                <tbody>
                  {[...agentActivity].sort((a, b) => (b.scans || 0) - (a.scans || 0)).map((a) => (
                    <tr key={a.agent_id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                      <td className="py-2 text-slate-300 font-mono text-xs">{a.agent_id}</td>
                      <td className="py-2 text-right text-emerald-400 font-mono">{a.scans}</td>
                      <td className="py-2 text-right text-cyan-400 font-mono">{a.entities}</td>
                      <td className="py-2 text-right text-red-400 font-mono">{a.threats}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="h-40 flex items-center justify-center text-slate-500 text-sm">No agent activity data</div>
          )}
        </div>
      </div>

      {/* Surface Activity */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Object.entries(SURFACE_ICONS).map(([surface]) => {
          const raw = surfaceActivity.find((s) => s.surface === surface) || {};
          const data = { count: raw.total_intercepts || raw.count || 0, blocked: raw.blocked || 0, tokenized: raw.tokenized || 0, passed: raw.logged || raw.passed || 0 };
          return (
            <div key={surface} className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5 hover:border-emerald-500/30 transition-all duration-300 hover:scale-[1.02]">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d={SURFACE_ICONS[surface]} />
                  </svg>
                </div>
                <div>
                  <div className="text-sm font-semibold text-white">{surface.replace('_', ' ')}</div>
                  <div className="text-xs text-slate-500">{data.count} total</div>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center">
                <div>
                  <div className="text-sm font-bold text-red-400">{data.blocked}</div>
                  <div className="text-[10px] text-slate-500">Blocked</div>
                </div>
                <div>
                  <div className="text-sm font-bold text-amber-400">{data.tokenized}</div>
                  <div className="text-[10px] text-slate-500">Tokenized</div>
                </div>
                <div>
                  <div className="text-sm font-bold text-emerald-400">{data.passed}</div>
                  <div className="text-[10px] text-slate-500">Passed</div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Threat Summary + Top Entities */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Summary */}
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-300">Threat Summary</h3>
            <span className={`text-xs px-2 py-1 rounded-full ${
              threatSummary.trend === 'increasing' ? 'bg-red-500/10 text-red-400' :
              threatSummary.trend === 'decreasing' ? 'bg-emerald-500/10 text-emerald-400' :
              'bg-slate-700/50 text-slate-400'
            }`}>
              {threatSummary.trend === 'increasing' ? 'Trending Up' : threatSummary.trend === 'decreasing' ? 'Trending Down' : 'Stable'}
            </span>
          </div>
          {threatSummary.by_severity?.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={threatSummary.by_severity} cx="50%" cy="50%" innerRadius={35} outerRadius={70} dataKey="count" nameKey="severity" paddingAngle={3}>
                  {threatSummary.by_severity.map((d) => (
                    <Cell key={d.severity} fill={SEV_COLORS[d.severity] || '#64748b'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Legend formatter={(v) => <span className="text-xs text-slate-400">{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[200px] flex items-center justify-center text-slate-500 text-sm">No threat data</div>
          )}
        </div>

        {/* Top Entities */}
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Top 10 Entity Types</h3>
          {topEntities.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={topEntities.slice(0, 10)} layout="vertical" margin={{ left: 80 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} />
                <YAxis type="category" dataKey="type" tick={{ fill: '#94a3b8', fontSize: 11 }} width={75} />
                <Tooltip contentStyle={TOOLTIP_STYLE} />
                <Bar dataKey="count" fill="#10b981" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[260px] flex items-center justify-center text-slate-500 text-sm">No entity data</div>
          )}
        </div>
      </div>
    </div>
  );
}
