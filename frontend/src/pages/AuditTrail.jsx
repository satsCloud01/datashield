import React, { useState, useEffect, useCallback } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, PieChart, Pie, Cell, Legend
} from 'recharts';

const EVENT_TYPES = ['ENTITY_PROTECTED', 'VAULT_WRITE', 'VAULT_READ', 'POLICY_VIOLATION', 'SEMANTIC_BLOCK'];
const TOOLTIP_STYLE = { background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' };
const TYPE_COLORS = {
  ENTITY_PROTECTED: 'text-emerald-400 bg-emerald-500/10',
  VAULT_WRITE: 'text-cyan-400 bg-cyan-500/10',
  VAULT_READ: 'text-blue-400 bg-blue-500/10',
  POLICY_VIOLATION: 'text-red-400 bg-red-500/10',
  SEMANTIC_BLOCK: 'text-amber-400 bg-amber-500/10',
};
const PIE_COLORS = ['#10b981', '#22d3ee', '#3b82f6', '#ef4444', '#f59e0b', '#a855f7', '#f472b6'];

export default function AuditTrail() {
  const [stats, setStats] = useState(null);
  const [verification, setVerification] = useState(null);
  const [chainEvents, setChainEvents] = useState([]);
  const [events, setEvents] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [filterType, setFilterType] = useState('ALL');
  const [filterAgent, setFilterAgent] = useState('');
  const [filterSession, setFilterSession] = useState('');
  const [filterEntityType, setFilterEntityType] = useState('');
  const [filterDateFrom, setFilterDateFrom] = useState('');
  const [filterDateTo, setFilterDateTo] = useState('');
  const [page, setPage] = useState(1);

  // Detail modal
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Session audit
  const [sessionId, setSessionId] = useState('');
  const [sessionEvents, setSessionEvents] = useState([]);
  const [sessionLoading, setSessionLoading] = useState(false);

  // Verify loading
  const [verifying, setVerifying] = useState(false);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch('/api/audit/stats');
      if (res.ok) setStats(await res.json());
    } catch { setError('Failed to load audit stats'); }
  }, []);

  const fetchVerification = useCallback(async () => {
    try {
      const res = await fetch('/api/audit/verify');
      if (res.ok) setVerification(await res.json());
    } catch {}
  }, []);

  const fetchEvents = useCallback(async () => {
    const params = new URLSearchParams({ page: String(page), limit: '25' });
    if (filterType !== 'ALL') params.set('event_type', filterType);
    if (filterAgent) params.set('agent', filterAgent);
    if (filterSession) params.set('session_id', filterSession);
    if (filterEntityType) params.set('entity_type', filterEntityType);
    if (filterDateFrom) params.set('date_from', filterDateFrom);
    if (filterDateTo) params.set('date_to', filterDateTo);
    try {
      const res = await fetch(`/api/audit/events?${params}`);
      if (res.ok) {
        const d = await res.json();
        setEvents(d.events || d.items || []);
        setTotalCount(d.total || d.count || 0);
        if (d.events && d.events.length > 0) setChainEvents(d.events.slice(0, 8));
      }
    } catch { setError('Failed to load audit events'); }
  }, [page, filterType, filterAgent, filterSession, filterEntityType, filterDateFrom, filterDateTo]);

  const fetchAgents = useCallback(async () => {
    try {
      const res = await fetch('/api/audit/agents');
      if (res.ok) setAgents(await res.json());
    } catch {}
  }, []);

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchStats(), fetchVerification(), fetchEvents(), fetchAgents()])
      .finally(() => setLoading(false));
  }, [fetchStats, fetchVerification, fetchEvents, fetchAgents]);

  const handleReVerify = async () => {
    setVerifying(true);
    try {
      const res = await fetch('/api/audit/verify');
      if (res.ok) setVerification(await res.json());
    } catch {}
    setVerifying(false);
  };

  const handleSessionAudit = async () => {
    if (!sessionId.trim()) return;
    setSessionLoading(true);
    try {
      const res = await fetch(`/api/audit/sessions/${sessionId.trim()}`);
      if (res.ok) {
        const d = await res.json();
        setSessionEvents(d.events || d || []);
      }
    } catch {}
    setSessionLoading(false);
  };

  const handleExport = async () => {
    const params = new URLSearchParams();
    if (filterType !== 'ALL') params.set('event_type', filterType);
    if (filterAgent) params.set('agent', filterAgent);
    if (filterSession) params.set('session_id', filterSession);
    try {
      const res = await fetch(`/api/audit/export?${params}`);
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-export-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {}
  };

  const byTypeData = stats?.by_type
    ? Object.entries(stats.by_type).map(([name, count]) => ({ name, count }))
    : [];

  const byHourData = stats?.by_hour || [];

  const byEntityData = stats?.by_entity_type
    ? Object.entries(stats.by_entity_type).map(([name, value]) => ({ name, value }))
    : [];

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Audit Trail</h1>
        <button onClick={handleExport}
          className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          Export Audit Log
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{error}
          <button onClick={() => setError(null)} className="ml-3 text-red-300 hover:text-white">Dismiss</button>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {[
          { label: 'Total Events', value: stats?.total_events ?? '-', color: 'text-white' },
          { label: 'Unique Agents', value: stats?.unique_agents ?? '-', color: 'text-cyan-400' },
          { label: 'Unique Sessions', value: stats?.unique_sessions ?? '-', color: 'text-emerald-400' },
          { label: 'Avg Latency', value: stats?.avg_latency ? `${stats.avg_latency.toFixed(1)}ms` : '-', color: 'text-amber-400' },
          { label: 'Peak Hour', value: stats?.peak_hour ?? '-', color: 'text-slate-300' },
        ].map((m) => (
          <div key={m.label} className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-4">
            <div className={`text-2xl font-bold ${m.color}`}>{m.value}</div>
            <div className="text-xs text-slate-500 mt-1">{m.label}</div>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Events by Type</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={byTypeData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 9 }} angle={-25} textAnchor="end" height={60} />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Events Over Time</h3>
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={byHourData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Line type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Events by Entity Type</h3>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={byEntityData} cx="50%" cy="50%" innerRadius={40} outerRadius={75} dataKey="value" paddingAngle={2}>
                {byEntityData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={TOOLTIP_STYLE} />
              <Legend formatter={(v) => <span className="text-[10px] text-slate-400">{v}</span>} />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Hash Chain Verification Banner */}
      {verification && (
        <div className={`rounded-xl p-4 border flex items-center justify-between ${
          verification.verified
            ? 'bg-emerald-500/5 border-emerald-500/20'
            : 'bg-red-500/5 border-red-500/20'
        }`}>
          <div className="flex items-center gap-3">
            {verification.verified ? (
              <svg className="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            ) : (
              <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            )}
            <div>
              <div className={`text-sm font-semibold ${verification.verified ? 'text-emerald-400' : 'text-red-400'}`}>
                {verification.verified
                  ? `Hash Chain Verified -- ${verification.chain_length || 0} events, integrity intact`
                  : `Hash Chain BROKEN -- ${verification.broken_at || 'unknown link'}`}
              </div>
              {verification.verification_time && (
                <div className="text-xs text-slate-500">Verified at {new Date(verification.verification_time).toLocaleString()}</div>
              )}
            </div>
          </div>
          <button onClick={handleReVerify} disabled={verifying}
            className="px-4 py-1.5 rounded-lg bg-slate-800/50 border border-slate-700/50 text-sm text-slate-300 hover:text-white transition-colors disabled:opacity-50">
            {verifying ? 'Verifying...' : 'Re-verify'}
          </button>
        </div>
      )}

      {/* Hash Chain Visualization */}
      {chainEvents.length > 0 && (
        <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Hash Chain Visualization</h3>
          <div className="flex items-center gap-1 overflow-x-auto pb-2">
            {chainEvents.slice(0, 8).map((e, i) => (
              <React.Fragment key={e.id || e.event_id || i}>
                <div className={`flex-shrink-0 p-3 rounded-lg border min-w-[150px] ${
                  verification?.verified !== false ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-red-500/5 border-red-500/20'
                }`}>
                  <div className="text-[10px] text-slate-400 font-mono truncate">{(e.event_id || e.id || '').slice(0, 12)}</div>
                  <div className="text-[9px] text-emerald-400 font-mono mt-1 truncate">hash: {(e.hash || '').slice(0, 16)}...</div>
                </div>
                {i < Math.min(chainEvents.length, 8) - 1 && (
                  <svg className="w-5 h-5 text-emerald-500/40 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M10 6l6 6-6 6V6z" />
                  </svg>
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {/* Events Table */}
      <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-5">
        <h3 className="text-lg font-semibold text-white mb-4">Events</h3>
        {/* Filters */}
        <div className="flex items-center gap-3 mb-4 flex-wrap">
          <select value={filterType} onChange={(e) => { setFilterType(e.target.value); setPage(1); }}
            className="bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none">
            <option value="ALL">All Types</option>
            {EVENT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input value={filterAgent} onChange={(e) => { setFilterAgent(e.target.value); setPage(1); }}
            placeholder="Agent search..." className="bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500/50 w-36" />
          <input value={filterSession} onChange={(e) => { setFilterSession(e.target.value); setPage(1); }}
            placeholder="Session ID..." className="bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500/50 w-36" />
          <input value={filterEntityType} onChange={(e) => { setFilterEntityType(e.target.value); setPage(1); }}
            placeholder="Entity type..." className="bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-emerald-500/50 w-32" />
          <input type="date" value={filterDateFrom} onChange={(e) => { setFilterDateFrom(e.target.value); setPage(1); }}
            className="bg-slate-900/50 border border-slate-700/50 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none" />
          <input type="date" value={filterDateTo} onChange={(e) => { setFilterDateTo(e.target.value); setPage(1); }}
            className="bg-slate-900/50 border border-slate-700/50 rounded-lg px-2 py-1.5 text-xs text-white focus:outline-none" />
          <span className="text-xs text-slate-500 ml-auto">{totalCount} events</span>
        </div>

        <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-slate-800/90 backdrop-blur">
              <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                <th className="text-left py-2 px-2 font-medium">Time</th>
                <th className="text-left py-2 px-2 font-medium">Event ID</th>
                <th className="text-left py-2 px-2 font-medium">Type</th>
                <th className="text-left py-2 px-2 font-medium">Agent</th>
                <th className="text-left py-2 px-2 font-medium">Session</th>
                <th className="text-left py-2 px-2 font-medium">Entities</th>
                <th className="text-left py-2 px-2 font-medium">Latency</th>
                <th className="text-left py-2 px-2 font-medium">Hash</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id || e.event_id} className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer"
                  onClick={() => setSelectedEvent(e)}>
                  <td className="py-2 px-2 text-slate-500 text-xs">{new Date(e.timestamp).toLocaleString()}</td>
                  <td className="py-2 px-2 text-slate-400 font-mono text-xs">{(e.event_id || e.id || '').slice(0, 12)}</td>
                  <td className="py-2 px-2"><span className={`text-xs px-2 py-0.5 rounded-full ${TYPE_COLORS[e.event_type] || 'text-slate-400 bg-slate-700/50'}`}>{e.event_type}</span></td>
                  <td className="py-2 px-2 text-slate-300 font-mono text-xs">{e.agent_id || e.agent}</td>
                  <td className="py-2 px-2 text-slate-500 font-mono text-[10px]">{(e.session_id || '').slice(0, 12)}</td>
                  <td className="py-2 px-2 text-slate-300 text-xs">{typeof e.entities === 'object' ? JSON.stringify(e.entities).slice(0, 30) : (e.entities_count || '-')}</td>
                  <td className="py-2 px-2 text-emerald-400 text-xs">{e.latency_ms ? `${e.latency_ms}ms` : '-'}</td>
                  <td className="py-2 px-2 text-slate-500 font-mono text-[10px]">{(e.hash || '').slice(0, 16)}</td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr><td colSpan={8} className="py-12 text-center text-slate-500">No events found</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between mt-4">
          <span className="text-xs text-slate-500">{totalCount} total</span>
          <div className="flex gap-2">
            <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}
              className="px-3 py-1 text-xs rounded-lg bg-slate-700/50 text-slate-300 disabled:opacity-30 hover:bg-slate-700">Prev</button>
            <span className="text-xs text-slate-400 self-center">Page {page}</span>
            <button onClick={() => setPage((p) => p + 1)} disabled={events.length < 25}
              className="px-3 py-1 text-xs rounded-lg bg-slate-700/50 text-slate-300 disabled:opacity-30 hover:bg-slate-700">Next</button>
          </div>
        </div>
      </div>

      {/* Agent Summary */}
      {agents.length > 0 && (
        <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-5">
          <h3 className="text-lg font-semibold text-white mb-4">Agent Summary</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                  <th className="text-left py-2 px-2 font-medium">Agent ID</th>
                  <th className="text-left py-2 px-2 font-medium">Event Count</th>
                  <th className="text-left py-2 px-2 font-medium">Last Active</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.agent_id || a.id} className="border-b border-slate-800/50">
                    <td className="py-2 px-2 text-slate-300 font-mono text-xs">{a.agent_id || a.id}</td>
                    <td className="py-2 px-2 text-emerald-400 text-xs">{a.event_count || a.count}</td>
                    <td className="py-2 px-2 text-slate-500 text-xs">{a.last_active ? new Date(a.last_active).toLocaleString() : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Session Audit */}
      <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-5">
        <h3 className="text-lg font-semibold text-white mb-4">Session Audit</h3>
        <div className="flex gap-3 mb-4">
          <input value={sessionId} onChange={(e) => setSessionId(e.target.value)}
            placeholder="Enter session ID..."
            className="flex-1 bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50 font-mono" />
          <button onClick={handleSessionAudit} disabled={sessionLoading || !sessionId.trim()}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-700 text-white rounded-lg text-sm font-medium transition-all">
            {sessionLoading ? 'Loading...' : 'Lookup'}
          </button>
        </div>
        {sessionEvents.length > 0 && (
          <div className="space-y-2">
            {sessionEvents.map((e, i) => (
              <div key={e.id || e.event_id || i} className="flex items-start gap-3">
                <div className="flex flex-col items-center">
                  <div className="w-3 h-3 rounded-full bg-emerald-500 border-2 border-slate-800" />
                  {i < sessionEvents.length - 1 && <div className="w-0.5 h-8 bg-slate-700" />}
                </div>
                <div className="flex-1 p-3 rounded-lg bg-slate-900/50 border border-slate-700/30">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${TYPE_COLORS[e.event_type] || 'text-slate-400 bg-slate-700/50'}`}>{e.event_type}</span>
                    <span className="text-xs text-slate-500">{new Date(e.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="text-xs text-slate-400">Agent: <span className="text-slate-300 font-mono">{e.agent_id || e.agent}</span></div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Event Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm" onClick={() => setSelectedEvent(null)}>
          <div className="bg-slate-800/90 border border-slate-700 rounded-xl p-6 max-w-lg w-full mx-4 space-y-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">{selectedEvent.event_id || selectedEvent.id}</h3>
              <button onClick={() => setSelectedEvent(null)} className="text-slate-400 hover:text-white">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
            <div className="grid grid-cols-2 gap-4">
              {[
                ['Event Type', selectedEvent.event_type],
                ['Agent', selectedEvent.agent_id || selectedEvent.agent],
                ['Session', selectedEvent.session_id],
                ['Latency', selectedEvent.latency_ms ? `${selectedEvent.latency_ms}ms` : '-'],
                ['Policy', selectedEvent.policy_id],
                ['Source IP', selectedEvent.source_ip],
                ['Target Service', selectedEvent.target_service],
              ].filter(([, v]) => v).map(([label, val]) => (
                <div key={label}>
                  <div className="text-xs text-slate-500">{label}</div>
                  <div className="text-sm text-white font-mono mt-0.5 break-all">{val}</div>
                </div>
              ))}
            </div>
            <div>
              <div className="text-xs text-slate-500 mb-1">Hash</div>
              <div className="text-xs text-emerald-400 font-mono break-all">{selectedEvent.hash}</div>
            </div>
            {selectedEvent.prev_hash && (
              <div>
                <div className="text-xs text-slate-500 mb-1">Previous Hash</div>
                <div className="text-xs text-slate-500 font-mono break-all">{selectedEvent.prev_hash}</div>
              </div>
            )}
            {selectedEvent.entities && (
              <div>
                <div className="text-xs text-slate-500 mb-1">Entities</div>
                <pre className="text-xs text-slate-300 font-mono bg-slate-900/50 rounded p-2 overflow-auto max-h-40">
                  {typeof selectedEvent.entities === 'string' ? selectedEvent.entities : JSON.stringify(selectedEvent.entities, null, 2)}
                </pre>
              </div>
            )}
            <div>
              <div className="text-xs text-slate-500 mb-1">Timestamp</div>
              <div className="text-sm text-white">{new Date(selectedEvent.timestamp).toLocaleString()}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
