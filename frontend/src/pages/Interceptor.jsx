import React, { useState, useEffect, useCallback } from 'react';
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const SURFACES = [
  { id: 'MCP', label: 'MCP', desc: 'Model Context Protocol — intercepts tool calls and context injections between agents and LLM providers.', guide: 'Add the DataShield MCP interceptor as a middleware in your MCP server chain. All tool_call and tool_result messages will be scanned.' },
  { id: 'A2A', label: 'A2A', desc: 'Agent-to-Agent Protocol — monitors and sanitizes inter-agent communication payloads.', guide: 'Configure agent discovery to route through the DataShield A2A proxy. Supports JSON-RPC and REST envelopes.' },
  { id: 'LLM_API', label: 'LLM API', desc: 'Direct LLM API calls — scans prompts and completions for PII leakage in real-time.', guide: 'Replace your LLM base URL with the DataShield proxy endpoint. Supports OpenAI, Anthropic, and Google formats.' },
  { id: 'RAG', label: 'RAG', desc: 'Retrieval-Augmented Generation — inspects retrieved context chunks before injection into prompts.', guide: 'Wrap your retrieval pipeline with the DataShield RAG interceptor. Scans all retrieved documents before prompt assembly.' },
];

const ACTION_COLORS = {
  BLOCKED: 'text-red-400 bg-red-500/10',
  TOKENIZED: 'text-amber-400 bg-amber-500/10',
  PASSED: 'text-emerald-400 bg-emerald-500/10',
  FLAGGED: 'text-yellow-400 bg-yellow-500/10',
};

const DIRECTION_COLORS = {
  INBOUND: 'text-cyan-400 bg-cyan-500/10',
  OUTBOUND: 'text-purple-400 bg-purple-500/10',
};

const Spinner = () => (
  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
  </svg>
);

function generateMockLogs(surface, count = 10) {
  const actions = ['BLOCKED', 'TOKENIZED', 'PASSED'];
  const directions = ['INBOUND', 'OUTBOUND'];
  const agents = ['agent-mcp-001', 'agent-a2a-003', 'agent-rag-007', 'agent-llm-012', 'agent-tool-005'];
  const entities = ['SSN', 'EMAIL', 'CREDIT_CARD', 'PERSON_NAME', 'PHONE', 'API_KEY', 'DOB'];
  return Array.from({ length: count }, (_, i) => ({
    id: `int-${surface.toLowerCase()}-${1000 + i}`,
    timestamp: new Date(Date.now() - Math.random() * 7200000).toISOString(),
    surface,
    agent_id: agents[Math.floor(Math.random() * agents.length)],
    direction: directions[Math.floor(Math.random() * 2)],
    entities_found: Math.floor(Math.random() * 8) + 1,
    entity_types: Array.from(new Set(Array.from({ length: Math.floor(Math.random() * 3) + 1 }, () => entities[Math.floor(Math.random() * entities.length)]))),
    action: actions[Math.floor(Math.random() * actions.length)],
    latency_ms: +(Math.random() * 4 + 0.5).toFixed(1),
    payload_preview: '{"message": "...sensitive data..."}',
  }));
}

function generateMockHourlyData() {
  return Array.from({ length: 24 }, (_, i) => ({
    hour: `${String(i).padStart(2, '0')}:00`,
    blocked: Math.floor(Math.random() * 50) + 5,
    tokenized: Math.floor(Math.random() * 200) + 50,
    passed: Math.floor(Math.random() * 150) + 30,
  }));
}

export default function Interceptor() {
  const [tab, setTab] = useState('MCP');
  const [logs, setLogs] = useState({});
  const [stats, setStats] = useState(null);
  const [surfaceStats, setSurfaceStats] = useState([]);
  const [hourlyData, setHourlyData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedRow, setExpandedRow] = useState(null);

  // Simulator
  const [showSimulator, setShowSimulator] = useState(false);
  const [simSurface, setSimSurface] = useState('MCP');
  const [simAgent, setSimAgent] = useState('agent-test-001');
  const [simRole, setSimRole] = useState('loan-processor');
  const [simPayload, setSimPayload] = useState('{"message": "Transfer $50,000 to John Doe, account 9876543210, SSN 123-45-6789, email john@bank.com"}');
  const [simPolicyId, setSimPolicyId] = useState('');
  const [simResult, setSimResult] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [policies, setPolicies] = useState([]);

  // Batch
  const [showBatch, setShowBatch] = useState(false);
  const [batchPayloads, setBatchPayloads] = useState('{"msg": "SSN 111-22-3333"}\n{"msg": "Call Jane at jane@corp.com"}\n{"msg": "Card 4111-1111-1111-1111"}');
  const [batchResults, setBatchResults] = useState(null);
  const [batchRunning, setBatchRunning] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    // Fetch stats
    try {
      const res = await fetch('/api/interceptor/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data.totals || data);
        setSurfaceStats(data.by_surface || []);
        setHourlyData(data.by_hour || []);
      } else throw new Error();
    } catch {
      setStats({ total: 13116, blocked: 666, tokenized: 8783, passed: 3667 });
      setSurfaceStats([
        { surface: 'MCP', blocked: 189, tokenized: 2156, passed: 1076 },
        { surface: 'A2A', blocked: 98, tokenized: 1534, passed: 555 },
        { surface: 'LLM_API', blocked: 312, tokenized: 3890, passed: 1430 },
        { surface: 'RAG', blocked: 67, tokenized: 1203, passed: 606 },
      ]);
      setHourlyData(generateMockHourlyData());
    }

    // Fetch logs
    try {
      const res = await fetch('/api/interceptor/logs');
      if (res.ok) { const data = await res.json(); setLogs(data); }
      else throw new Error();
    } catch {
      const l = {};
      for (const s of SURFACES) l[s.id] = generateMockLogs(s.id);
      setLogs(l);
    }

    // Fetch policies for simulator dropdown
    try {
      const res = await fetch('/api/policies');
      if (res.ok) { const data = await res.json(); setPolicies(data); if (data.length > 0) setSimPolicyId(data[0].id); }
    } catch {
      setPolicies([{ id: 'pol-001', name: 'BFSI Default' }, { id: 'pol-002', name: 'Healthcare HIPAA' }, { id: 'pol-003', name: 'Strict Lockdown' }]);
      setSimPolicyId('pol-001');
    }

    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleSimulate = async () => {
    setSimulating(true);
    setSimResult(null);
    try {
      const res = await fetch('/api/interceptor/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ surface: simSurface, agent_id: simAgent, agent_role: simRole, payload: simPayload, policy_id: simPolicyId }),
      });
      if (res.ok) { setSimResult(await res.json()); setSimulating(false); return; }
    } catch {}
    await new Promise((r) => setTimeout(r, 600));
    setSimResult({
      action: 'TOKENIZED',
      entities: [
        { value: 'John Doe', type: 'PERSON_NAME', confidence: 0.94 },
        { value: '9876543210', type: 'BANK_ACCOUNT', confidence: 0.91 },
        { value: '123-45-6789', type: 'SSN', confidence: 0.98 },
        { value: 'john@bank.com', type: 'EMAIL', confidence: 0.96 },
      ],
      policy_decisions: ['SSN -> tokenize (PCI_DSS)', 'BANK_ACCOUNT -> tokenize (SOX)', 'PERSON_NAME -> mask (GDPR)', 'EMAIL -> tokenize (GDPR)'],
      sanitized_payload: simPayload.replace('John Doe', '<<PERSON_NAME_X1>>').replace('9876543210', '<<BANK_ACCOUNT_X1>>').replace('123-45-6789', '<<SSN_X1>>').replace('john@bank.com', '<<EMAIL_X1>>'),
      risk_score: 78,
      recommendation: 'High PII density detected. Consider enabling strict mode for financial payloads. 4 entities across 4 categories were found in a single message.',
      latency_ms: +(Math.random() * 3 + 1).toFixed(1),
    });
    setSimulating(false);
  };

  const handleBatch = async () => {
    setBatchRunning(true);
    setBatchResults(null);
    const payloads = batchPayloads.split('\n').filter((l) => l.trim());
    try {
      const res = await fetch('/api/interceptor/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payloads, policy_id: simPolicyId }),
      });
      if (res.ok) { setBatchResults(await res.json()); setBatchRunning(false); return; }
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
    setBatchResults(payloads.map((p, i) => ({
      index: i,
      payload: p.length > 60 ? p.slice(0, 60) + '...' : p,
      entities_found: Math.floor(Math.random() * 4) + 1,
      action: ['TOKENIZED', 'BLOCKED', 'TOKENIZED'][i % 3],
      latency_ms: +(Math.random() * 3 + 0.5).toFixed(1),
    })));
    setBatchRunning(false);
  };

  const currentSurface = SURFACES.find((s) => s.id === tab);
  const filteredLogs = logs[tab] || [];

  const riskColor = (score) => {
    if (score >= 75) return 'text-red-400';
    if (score >= 50) return 'text-amber-400';
    return 'text-emerald-400';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Agentic Pipeline Interceptor</h1>
          <p className="text-slate-400 text-sm mt-1">Monitor and control PII flow across all agentic communication surfaces.</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => { setShowBatch(!showBatch); setShowSimulator(false); }} className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all border ${showBatch ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-slate-700 text-slate-300 border-slate-600 hover:bg-slate-600'}`}>
            Batch Test
          </button>
          <button onClick={() => { setShowSimulator(!showSimulator); setShowBatch(false); }} className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all border ${showSimulator ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-slate-700 text-slate-300 border-slate-600 hover:bg-slate-600'}`}>
            Simulator
          </button>
        </div>
      </div>

      {/* Stats Overview */}
      {loading ? (
        <div className="flex items-center justify-center py-8"><Spinner /><span className="ml-2 text-slate-500 text-sm">Loading interceptor data...</span></div>
      ) : (
        <>
          {stats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Total Interceptions', value: stats.total, color: 'text-white' },
                { label: 'Blocked', value: stats.blocked, color: 'text-red-400' },
                { label: 'Tokenized', value: stats.tokenized, color: 'text-amber-400' },
                { label: 'Passed', value: stats.passed, color: 'text-emerald-400' },
              ].map((m) => (
                <div key={m.label} className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-4">
                  <div className="text-xs text-slate-500">{m.label}</div>
                  <div className={`text-2xl font-bold ${m.color}`}>{m.value?.toLocaleString()}</div>
                </div>
              ))}
            </div>
          )}

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4">By Surface</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={surfaceStats}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="surface" tick={{ fill: '#64748b', fontSize: 12 }} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' }} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
                  <Bar dataKey="blocked" fill="#ef4444" radius={[4, 4, 0, 0]} name="Blocked" />
                  <Bar dataKey="tokenized" fill="#f59e0b" radius={[4, 4, 0, 0]} name="Tokenized" />
                  <Bar dataKey="passed" fill="#10b981" radius={[4, 4, 0, 0]} name="Passed" />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4">By Hour (24h)</h3>
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={hourlyData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="hour" tick={{ fill: '#64748b', fontSize: 10 }} interval={3} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' }} />
                  <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
                  <Line type="monotone" dataKey="blocked" stroke="#ef4444" strokeWidth={2} dot={false} name="Blocked" />
                  <Line type="monotone" dataKey="tokenized" stroke="#f59e0b" strokeWidth={2} dot={false} name="Tokenized" />
                  <Line type="monotone" dataKey="passed" stroke="#10b981" strokeWidth={2} dot={false} name="Passed" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Flow Diagram */}
          <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Interception Flow</h3>
            <div className="flex items-center justify-center gap-1 flex-wrap">
              {[
                { step: 'Agent Request', icon: 'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z', color: 'border-cyan-500/30 bg-cyan-500/5' },
                { step: 'Interceptor Captures', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z', color: 'border-amber-500/30 bg-amber-500/5' },
                { step: 'Detection Scans', icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z', color: 'border-purple-500/30 bg-purple-500/5' },
                { step: 'Policy Evaluates', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', color: 'border-emerald-500/30 bg-emerald-500/5' },
                { step: 'Vault Tokenizes', icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z', color: 'border-blue-500/30 bg-blue-500/5' },
                { step: 'Sanitized Forward', icon: 'M13 7l5 5m0 0l-5 5m5-5H6', color: 'border-emerald-500/30 bg-emerald-500/5' },
              ].map((s, i) => (
                <React.Fragment key={s.step}>
                  <div className={`px-4 py-3 rounded-lg border text-center min-w-[120px] ${s.color}`}>
                    <svg className="w-5 h-5 mx-auto mb-1 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d={s.icon} /></svg>
                    <div className="text-xs text-slate-300 font-medium">{s.step}</div>
                  </div>
                  {i < 5 && <svg className="w-5 h-5 text-emerald-500/40 flex-shrink-0" fill="currentColor" viewBox="0 0 24 24"><path d="M10 6l6 6-6 6V6z" /></svg>}
                </React.Fragment>
              ))}
            </div>
          </div>

          {/* Surface Tabs + Logs */}
          <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
            <div className="flex gap-1 mb-4 bg-slate-900/50 rounded-lg p-1 w-fit">
              {SURFACES.map((s) => (
                <button
                  key={s.id}
                  onClick={() => { setTab(s.id); setExpandedRow(null); }}
                  className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${tab === s.id ? 'bg-emerald-500/20 text-emerald-400' : 'text-slate-400 hover:text-white'}`}
                >
                  {s.label}
                </button>
              ))}
            </div>

            {currentSurface && (
              <div className="mb-4 p-3 rounded-lg bg-slate-900/30 border border-slate-700/30">
                <p className="text-sm text-slate-300">{currentSurface.desc}</p>
                <p className="text-xs text-slate-500 mt-1">{currentSurface.guide}</p>
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                    <th className="text-left py-2 font-medium">Time</th>
                    <th className="text-left py-2 font-medium">Surface</th>
                    <th className="text-left py-2 font-medium">Agent</th>
                    <th className="text-left py-2 font-medium">Direction</th>
                    <th className="text-left py-2 font-medium">Entities</th>
                    <th className="text-left py-2 font-medium">Action</th>
                    <th className="text-left py-2 font-medium">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.length === 0 ? (
                    <tr><td colSpan={7} className="py-8 text-center text-slate-500 text-sm">No interception logs for this surface.</td></tr>
                  ) : filteredLogs.map((log) => (
                    <React.Fragment key={log.id}>
                      <tr
                        onClick={() => setExpandedRow(expandedRow === log.id ? null : log.id)}
                        className="border-b border-slate-800/50 hover:bg-slate-700/20 cursor-pointer"
                      >
                        <td className="py-2 text-slate-500 text-xs">{new Date(log.timestamp).toLocaleTimeString()}</td>
                        <td className="py-2"><span className="text-xs px-2 py-0.5 rounded bg-slate-700/50 text-slate-300">{log.surface || tab}</span></td>
                        <td className="py-2 text-slate-300 font-mono text-xs">{log.agent_id}</td>
                        <td className="py-2">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${DIRECTION_COLORS[log.direction] || 'text-slate-400 bg-slate-700/50'}`}>
                            {log.direction || 'INBOUND'}
                          </span>
                        </td>
                        <td className="py-2">
                          <div className="flex items-center gap-1">
                            <span className="text-slate-300 text-xs">{log.entities_found}</span>
                            <div className="flex gap-0.5 flex-wrap">
                              {(log.entity_types || []).slice(0, 3).map((t, i) => (
                                <span key={i} className="text-[10px] px-1 py-0.5 rounded bg-slate-700/50 text-slate-500">{t}</span>
                              ))}
                            </div>
                          </div>
                        </td>
                        <td className="py-2"><span className={`text-xs px-2 py-0.5 rounded-full font-medium ${ACTION_COLORS[log.action] || ''}`}>{log.action}</span></td>
                        <td className="py-2 text-emerald-400 text-xs">{log.latency_ms}ms</td>
                      </tr>
                      {expandedRow === log.id && (
                        <tr>
                          <td colSpan={7} className="py-3 px-4">
                            <div className="bg-slate-950 rounded-lg p-3 text-xs text-slate-400 font-mono">
                              <div className="text-slate-500 mb-1">Payload preview:</div>
                              {log.payload_preview || '{"message": "..."}'}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Simulator Panel */}
          {showSimulator && (
            <div className="bg-slate-800/70 backdrop-blur-sm border border-emerald-500/30 rounded-xl p-5 space-y-4">
              <h3 className="text-sm font-semibold text-emerald-400">Interception Simulator</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div>
                  <label className="text-xs text-slate-500 block mb-1">Surface</label>
                  <select value={simSurface} onChange={(e) => setSimSurface(e.target.value)} className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50">
                    {SURFACES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-500 block mb-1">Agent ID</label>
                  <input value={simAgent} onChange={(e) => setSimAgent(e.target.value)} className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50" />
                </div>
                <div>
                  <label className="text-xs text-slate-500 block mb-1">Agent Role</label>
                  <select value={simRole} onChange={(e) => setSimRole(e.target.value)} className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50">
                    {['loan-processor', 'kyc-agent', 'fraud-detector', 'triage-agent', 'records-agent', 'billing-agent', 'general'].map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-500 block mb-1">Policy</label>
                  <select value={simPolicyId} onChange={(e) => setSimPolicyId(e.target.value)} className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50">
                    {policies.map((p) => <option key={p.id} value={p.id}>{p.name || p.id}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label className="text-xs text-slate-500 block mb-1">Payload</label>
                <textarea value={simPayload} onChange={(e) => setSimPayload(e.target.value)} className="w-full h-24 bg-slate-900/50 border border-slate-700/50 rounded-lg p-3 text-sm text-slate-300 font-mono resize-none focus:outline-none focus:border-emerald-500/50" />
              </div>
              <button
                onClick={handleSimulate}
                disabled={simulating || !simPayload.trim()}
                className="px-6 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2"
              >
                {simulating ? <><Spinner /> Simulating...</> : 'Simulate Interception'}
              </button>

              {simResult && (
                <div className="space-y-4 p-4 rounded-lg bg-slate-900/50 border border-slate-700/30">
                  <div className="flex items-center gap-4 flex-wrap">
                    <span className={`text-sm px-3 py-1 rounded-full font-medium ${ACTION_COLORS[simResult.action]}`}>{simResult.action}</span>
                    <span className="text-xs text-slate-400">Latency: <span className="text-cyan-400">{simResult.latency_ms}ms</span></span>
                  </div>

                  {/* Entities detected */}
                  <div>
                    <div className="text-xs text-slate-500 mb-2">Entities Detected</div>
                    <div className="flex gap-2 flex-wrap">
                      {(simResult.entities || []).map((e, i) => (
                        <div key={i} className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700/50">
                          <span className="text-slate-300 font-mono">{e.value}</span>
                          <span className="ml-2 text-slate-500">{e.type}</span>
                          <span className="ml-1 text-slate-600">({(e.confidence * 100).toFixed(0)}%)</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Policy decisions */}
                  {simResult.policy_decisions && (
                    <div>
                      <div className="text-xs text-slate-500 mb-2">Policy Decisions</div>
                      <div className="space-y-1">
                        {simResult.policy_decisions.map((d, i) => (
                          <div key={i} className="text-xs text-slate-400 font-mono pl-3 border-l-2 border-emerald-500/30">{d}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Risk score gauge */}
                  {simResult.risk_score !== undefined && (
                    <div>
                      <div className="text-xs text-slate-500 mb-2">Risk Score</div>
                      <div className="flex items-center gap-3">
                        <div className="flex-1 h-3 bg-slate-700 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full transition-all ${simResult.risk_score >= 75 ? 'bg-red-500' : simResult.risk_score >= 50 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                            style={{ width: `${simResult.risk_score}%` }}
                          />
                        </div>
                        <span className={`text-lg font-bold ${riskColor(simResult.risk_score)}`}>{simResult.risk_score}</span>
                      </div>
                    </div>
                  )}

                  {/* Recommendation */}
                  {simResult.recommendation && (
                    <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20">
                      <div className="text-xs text-amber-400 font-medium mb-1">Recommendation</div>
                      <div className="text-xs text-slate-400">{simResult.recommendation}</div>
                    </div>
                  )}

                  {/* Sanitized payload */}
                  <div>
                    <div className="text-xs text-slate-500 mb-1">Sanitized Payload</div>
                    <div className="bg-slate-950 rounded-lg p-3 text-sm text-cyan-300 font-mono whitespace-pre-wrap">{simResult.sanitized_payload}</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Batch Simulation */}
          {showBatch && (
            <div className="bg-slate-800/70 backdrop-blur-sm border border-amber-500/30 rounded-xl p-5 space-y-4">
              <h3 className="text-sm font-semibold text-amber-400">Batch Simulation</h3>
              <p className="text-xs text-slate-500">Enter one JSON payload per line.</p>
              <textarea
                value={batchPayloads}
                onChange={(e) => setBatchPayloads(e.target.value)}
                className="w-full h-28 bg-slate-900/50 border border-slate-700/50 rounded-lg p-3 text-sm text-slate-300 font-mono resize-none focus:outline-none focus:border-amber-500/50"
              />
              <button
                onClick={handleBatch}
                disabled={batchRunning || !batchPayloads.trim()}
                className="px-6 py-2 bg-amber-500 hover:bg-amber-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2"
              >
                {batchRunning ? <><Spinner /> Running Batch...</> : 'Run Batch Test'}
              </button>

              {batchResults && (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                        <th className="text-left py-2 font-medium">#</th>
                        <th className="text-left py-2 font-medium">Payload</th>
                        <th className="text-left py-2 font-medium">Entities</th>
                        <th className="text-left py-2 font-medium">Action</th>
                        <th className="text-left py-2 font-medium">Latency</th>
                      </tr>
                    </thead>
                    <tbody>
                      {batchResults.map((r) => (
                        <tr key={r.index} className="border-b border-slate-800/50">
                          <td className="py-2 text-slate-500 text-xs">{r.index + 1}</td>
                          <td className="py-2 text-slate-300 font-mono text-xs max-w-[300px] truncate">{r.payload}</td>
                          <td className="py-2 text-slate-300 text-xs">{r.entities_found}</td>
                          <td className="py-2"><span className={`text-xs px-2 py-0.5 rounded-full font-medium ${ACTION_COLORS[r.action]}`}>{r.action}</span></td>
                          <td className="py-2 text-emerald-400 text-xs">{r.latency_ms}ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
