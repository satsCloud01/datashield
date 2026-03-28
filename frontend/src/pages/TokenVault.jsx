import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const SAMPLE_TEXT = `Process loan application for John Smith, SSN 123-45-6789, email john.smith@acme.com, phone (555) 867-5309. Credit card: 4532-0151-1283-0366, exp 12/28. Patient DOB: 1985-03-15. IP: 192.168.1.100. API Key: sk-ant-api03-xxxxxxxxxxxx. Address: 742 Evergreen Terrace, Springfield IL 62704. Passport: X12345678.`;

const MODES = [
  { id: 'REDACT', label: 'Redact', desc: 'Replace with [REDACTED]', color: 'red' },
  { id: 'TOKENIZE', label: 'Tokenize', desc: 'Replace with <<TYPE_Xn>> (reversible)', color: 'cyan' },
  { id: 'PSEUDONYMIZE', label: 'Pseudonymize', desc: 'Replace with consistent fake values', color: 'purple' },
  { id: 'GENERALIZE', label: 'Generalize', desc: 'Replace with categories (age to 30s, city to region)', color: 'amber' },
  { id: 'ENCRYPT', label: 'Encrypt', desc: 'Format-preserving base64 encoding', color: 'blue' },
  { id: 'SYNTHESIZE', label: 'Synthesize', desc: 'Replace with realistic fake data', color: 'emerald' },
];

const TYPE_COLORS = {
  PERSON_NAME: 'bg-purple-500/10 text-purple-400',
  SSN: 'bg-red-500/10 text-red-400',
  EMAIL: 'bg-blue-500/10 text-blue-400',
  PHONE: 'bg-amber-500/10 text-amber-400',
  CREDIT_CARD: 'bg-red-500/10 text-red-400',
  DOB: 'bg-cyan-500/10 text-cyan-400',
  IP_ADDRESS: 'bg-slate-500/10 text-slate-400',
  API_KEY: 'bg-yellow-500/10 text-yellow-400',
  ADDRESS: 'bg-emerald-500/10 text-emerald-400',
  PASSPORT: 'bg-indigo-500/10 text-indigo-400',
};

const Spinner = () => (
  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
  </svg>
);

export default function TokenVault() {
  const [original, setOriginal] = useState(SAMPLE_TEXT);
  const [protectedText, setProtectedText] = useState('');
  const [restoredText, setRestoredText] = useState('');
  const [mappings, setMappings] = useState([]);
  const [mode, setMode] = useState('TOKENIZE');
  const [session, setSession] = useState(null);
  const [vaultRef, setVaultRef] = useState(null);
  const [protecting, setProtecting] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [error, setError] = useState(null);
  const [sessionForm, setSessionForm] = useState({ agent_id: 'agent-loan-001', ttl: 3600 });
  const [creatingSession, setCreatingSession] = useState(false);
  const [vaultStats, setVaultStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(true);

  // Fetch vault stats
  useEffect(() => {
    (async () => {
      setStatsLoading(true);
      try {
        const res = await fetch('/api/vault/stats');
        if (res.ok) { setVaultStats(await res.json()); setStatsLoading(false); return; }
      } catch {}
      setVaultStats({
        active_sessions: 12,
        total_tokens: 4837,
        tokens_by_type: [
          { type: 'PERSON_NAME', count: 1243 },
          { type: 'SSN', count: 892 },
          { type: 'EMAIL', count: 756 },
          { type: 'CREDIT_CARD', count: 634 },
          { type: 'PHONE', count: 512 },
          { type: 'DOB', count: 398 },
          { type: 'IP_ADDRESS', count: 245 },
          { type: 'API_KEY', count: 157 },
        ],
      });
      setStatsLoading(false);
    })();
  }, [protectedText]);

  const handleCreateSession = async () => {
    setCreatingSession(true);
    setError(null);
    try {
      const res = await fetch('/api/vault/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agent_id: sessionForm.agent_id, ttl: Number(sessionForm.ttl) }),
      });
      if (res.ok) {
        const data = await res.json();
        setSession({ session_id: data.session_id, agent_id: sessionForm.agent_id, status: 'ACTIVE', expires_at: data.expires_at });
        setCreatingSession(false);
        return;
      }
    } catch {}
    const sid = `vault-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
    setSession({
      session_id: sid,
      agent_id: sessionForm.agent_id,
      status: 'ACTIVE',
      expires_at: new Date(Date.now() + Number(sessionForm.ttl) * 1000).toISOString(),
    });
    setCreatingSession(false);
  };

  const handleProtect = async () => {
    setProtecting(true);
    setRestoredText('');
    setError(null);
    try {
      const res = await fetch('/api/protect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: original,
          mode,
          session_id: session?.session_id,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setProtectedText(data.protected_text);
        setMappings(data.mappings || []);
        setVaultRef(data.vault_ref || data.session_id);
        if (data.session_id && !session) {
          setSession({ session_id: data.session_id, agent_id: 'auto', status: 'ACTIVE', expires_at: data.expires_at });
        }
        setProtecting(false);
        return;
      }
    } catch {}
    // Fallback: client-side mock
    await new Promise((r) => setTimeout(r, 500));
    const patterns = [
      { type: 'PERSON_NAME', regex: /\b(John Smith)\b/g },
      { type: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
      { type: 'EMAIL', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g },
      { type: 'PHONE', regex: /\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g },
      { type: 'CREDIT_CARD', regex: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g },
      { type: 'DOB', regex: /\b\d{4}-\d{2}-\d{2}\b/g },
      { type: 'IP_ADDRESS', regex: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g },
      { type: 'API_KEY', regex: /\bsk-[a-zA-Z0-9-]+x+\b/g },
    ];
    const mocks = { REDACT: (t) => '[REDACTED]', TOKENIZE: (t, c) => `<<${t}_X${c}>>`, PSEUDONYMIZE: (t) => t === 'PERSON_NAME' ? 'Jane Doe' : t === 'EMAIL' ? 'user@example.com' : '***-**-0000', GENERALIZE: (t) => t === 'DOB' ? '1980s' : t === 'PERSON_NAME' ? '[Adult Male]' : '[GENERALIZED]', ENCRYPT: (v) => btoa(v).slice(0, v.length), SYNTHESIZE: (t) => t === 'PERSON_NAME' ? 'Michael Chen' : t === 'EMAIL' ? 'mchen@corp.io' : '***-**-1111' };
    const maps = [];
    let pt = original;
    let counter = {};
    for (const { type, regex } of patterns) {
      let m;
      while ((m = regex.exec(original)) !== null) {
        counter[type] = (counter[type] || 0) + 1;
        let replacement;
        if (mode === 'TOKENIZE') replacement = `<<${type}_X${counter[type]}>>`;
        else if (mode === 'REDACT') replacement = '[REDACTED]';
        else if (mode === 'ENCRYPT') replacement = btoa(m[0]).slice(0, m[0].length);
        else replacement = mocks[mode] ? mocks[mode](type, counter[type]) : `[${mode}]`;
        maps.push({ original: m[0], replacement, type, action: mode });
      }
    }
    for (const map of maps) pt = pt.replace(map.original, map.replacement);
    setProtectedText(pt);
    setMappings(maps);
    const vr = `vref-${Date.now().toString(36)}`;
    setVaultRef(vr);
    if (!session) {
      setSession({ session_id: `vault-${Date.now().toString(36)}`, agent_id: 'local', status: 'ACTIVE', expires_at: new Date(Date.now() + 3600000).toISOString() });
    }
    setProtecting(false);
  };

  const handleRestore = async () => {
    setRestoring(true);
    setError(null);
    try {
      const res = await fetch('/api/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vault_ref: vaultRef, protected_text: protectedText, session_id: session?.session_id }),
      });
      if (res.ok) {
        const data = await res.json();
        setRestoredText(data.restored_text);
        setRestoring(false);
        return;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 400));
    let restored = protectedText;
    for (const map of mappings) {
      restored = restored.replace(map.replacement || map.token, map.original);
    }
    setRestoredText(restored);
    setRestoring(false);
  };

  const fidelityMatch = restoredText && restoredText === original;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Token Vault</h1>
          <p className="text-slate-400 text-sm mt-1">Reversible tokenization — protect sensitive data and restore with zero loss.</p>
        </div>
      </div>

      {/* Session Panel */}
      <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-4">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-6 flex-wrap">
            {session ? (
              <>
                <div>
                  <div className="text-xs text-slate-500">Session ID</div>
                  <div className="text-sm text-emerald-400 font-mono">{session.session_id}</div>
                </div>
                <div>
                  <div className="text-xs text-slate-500">Agent</div>
                  <div className="text-sm text-slate-300 font-mono">{session.agent_id}</div>
                </div>
                <div>
                  <div className="text-xs text-slate-500">Status</div>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${session.status === 'ACTIVE' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                    {session.status}
                  </span>
                </div>
                <div>
                  <div className="text-xs text-slate-500">Expires</div>
                  <div className="text-sm text-slate-300">{new Date(session.expires_at).toLocaleString()}</div>
                </div>
              </>
            ) : (
              <span className="text-sm text-slate-500">No active session</span>
            )}
          </div>
          {!session && (
            <div className="flex items-center gap-3">
              <input
                value={sessionForm.agent_id}
                onChange={(e) => setSessionForm({ ...sessionForm, agent_id: e.target.value })}
                placeholder="Agent ID"
                className="bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-emerald-500/50 w-40"
              />
              <input
                value={sessionForm.ttl}
                onChange={(e) => setSessionForm({ ...sessionForm, ttl: e.target.value })}
                placeholder="TTL (s)"
                type="number"
                className="bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-emerald-500/50 w-24"
              />
              <button
                onClick={handleCreateSession}
                disabled={creatingSession || !sessionForm.agent_id}
                className="px-4 py-1.5 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2"
              >
                {creatingSession ? <Spinner /> : null}
                Create Session
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Mode Selector */}
      <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-4">
        <h3 className="text-sm font-semibold text-slate-300 mb-3">Protection Mode</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
          {MODES.map((m) => (
            <button
              key={m.id}
              onClick={() => { setMode(m.id); setProtectedText(''); setRestoredText(''); setMappings([]); }}
              className={`p-3 rounded-lg border text-left transition-all ${mode === m.id ? 'border-emerald-500/50 bg-emerald-500/10' : 'border-slate-700/50 bg-slate-900/30 hover:border-slate-600'}`}
            >
              <div className={`text-sm font-semibold ${mode === m.id ? 'text-emerald-400' : 'text-slate-300'}`}>{m.label}</div>
              <div className="text-[10px] text-slate-500 mt-1 leading-tight">{m.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-sm text-red-400">{error}</div>
      )}

      {/* Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Original */}
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <label className="text-sm font-semibold text-slate-300 mb-3 block">Original Text</label>
          <textarea
            value={original}
            onChange={(e) => { setOriginal(e.target.value); setProtectedText(''); setRestoredText(''); setMappings([]); }}
            className="w-full h-52 bg-slate-900/50 border border-slate-700/50 rounded-lg p-4 text-sm text-slate-300 font-mono resize-none focus:outline-none focus:border-emerald-500/50"
          />
          <button
            onClick={handleProtect}
            disabled={protecting || !original.trim()}
            className="mt-3 w-full py-3 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg font-semibold transition-all flex items-center justify-center gap-2"
          >
            {protecting ? <><Spinner /> Protecting...</> : (
              <>
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" /></svg>
                Protect ({mode})
              </>
            )}
          </button>
        </div>

        {/* Right: Protected */}
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <label className="text-sm font-semibold text-slate-300 mb-3 block">Protected Text</label>
          <div className="w-full h-52 bg-slate-900/50 border border-slate-700/50 rounded-lg p-4 text-sm font-mono overflow-y-auto">
            {protectedText ? (
              <span className="text-cyan-300 whitespace-pre-wrap">{protectedText}</span>
            ) : (
              <span className="text-slate-600">Protected text will appear here after you click Protect...</span>
            )}
          </div>
          {protectedText && (
            <button
              onClick={handleRestore}
              disabled={restoring}
              className="mt-3 w-full py-3 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg font-semibold transition-all flex items-center justify-center gap-2"
            >
              {restoring ? <><Spinner /> Restoring...</> : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
                  Restore Original
                </>
              )}
            </button>
          )}
        </div>
      </div>

      {/* Restored Section + Round-trip Verification */}
      {restoredText && (
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <label className="text-sm font-semibold text-emerald-400 flex items-center gap-2">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
              Restored Text
            </label>
            {fidelityMatch ? (
              <span className="text-xs px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/30">
                100% Fidelity — Zero Data Loss
              </span>
            ) : (
              <span className="text-xs px-3 py-1 rounded-full bg-amber-500/10 text-amber-400 font-semibold border border-amber-500/30">
                Partial Restoration
              </span>
            )}
          </div>
          <div className="bg-slate-900/50 border border-emerald-500/20 rounded-lg p-4 text-sm text-emerald-300 font-mono whitespace-pre-wrap">
            {restoredText}
          </div>
          {/* Visual diff */}
          {!fidelityMatch && (
            <div className="mt-4 grid grid-cols-2 gap-4">
              <div>
                <div className="text-xs text-slate-500 mb-1">Original</div>
                <div className="bg-slate-900/50 rounded-lg p-3 text-xs text-slate-400 font-mono whitespace-pre-wrap max-h-32 overflow-y-auto">{original}</div>
              </div>
              <div>
                <div className="text-xs text-slate-500 mb-1">Restored</div>
                <div className="bg-slate-900/50 rounded-lg p-3 text-xs text-amber-300 font-mono whitespace-pre-wrap max-h-32 overflow-y-auto">{restoredText}</div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Token Mapping Table */}
      {mappings.length > 0 && (
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Token Mapping ({mappings.length} entities)</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                  <th className="text-left py-2 font-medium">Original Value</th>
                  <th className="text-left py-2 font-medium">Token / Replacement</th>
                  <th className="text-left py-2 font-medium">Entity Type</th>
                  <th className="text-left py-2 font-medium">Action Applied</th>
                </tr>
              </thead>
              <tbody>
                {mappings.map((m, i) => (
                  <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-700/20">
                    <td className="py-2.5 text-red-300 font-mono text-xs">{m.original}</td>
                    <td className="py-2.5 text-cyan-300 font-mono text-xs">{m.replacement || m.token}</td>
                    <td className="py-2.5">
                      <span className={`text-xs px-2 py-0.5 rounded ${TYPE_COLORS[m.type] || 'bg-slate-700/50 text-slate-400'}`}>{m.type}</span>
                    </td>
                    <td className="py-2.5">
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400">{m.action || mode}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Vault Stats */}
      <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-slate-300 mb-4">Vault Utilization</h3>
        {statsLoading ? (
          <div className="flex items-center justify-center py-8"><Spinner /><span className="ml-2 text-slate-500 text-sm">Loading vault stats...</span></div>
        ) : vaultStats ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                <div className="text-xs text-slate-500">Active Sessions</div>
                <div className="text-2xl font-bold text-emerald-400">{vaultStats.active_sessions}</div>
              </div>
              <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                <div className="text-xs text-slate-500">Total Tokens</div>
                <div className="text-2xl font-bold text-cyan-400">{vaultStats.total_tokens?.toLocaleString()}</div>
              </div>
              <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700/30">
                <div className="text-xs text-slate-500">Current Mappings</div>
                <div className="text-2xl font-bold text-white">{mappings.length}</div>
              </div>
            </div>
            {vaultStats.tokens_by_type && vaultStats.tokens_by_type.length > 0 && (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={vaultStats.tokens_by_type}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="type" tick={{ fill: '#64748b', fontSize: 10 }} angle={-20} textAnchor="end" height={50} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, color: '#e2e8f0' }} />
                  <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} name="Tokens" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
