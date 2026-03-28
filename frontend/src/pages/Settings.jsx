import React, { useState, useEffect, useCallback } from 'react';

/* ── AI Key BYOK helpers ── */
const AI_KEY_STORAGE = 'datashield_anthropic_key';

function getStoredKey() {
  try { return localStorage.getItem(AI_KEY_STORAGE) || ''; } catch { return ''; }
}

function AIConfigSection() {
  const [apiKey, setApiKey] = useState(getStoredKey);
  const [showKey, setShowKey] = useState(false);
  const [testing, setTesting] = useState(false);
  const [status, setStatus] = useState(getStoredKey() ? 'saved' : 'disconnected'); // saved | connected | disconnected | error

  const handleSaveKey = (val) => {
    setApiKey(val);
    if (val) {
      try { localStorage.setItem(AI_KEY_STORAGE, val); } catch {}
      setStatus('saved');
    } else {
      try { localStorage.removeItem(AI_KEY_STORAGE); } catch {}
      setStatus('disconnected');
    }
    // dispatch event so sidebar picks it up
    window.dispatchEvent(new Event('datashield-ai-key-change'));
  };

  const handleTest = async () => {
    if (!apiKey) return;
    setTesting(true);
    setStatus('testing');
    try {
      const res = await fetch('/api/health', {
        headers: { 'X-API-Key': apiKey },
      });
      if (res.ok) {
        setStatus('connected');
      } else {
        setStatus('error');
      }
    } catch {
      setStatus('error');
    }
    setTesting(false);
  };

  const handleClear = () => {
    handleSaveKey('');
    setShowKey(false);
  };

  const statusColors = {
    connected: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    saved: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    disconnected: 'text-slate-400 bg-slate-700/50 border-slate-600',
    error: 'text-red-400 bg-red-500/10 border-red-500/30',
    testing: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  };
  const statusLabels = {
    connected: 'Connected',
    saved: 'Key Saved',
    disconnected: 'Disconnected',
    error: 'Invalid Key',
    testing: 'Testing...',
  };

  return (
    <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <svg className="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
        AI Configuration
        <span className={`ml-auto text-xs px-2 py-0.5 rounded-full border ${statusColors[status]}`}>
          {statusLabels[status]}
        </span>
      </h2>

      {/* Privacy banner */}
      <div className="mb-4 p-3 rounded-lg bg-purple-500/5 border border-purple-500/20 flex items-start gap-3">
        <svg className="w-5 h-5 text-purple-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
        <p className="text-sm text-purple-300">
          API keys are stored in your browser only and never sent to our servers for storage.
          Keys are passed per-request via headers and are never persisted server-side.
        </p>
      </div>

      {/* API Key input */}
      <div className="mb-4">
        <label className="text-sm text-slate-400 block mb-2">Anthropic API Key</label>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <input
              type={showKey ? 'text' : 'password'}
              value={apiKey}
              onChange={(e) => handleSaveKey(e.target.value)}
              placeholder="sk-ant-..."
              className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-4 py-2.5 text-sm text-white font-mono focus:outline-none focus:border-purple-500/50 pr-10"
            />
            <button
              onClick={() => setShowKey(!showKey)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {showKey ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" />
                ) : (
                  <><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></>
                )}
              </svg>
            </button>
          </div>
          <button
            onClick={handleTest}
            disabled={!apiKey || testing}
            className="px-4 py-2 bg-purple-500 hover:bg-purple-600 disabled:bg-slate-700 text-white rounded-lg text-sm font-medium transition-all"
          >
            {testing ? 'Testing...' : 'Test Connection'}
          </button>
          <button
            onClick={handleClear}
            disabled={!apiKey}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-40 text-slate-300 rounded-lg text-sm font-medium transition-all"
          >
            Clear
          </button>
        </div>
        <p className="text-xs text-slate-500 mt-1.5">
          Used for AI-enhanced PII detection and threat analysis. All features work without a key (regex-based fallback).
        </p>
      </div>
    </div>
  );
}

export default function Settings() {
  // Vault config
  const [vaultTTL, setVaultTTL] = useState(1800);
  const [sessionTimeout, setSessionTimeout] = useState(3600);

  // Detection config
  const [confidenceThreshold, setConfidenceThreshold] = useState(0.85);
  const [entityRegistry, setEntityRegistry] = useState([]);
  const [enabledEntities, setEnabledEntities] = useState(new Set());

  // Agent roles
  const [roles, setRoles] = useState([]);
  const [newRoleName, setNewRoleName] = useState('');
  const [newRoleClearance, setNewRoleClearance] = useState('INTERNAL');
  const [newRoleDescription, setNewRoleDescription] = useState('');
  const [editingRole, setEditingRole] = useState(null);

  // Notifications
  const [notifications, setNotifications] = useState({
    email: false,
    slack: false,
    siem_export: false,
    webhook: false,
  });
  const [webhookUrl, setWebhookUrl] = useState('');

  // UI state
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);
  const [deleteConfirm, setDeleteConfirm] = useState(null);

  // About info
  const [aboutInfo, setAboutInfo] = useState({});

  const fetchSettings = useCallback(async () => {
    try {
      const res = await fetch('/api/settings');
      if (res.ok) {
        const d = await res.json();
        if (d.vault_ttl !== undefined) setVaultTTL(d.vault_ttl);
        if (d.session_timeout !== undefined) setSessionTimeout(d.session_timeout);
        if (d.confidence_threshold !== undefined) setConfidenceThreshold(d.confidence_threshold);
        if (d.enabled_entities) setEnabledEntities(new Set(d.enabled_entities));
        if (d.notifications) {
          setNotifications(d.notifications);
          if (d.notifications.webhook_url) setWebhookUrl(d.notifications.webhook_url);
        }
        if (d.about) setAboutInfo(d.about);
      }
    } catch { setError('Failed to load settings'); }
  }, []);

  const fetchEntityRegistry = useCallback(async () => {
    try {
      const res = await fetch('/api/scan/entity-registry');
      if (res.ok) {
        const d = await res.json();
        setEntityRegistry(Array.isArray(d) ? d : d.entities || d.categories || []);
      }
    } catch {}
  }, []);

  const fetchRoles = useCallback(async () => {
    try {
      const res = await fetch('/api/settings/agent-roles');
      if (res.ok) {
        const d = await res.json();
        setRoles(Array.isArray(d) ? d : d.roles || []);
      }
    } catch {}
  }, []);

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchSettings(), fetchEntityRegistry(), fetchRoles()])
      .finally(() => setLoading(false));
  }, [fetchSettings, fetchEntityRegistry, fetchRoles]);

  const toggleEntity = (name) => {
    const next = new Set(enabledEntities);
    next.has(name) ? next.delete(name) : next.add(name);
    setEnabledEntities(next);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await fetch('/api/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vault_ttl: vaultTTL,
          session_timeout: sessionTimeout,
          confidence_threshold: confidenceThreshold,
          enabled_entities: [...enabledEntities],
          notifications: { ...notifications, webhook_url: webhookUrl },
        }),
      });
      if (res.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 2500);
      } else {
        setError('Failed to save settings');
      }
    } catch {
      setError('Failed to save settings');
    }
    setSaving(false);
  };

  const handleAddRole = async () => {
    if (!newRoleName.trim()) return;
    try {
      const res = await fetch('/api/settings/agent-roles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newRoleName,
          clearance: newRoleClearance,
          description: newRoleDescription,
        }),
      });
      if (res.ok) {
        await fetchRoles();
        setNewRoleName('');
        setNewRoleDescription('');
      }
    } catch {}
  };

  const handleDeleteRole = async (id) => {
    try {
      await fetch(`/api/settings/agent-roles/${id}`, { method: 'DELETE' });
      await fetchRoles();
    } catch {}
    setDeleteConfirm(null);
  };

  // Group entity registry by category
  const entityGroups = {};
  if (Array.isArray(entityRegistry)) {
    entityRegistry.forEach((e) => {
      const cat = e.category || 'General';
      if (!entityGroups[cat]) entityGroups[cat] = [];
      entityGroups[cat].push(e);
    });
  }

  const CLEARANCE_COLORS = {
    CONFIDENTIAL: 'text-red-400 bg-red-500/10',
    RESTRICTED: 'text-amber-400 bg-amber-500/10',
    INTERNAL: 'text-cyan-400 bg-cyan-500/10',
    PUBLIC: 'text-emerald-400 bg-emerald-500/10',
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <button onClick={handleSave} disabled={saving}
          className="px-6 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2">
          {saved ? (
            <><svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>Saved</>
          ) : saving ? 'Saving...' : 'Save Settings'}
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{error}
          <button onClick={() => setError(null)} className="ml-3 text-red-300 hover:text-white">Dismiss</button>
        </div>
      )}

      {saved && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-sm">
          Settings saved successfully.
        </div>
      )}

      {/* AI Configuration — BYOK */}
      <AIConfigSection />

      {/* Vault Configuration */}
      <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          Vault Configuration
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="text-sm text-slate-400 block mb-2">Vault TTL (seconds)</label>
            <input type="range" min="300" max="7200" step="60" value={vaultTTL}
              onChange={(e) => setVaultTTL(+e.target.value)}
              className="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-emerald-500" />
            <div className="flex justify-between text-xs text-slate-500 mt-1">
              <span>5 min</span>
              <span className="text-emerald-400 font-semibold">{vaultTTL}s ({(vaultTTL / 60).toFixed(0)} min)</span>
              <span>2 hr</span>
            </div>
            <p className="text-xs text-slate-500 mt-1">How long tokenized data persists in the vault before auto-expiry.</p>
          </div>
          <div>
            <label className="text-sm text-slate-400 block mb-2">Session Timeout (seconds)</label>
            <input type="number" value={sessionTimeout} onChange={(e) => setSessionTimeout(+e.target.value)}
              className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:border-emerald-500/50" />
            <p className="text-xs text-slate-500 mt-1">Idle timeout before agent sessions expire.</p>
          </div>
        </div>
      </div>

      {/* Detection Configuration */}
      <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <svg className="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          Detection Configuration
        </h2>

        <div className="mb-6">
          <label className="text-sm text-slate-400 block mb-2">
            Confidence Threshold: <span className="text-emerald-400 font-semibold">{confidenceThreshold.toFixed(2)}</span>
          </label>
          <input type="range" min="0.5" max="1.0" step="0.05" value={confidenceThreshold}
            onChange={(e) => setConfidenceThreshold(+e.target.value)}
            className="w-full h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-emerald-500" />
          <div className="flex justify-between text-xs text-slate-500 mt-1">
            <span>0.50 (More detections)</span>
            <span>1.00 (Fewer, higher confidence)</span>
          </div>
        </div>

        <div>
          <label className="text-sm text-slate-400 block mb-3">
            Enabled Entity Types ({enabledEntities.size})
          </label>
          {Object.keys(entityGroups).length > 0 ? (
            Object.entries(entityGroups).map(([category, entities]) => (
              <div key={category} className="mb-4">
                <div className="text-xs text-slate-500 font-medium mb-2 uppercase tracking-wider">{category}</div>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
                  {entities.map((e) => {
                    const name = e.name || e.type || e;
                    return (
                      <button key={name} onClick={() => toggleEntity(name)}
                        className={`px-2 py-1.5 rounded-lg text-[10px] font-mono transition-all truncate ${
                          enabledEntities.has(name)
                            ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            : 'bg-slate-800/50 text-slate-500 border border-slate-700/30 hover:text-slate-300'
                        }`}>
                        {name}
                      </button>
                    );
                  })}
                </div>
              </div>
            ))
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
              {[...enabledEntities].map((name) => (
                <button key={name} onClick={() => toggleEntity(name)}
                  className="px-2 py-1.5 rounded-lg text-[10px] font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 truncate">
                  {name}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Agent Roles */}
      <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <svg className="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
          </svg>
          Agent Roles
        </h2>

        {/* Roles table */}
        <div className="overflow-x-auto mb-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                <th className="text-left py-2 px-2 font-medium">Role Name</th>
                <th className="text-left py-2 px-2 font-medium">Clearance Level</th>
                <th className="text-left py-2 px-2 font-medium">Permissions</th>
                <th className="text-left py-2 px-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {roles.map((r) => (
                <tr key={r.id} className="border-b border-slate-800/50">
                  <td className="py-2 px-2">
                    <div className="text-sm text-white font-medium">{r.name}</div>
                    {r.description && <div className="text-xs text-slate-500">{r.description}</div>}
                  </td>
                  <td className="py-2 px-2">
                    <span className={`text-xs px-2 py-0.5 rounded-full ${CLEARANCE_COLORS[r.clearance] || 'text-slate-400 bg-slate-700/50'}`}>
                      {r.clearance}
                    </span>
                  </td>
                  <td className="py-2 px-2">
                    <div className="flex gap-1 flex-wrap">
                      {(r.permissions || []).map((p) => (
                        <span key={p} className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">{p}</span>
                      ))}
                    </div>
                  </td>
                  <td className="py-2 px-2">
                    <button onClick={() => setDeleteConfirm(r.id)}
                      className="text-xs text-red-400 hover:text-red-300 transition-colors">Delete</button>
                  </td>
                </tr>
              ))}
              {roles.length === 0 && (
                <tr><td colSpan={4} className="py-6 text-center text-slate-500">No roles configured</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Add role form */}
        <div className="p-4 rounded-lg bg-slate-900/50 border border-slate-700/30">
          <h4 className="text-sm text-slate-300 font-medium mb-3">Add Role</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input value={newRoleName} onChange={(e) => setNewRoleName(e.target.value)}
              placeholder="Role name..."
              className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50" />
            <select value={newRoleClearance} onChange={(e) => setNewRoleClearance(e.target.value)}
              className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none">
              {['CONFIDENTIAL', 'RESTRICTED', 'INTERNAL', 'PUBLIC'].map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
            <input value={newRoleDescription} onChange={(e) => setNewRoleDescription(e.target.value)}
              placeholder="Description..."
              className="bg-slate-800/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50" />
          </div>
          <button onClick={handleAddRole} disabled={!newRoleName.trim()}
            className="mt-3 px-4 py-2 bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-700 text-white rounded-lg text-sm font-medium transition-all">
            Add Role
          </button>
        </div>
      </div>

      {/* Notifications */}
      <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <svg className="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          Notifications
        </h2>
        <div className="space-y-3">
          {[
            { key: 'email', label: 'Email Notifications' },
            { key: 'slack', label: 'Slack Notifications' },
            { key: 'siem_export', label: 'SIEM Export' },
            { key: 'webhook', label: 'Webhook' },
          ].map(({ key, label }) => (
            <div key={key}>
              <div className="flex items-center justify-between p-3 rounded-lg bg-slate-900/50 border border-slate-700/30">
                <span className="text-sm text-slate-300">{label}</span>
                <button onClick={() => setNotifications({ ...notifications, [key]: !notifications[key] })}
                  className={`w-10 h-5 rounded-full transition-all relative ${notifications[key] ? 'bg-emerald-500' : 'bg-slate-600'}`}>
                  <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${notifications[key] ? 'left-5' : 'left-0.5'}`} />
                </button>
              </div>
              {key === 'webhook' && notifications.webhook && (
                <div className="mt-2 ml-4">
                  <input value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://your-webhook-endpoint.com/..."
                    className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50 font-mono" />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* About */}
      <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white mb-4">About</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-xs text-slate-500">Version</div>
            <div className="text-sm text-white">{aboutInfo.version || '1.0.0'}</div>
          </div>
          <div>
            <div className="text-xs text-slate-500">Engine</div>
            <div className="text-sm text-white">{aboutInfo.engine || 'DataShield Core'}</div>
          </div>
          <div>
            <div className="text-xs text-slate-500">Entity Types</div>
            <div className="text-sm text-emerald-400">{aboutInfo.entity_count || enabledEntities.size || '57'}</div>
          </div>
          <div>
            <div className="text-xs text-slate-500">Frameworks</div>
            <div className="text-sm text-emerald-400">{aboutInfo.framework_count || '8'}</div>
          </div>
        </div>
        <p className="text-xs text-slate-500 mt-4">
          DataShield AI -- Real-time PII detection and reversible tokenization for the agentic AI era.
        </p>
      </div>

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm" onClick={() => setDeleteConfirm(null)}>
          <div className="bg-slate-800/90 border border-slate-700 rounded-xl p-6 max-w-sm w-full mx-4" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-white mb-2">Confirm Delete</h3>
            <p className="text-sm text-slate-400 mb-4">Are you sure you want to delete this agent role? This cannot be undone.</p>
            <div className="flex gap-3 justify-end">
              <button onClick={() => setDeleteConfirm(null)} className="px-4 py-2 text-sm text-slate-400 hover:text-white">Cancel</button>
              <button onClick={() => handleDeleteRole(deleteConfirm)}
                className="px-4 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm font-medium transition-all">Delete</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
