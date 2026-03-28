import React, { useState, useEffect, useCallback } from 'react';

const COMPLIANCE_PACKS = ['GDPR', 'HIPAA', 'PCI_DSS', 'CCPA', 'SOX', 'EU_AI_ACT'];
const TEMPLATES = ['BFSI', 'Healthcare', 'Strict', 'Minimal'];

const STATUS_COLORS = {
  ACTIVE: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  active: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  DRAFT: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  draft: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  ARCHIVED: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
  archived: 'text-slate-400 bg-slate-500/10 border-slate-500/30',
};

const ACTION_COLORS = {
  tokenize: 'text-cyan-400 bg-cyan-500/10',
  mask: 'text-yellow-400 bg-yellow-500/10',
  redact: 'text-red-400 bg-red-500/10',
  encrypt: 'text-blue-400 bg-blue-500/10',
};

const TEMPLATE_YAML = {
  BFSI: `policy:
  name: ""
  version: "1.0"
  compliance_packs:
    - PCI_DSS
    - SOX
    - GDPR
  entity_rules:
    - entity_type: SSN
      action: tokenize
      min_confidence: 0.85
    - entity_type: CREDIT_CARD
      action: tokenize
      min_confidence: 0.90
    - entity_type: BANK_ACCOUNT
      action: tokenize
      min_confidence: 0.85
    - entity_type: PERSON_NAME
      action: mask
      min_confidence: 0.80
    - entity_type: EMAIL
      action: tokenize
      min_confidence: 0.90
  agent_roles:
    - loan-processor
    - kyc-agent
    - fraud-detector
  vault_ttl: 3600
  log_level: audit`,
  Healthcare: `policy:
  name: ""
  version: "1.0"
  compliance_packs:
    - HIPAA
    - GDPR
  entity_rules:
    - entity_type: SSN
      action: redact
      min_confidence: 0.80
    - entity_type: DOB
      action: tokenize
      min_confidence: 0.85
    - entity_type: MRN
      action: tokenize
      min_confidence: 0.90
    - entity_type: PERSON_NAME
      action: tokenize
      min_confidence: 0.80
    - entity_type: ADDRESS
      action: redact
      min_confidence: 0.85
  agent_roles:
    - triage-agent
    - records-agent
    - billing-agent
  vault_ttl: 1800
  log_level: audit`,
  Strict: `policy:
  name: ""
  version: "1.0"
  compliance_packs:
    - GDPR
    - CCPA
    - HIPAA
    - PCI_DSS
    - SOX
    - EU_AI_ACT
  entity_rules:
    - entity_type: "*"
      action: redact
      min_confidence: 0.70
  agent_roles:
    - "*"
  vault_ttl: 0
  log_level: audit`,
  Minimal: `policy:
  name: ""
  version: "1.0"
  compliance_packs:
    - GDPR
  entity_rules:
    - entity_type: SSN
      action: tokenize
      min_confidence: 0.90
    - entity_type: CREDIT_CARD
      action: tokenize
      min_confidence: 0.95
  agent_roles:
    - "*"
  vault_ttl: 7200
  log_level: info`,
};

const Spinner = () => (
  <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
  </svg>
);

export default function PolicyStudio() {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [editYaml, setEditYaml] = useState('');
  const [originalYaml, setOriginalYaml] = useState('');
  const [validation, setValidation] = useState(null);
  const [validating, setValidating] = useState(false);
  const [saving, setSaving] = useState(false);

  // Create form
  const [showCreate, setShowCreate] = useState(false);
  const [newPolicy, setNewPolicy] = useState({ name: '', description: '', compliance_packs: [], template: '' });
  const [newYaml, setNewYaml] = useState('');
  const [creating, setCreating] = useState(false);

  // Simulation
  const [showSimulation, setShowSimulation] = useState(false);
  const [simText, setSimText] = useState('John Smith, SSN 123-45-6789, email john@acme.com, card 4532-0151-1283-0366');
  const [simResult, setSimResult] = useState(null);
  const [simulating, setSimulating] = useState(false);

  const fetchPolicies = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/policies');
      if (res.ok) { setPolicies(await res.json()); setLoading(false); return; }
    } catch {}
    // Fallback
    setPolicies([
      { id: 'pol-001', name: 'BFSI Default', description: 'Standard banking and financial services PII protection', status: 'ACTIVE', compliance_packs: ['PCI_DSS', 'SOX', 'GDPR'], entity_rules: [{ entity_type: 'SSN', action: 'tokenize', min_confidence: 0.85 }, { entity_type: 'CREDIT_CARD', action: 'tokenize', min_confidence: 0.9 }], created_at: '2026-03-01T10:00:00Z', yaml: TEMPLATE_YAML.BFSI.replace('name: ""', 'name: "BFSI Default"') },
      { id: 'pol-002', name: 'Healthcare HIPAA', description: 'HIPAA-compliant policy for healthcare AI agents', status: 'ACTIVE', compliance_packs: ['HIPAA', 'GDPR'], entity_rules: [{ entity_type: 'SSN', action: 'redact', min_confidence: 0.8 }, { entity_type: 'DOB', action: 'tokenize', min_confidence: 0.85 }], created_at: '2026-03-05T14:30:00Z', yaml: TEMPLATE_YAML.Healthcare.replace('name: ""', 'name: "Healthcare HIPAA"') },
      { id: 'pol-003', name: 'Strict Lockdown', description: 'Maximum protection -- redacts all detected entities', status: 'DRAFT', compliance_packs: ['GDPR', 'CCPA', 'HIPAA', 'PCI_DSS', 'SOX'], entity_rules: [{ entity_type: '*', action: 'redact', min_confidence: 0.7 }], created_at: '2026-03-10T09:15:00Z', yaml: TEMPLATE_YAML.Strict.replace('name: ""', 'name: "Strict Lockdown"') },
      { id: 'pol-004', name: 'EU AI Act Compliant', description: 'Policy designed for EU AI Act transparency requirements', status: 'ARCHIVED', compliance_packs: ['EU_AI_ACT', 'GDPR'], entity_rules: [{ entity_type: 'PERSON_NAME', action: 'tokenize', min_confidence: 0.85 }], created_at: '2026-02-20T11:00:00Z', yaml: TEMPLATE_YAML.Minimal.replace('name: ""', 'name: "EU AI Act Compliant"') },
    ]);
    setLoading(false);
  }, []);

  useEffect(() => { fetchPolicies(); }, [fetchPolicies]);

  const selectPolicy = (p) => {
    setSelected(p);
    setEditYaml(p.yaml || '');
    setOriginalYaml(p.yaml || '');
    setValidation(null);
    setShowCreate(false);
    setShowSimulation(false);
    setSimResult(null);
  };

  const handleValidate = async () => {
    setValidating(true);
    try {
      const res = await fetch('/api/policies/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: editYaml }),
      });
      if (res.ok) { setValidation(await res.json()); setValidating(false); return; }
    } catch {}
    const hasPolicy = editYaml.includes('policy:');
    const hasName = editYaml.includes('name:');
    const hasRules = editYaml.includes('entity_rules:');
    setValidation({ valid: hasPolicy && hasName && hasRules, errors: (!hasPolicy ? ['Missing policy: root key'] : []).concat(!hasName ? ['Missing name field'] : []).concat(!hasRules ? ['Missing entity_rules'] : []) });
    setValidating(false);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await fetch(`/api/policies/${selected.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ yaml: editYaml }),
      });
      if (res.ok) {
        const updated = await res.json();
        setPolicies(policies.map((p) => p.id === selected.id ? { ...p, ...updated, yaml: editYaml } : p));
        setSelected({ ...selected, ...updated, yaml: editYaml });
        setOriginalYaml(editYaml);
        setSaving(false);
        return;
      }
    } catch {}
    setPolicies(policies.map((p) => p.id === selected.id ? { ...p, yaml: editYaml } : p));
    setOriginalYaml(editYaml);
    setSaving(false);
  };

  const handleArchive = async () => {
    try {
      await fetch(`/api/policies/${selected.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'ARCHIVED' }),
      });
    } catch {}
    const updated = { ...selected, status: 'ARCHIVED' };
    setPolicies(policies.map((p) => p.id === selected.id ? updated : p));
    setSelected(updated);
  };

  const handleCreate = async () => {
    setCreating(true);
    const yaml = newYaml || TEMPLATE_YAML[newPolicy.template] || TEMPLATE_YAML.Minimal;
    const finalYaml = yaml.replace('name: ""', `name: "${newPolicy.name}"`);
    try {
      const res = await fetch('/api/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newPolicy.name, description: newPolicy.description, compliance_packs: newPolicy.compliance_packs, yaml: finalYaml }),
      });
      if (res.ok) {
        const created = await res.json();
        setPolicies([...policies, created]);
        selectPolicy(created);
        setShowCreate(false);
        setCreating(false);
        return;
      }
    } catch {}
    const id = `pol-${String(policies.length + 1).padStart(3, '0')}`;
    const p = { id, name: newPolicy.name, description: newPolicy.description, status: 'DRAFT', compliance_packs: newPolicy.compliance_packs, entity_rules: [], created_at: new Date().toISOString(), yaml: finalYaml };
    setPolicies([...policies, p]);
    selectPolicy(p);
    setShowCreate(false);
    setCreating(false);
  };

  const handleSimulate = async () => {
    setSimulating(true);
    try {
      const res = await fetch('/api/interceptor/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: simText, policy_id: selected.id }),
      });
      if (res.ok) { setSimResult(await res.json()); setSimulating(false); return; }
    } catch {}
    await new Promise((r) => setTimeout(r, 500));
    setSimResult({
      entities: [
        { value: 'John Smith', type: 'PERSON_NAME', action: 'mask', confidence: 0.92 },
        { value: '123-45-6789', type: 'SSN', action: 'tokenize', confidence: 0.98 },
        { value: 'john@acme.com', type: 'EMAIL', action: 'tokenize', confidence: 0.95 },
        { value: '4532-0151-1283-0366', type: 'CREDIT_CARD', action: 'tokenize', confidence: 0.97 },
      ],
      protected_text: simText.replace('John Smith', '[MASKED]').replace('123-45-6789', '<<SSN_X1>>').replace('john@acme.com', '<<EMAIL_X1>>').replace('4532-0151-1283-0366', '<<CREDIT_CARD_X1>>'),
      policy_name: selected.name,
    });
    setSimulating(false);
  };

  const toggleCompliancePack = (pack) => {
    setNewPolicy((prev) => ({
      ...prev,
      compliance_packs: prev.compliance_packs.includes(pack)
        ? prev.compliance_packs.filter((p) => p !== pack)
        : [...prev.compliance_packs, pack],
    }));
  };

  const yamlChanged = editYaml !== originalYaml;

  // Compute simple diff lines
  const diffLines = () => {
    if (!yamlChanged) return [];
    const oldLines = originalYaml.split('\n');
    const newLines = editYaml.split('\n');
    const lines = [];
    const max = Math.max(oldLines.length, newLines.length);
    for (let i = 0; i < max; i++) {
      if (oldLines[i] !== newLines[i]) {
        if (oldLines[i] !== undefined) lines.push({ type: 'removed', text: oldLines[i], line: i + 1 });
        if (newLines[i] !== undefined) lines.push({ type: 'added', text: newLines[i], line: i + 1 });
      }
    }
    return lines;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Policy Studio</h1>
          <p className="text-slate-400 text-sm mt-1">Create, manage, and test data protection policies.</p>
        </div>
        <button
          onClick={() => { setShowCreate(true); setSelected(null); setNewPolicy({ name: '', description: '', compliance_packs: [], template: '' }); setNewYaml(''); }}
          className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg text-sm font-medium transition-all"
        >
          + Create Policy
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Policy List Sidebar */}
        <div className="space-y-3 max-h-[calc(100vh-12rem)] overflow-y-auto pr-1">
          {loading ? (
            <div className="flex items-center justify-center py-12"><Spinner /><span className="ml-2 text-slate-500 text-sm">Loading policies...</span></div>
          ) : error ? (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-sm text-red-400">{error}</div>
          ) : policies.length === 0 ? (
            <div className="text-center py-12 text-slate-500 text-sm">No policies found. Create one to get started.</div>
          ) : (
            policies.map((p) => (
              <div
                key={p.id}
                onClick={() => selectPolicy(p)}
                className={`bg-slate-800/70 backdrop-blur-sm border rounded-xl p-4 cursor-pointer transition-all hover:border-slate-600 ${selected?.id === p.id ? 'border-emerald-500/50 bg-emerald-500/5' : 'border-slate-700'}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-white truncate">{p.name}</h3>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium border ${STATUS_COLORS[p.status] || STATUS_COLORS.DRAFT}`}>
                    {(p.status || 'DRAFT').toUpperCase()}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mb-2 line-clamp-2">{p.description}</p>
                <div className="flex gap-1 flex-wrap mb-2">
                  {(p.compliance_packs || []).map((c) => (
                    <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-400">{c}</span>
                  ))}
                </div>
                {p.created_at && <div className="text-[10px] text-slate-600">{new Date(p.created_at).toLocaleDateString()}</div>}
              </div>
            ))
          )}
        </div>

        {/* Detail / Create Panel */}
        <div className="lg:col-span-2 space-y-4">
          {showCreate ? (
            <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-6 space-y-5">
              <h3 className="text-lg font-semibold text-white">Create New Policy</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-slate-400 block mb-1">Policy Name *</label>
                  <input
                    value={newPolicy.name}
                    onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                    className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50"
                    placeholder="e.g., Fintech Default"
                  />
                </div>
                <div>
                  <label className="text-sm text-slate-400 block mb-1">Policy ID</label>
                  <input
                    value={`pol-${String(policies.length + 1).padStart(3, '0')}`}
                    disabled
                    className="w-full bg-slate-900/30 border border-slate-700/30 rounded-lg px-4 py-2 text-sm text-slate-500 font-mono"
                  />
                </div>
              </div>
              <div>
                <label className="text-sm text-slate-400 block mb-1">Description</label>
                <input
                  value={newPolicy.description}
                  onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
                  className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50"
                  placeholder="Brief description of this policy..."
                />
              </div>
              <div>
                <label className="text-sm text-slate-400 block mb-2">Compliance Packs</label>
                <div className="flex gap-2 flex-wrap">
                  {COMPLIANCE_PACKS.map((pack) => (
                    <label key={pack} className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={newPolicy.compliance_packs.includes(pack)}
                        onChange={() => toggleCompliancePack(pack)}
                        className="w-3.5 h-3.5 rounded border-slate-600 text-emerald-500 focus:ring-emerald-500/30 bg-slate-900"
                      />
                      <span className="text-xs text-slate-300">{pack}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <label className="text-sm text-slate-400 block mb-1">YAML Template</label>
                <select
                  value={newPolicy.template}
                  onChange={(e) => {
                    const t = e.target.value;
                    setNewPolicy({ ...newPolicy, template: t });
                    if (t && TEMPLATE_YAML[t]) setNewYaml(TEMPLATE_YAML[t].replace('name: ""', `name: "${newPolicy.name || ''}"`));
                  }}
                  className="w-full bg-slate-900/50 border border-slate-700/50 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-emerald-500/50"
                >
                  <option value="">Select a template...</option>
                  {TEMPLATES.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              {newYaml && (
                <div>
                  <label className="text-sm text-slate-400 block mb-1">Policy YAML</label>
                  <textarea
                    value={newYaml}
                    onChange={(e) => setNewYaml(e.target.value)}
                    className="w-full h-64 bg-slate-950 border border-slate-700/50 rounded-lg p-4 text-sm text-emerald-300 font-mono resize-none focus:outline-none focus:border-emerald-500/50 leading-relaxed"
                    spellCheck={false}
                  />
                </div>
              )}
              <div className="flex gap-3">
                <button
                  onClick={handleCreate}
                  disabled={creating || !newPolicy.name}
                  className="px-6 py-2 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2"
                >
                  {creating ? <Spinner /> : null} Create Policy
                </button>
                <button onClick={() => setShowCreate(false)} className="px-6 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm font-medium transition-all">
                  Cancel
                </button>
              </div>
            </div>
          ) : selected ? (
            <>
              {/* Policy Header */}
              <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-semibold text-white">{selected.name}</h3>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium border ${STATUS_COLORS[selected.status] || STATUS_COLORS.DRAFT}`}>
                        {(selected.status || 'DRAFT').toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm text-slate-400 mt-1">{selected.description}</p>
                    <p className="text-xs text-slate-600 mt-1 font-mono">{selected.id}</p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setShowSimulation(!showSimulation)}
                      className="px-3 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 rounded-lg text-xs font-medium transition-all border border-cyan-500/30"
                    >
                      Test Policy
                    </button>
                    <button
                      onClick={handleArchive}
                      className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-xs font-medium transition-all"
                    >
                      Archive
                    </button>
                  </div>
                </div>

                <div className="flex gap-2 flex-wrap">
                  {(selected.compliance_packs || []).map((c) => (
                    <span key={c} className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400">{c}</span>
                  ))}
                </div>

                {selected.entity_rules && selected.entity_rules.length > 0 && (
                  <div className="mt-4">
                    <div className="text-xs text-slate-500 mb-2">Entity Rules</div>
                    <div className="space-y-1">
                      {selected.entity_rules.map((r, i) => (
                        <div key={i} className="flex items-center gap-3 text-xs p-2 rounded bg-slate-900/50">
                          <span className="text-slate-300 font-mono w-32">{r.entity_type}</span>
                          <span className={`px-2 py-0.5 rounded ${ACTION_COLORS[r.action] || 'bg-slate-700 text-slate-400'}`}>{r.action}</span>
                          <span className="text-slate-500 ml-auto">min: {r.min_confidence}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Policy Simulation */}
              {showSimulation && (
                <div className="bg-slate-800/70 backdrop-blur-sm border border-cyan-500/30 rounded-xl p-5 space-y-4">
                  <h3 className="text-sm font-semibold text-cyan-400">Policy Simulation</h3>
                  <textarea
                    value={simText}
                    onChange={(e) => setSimText(e.target.value)}
                    placeholder="Enter sample text to test against this policy..."
                    className="w-full h-24 bg-slate-900/50 border border-slate-700/50 rounded-lg p-3 text-sm text-slate-300 font-mono resize-none focus:outline-none focus:border-cyan-500/50"
                  />
                  <button
                    onClick={handleSimulate}
                    disabled={simulating || !simText.trim()}
                    className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2"
                  >
                    {simulating ? <><Spinner /> Simulating...</> : 'Run Simulation'}
                  </button>
                  {simResult && (
                    <div className="space-y-3 p-4 rounded-lg bg-slate-900/50 border border-slate-700/30">
                      <div className="text-xs text-slate-500">Entities detected by <span className="text-emerald-400">{simResult.policy_name}</span></div>
                      <div className="flex gap-2 flex-wrap">
                        {(simResult.entities || []).map((e, i) => (
                          <div key={i} className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700/50">
                            <span className="text-slate-300 font-mono">{e.value}</span>
                            <span className={`ml-2 px-1.5 py-0.5 rounded ${ACTION_COLORS[e.action] || 'bg-slate-700 text-slate-400'}`}>{e.action}</span>
                            <span className="ml-2 text-slate-500">{e.type}</span>
                            <span className="ml-1 text-slate-600">({(e.confidence * 100).toFixed(0)}%)</span>
                          </div>
                        ))}
                      </div>
                      <div>
                        <div className="text-xs text-slate-500 mb-1">Protected Output</div>
                        <div className="bg-slate-950 rounded-lg p-3 text-sm text-cyan-300 font-mono whitespace-pre-wrap">{simResult.protected_text}</div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* YAML Editor */}
              <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-slate-300">Policy YAML</h3>
                  <div className="flex items-center gap-2">
                    {validation !== null && (
                      <span className={`text-xs px-2 py-0.5 rounded flex items-center gap-1 ${validation.valid ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                        {validation.valid ? (
                          <><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg> Valid</>
                        ) : (
                          <><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg> Invalid</>
                        )}
                      </span>
                    )}
                    <button onClick={handleValidate} disabled={validating} className="text-xs px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded transition-all flex items-center gap-1">
                      {validating ? <Spinner /> : null} Validate
                    </button>
                    <button
                      onClick={handleSave}
                      disabled={saving || !yamlChanged}
                      className="text-xs px-3 py-1 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded transition-all flex items-center gap-1"
                    >
                      {saving ? <Spinner /> : null} Save
                    </button>
                  </div>
                </div>

                {validation && !validation.valid && validation.errors && validation.errors.length > 0 && (
                  <div className="mb-3 p-2 rounded bg-red-500/10 border border-red-500/20">
                    {validation.errors.map((err, i) => <div key={i} className="text-xs text-red-400">{err}</div>)}
                  </div>
                )}

                <textarea
                  value={editYaml}
                  onChange={(e) => { setEditYaml(e.target.value); setValidation(null); }}
                  className="w-full h-80 bg-slate-950 border border-slate-700/50 rounded-lg p-4 text-sm text-emerald-300 font-mono resize-none focus:outline-none focus:border-emerald-500/50 leading-relaxed"
                  spellCheck={false}
                />
              </div>

              {/* Policy Diff */}
              {yamlChanged && (
                <div className="bg-slate-800/70 backdrop-blur-sm border border-amber-500/30 rounded-xl p-5">
                  <h3 className="text-sm font-semibold text-amber-400 mb-3">Unsaved Changes</h3>
                  <div className="space-y-0.5 font-mono text-xs max-h-48 overflow-y-auto">
                    {diffLines().map((d, i) => (
                      <div key={i} className={`px-3 py-1 rounded ${d.type === 'removed' ? 'bg-red-500/10 text-red-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
                        <span className="text-slate-600 mr-2">{d.line}</span>
                        <span>{d.type === 'removed' ? '- ' : '+ '}{d.text}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-12 flex flex-col items-center justify-center text-center">
              <svg className="w-12 h-12 text-slate-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
              <h3 className="text-lg font-medium text-slate-400">Select a policy</h3>
              <p className="text-sm text-slate-500 mt-1">Choose a policy from the list to view and edit its configuration.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
