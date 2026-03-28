import React, { useState, useEffect } from 'react';

const CATEGORY_COLORS = {
  PII: { bg: 'bg-cyan-500/20', text: 'text-cyan-400', border: 'border-cyan-500/30', hex: '#22d3ee' },
  PHI: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', hex: '#ef4444' },
  PCI: { bg: 'bg-amber-500/20', text: 'text-amber-400', border: 'border-amber-500/30', hex: '#f59e0b' },
  FINANCIAL: { bg: 'bg-purple-500/20', text: 'text-purple-400', border: 'border-purple-500/30', hex: '#a855f7' },
  IP_CODE: { bg: 'bg-rose-500/20', text: 'text-rose-400', border: 'border-rose-500/30', hex: '#f43f5e' },
  CUSTOM: { bg: 'bg-slate-500/20', text: 'text-slate-400', border: 'border-slate-500/30', hex: '#64748b' },
};

const PROTECT_MODES = ['REDACT', 'TOKENIZE', 'PSEUDONYMIZE', 'GENERALIZE', 'ENCRYPT', 'SYNTHESIZE'];

const DEFAULT_SAMPLE = `Process loan application for John Smith, SSN 123-45-6789, email john.smith@acme.com, phone (555) 867-5309. Credit card: 4532-0151-1283-0366, exp 12/28. Patient DOB: 1985-03-15. IP: 192.168.1.100. API Key: sk-ant-api03-xxxxxxxxxxxx`;

export default function Scanner() {
  const [tab, setTab] = useState('single'); // single | batch
  const [text, setText] = useState(DEFAULT_SAMPLE);
  const [batchTexts, setBatchTexts] = useState(['', '']);
  const [samples, setSamples] = useState([]);
  const [selectedSample, setSelectedSample] = useState('');
  const [results, setResults] = useState(null);
  const [batchResults, setBatchResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [protectMode, setProtectMode] = useState('TOKENIZE');
  const [protectResult, setProtectResult] = useState(null);
  const [protecting, setProtecting] = useState(false);
  const [restoreResult, setRestoreResult] = useState(null);
  const [restoring, setRestoring] = useState(false);
  const [entityRegistry, setEntityRegistry] = useState([]);
  const [registryOpen, setRegistryOpen] = useState(false);
  const [registrySearch, setRegistrySearch] = useState('');
  const [registryFilter, setRegistryFilter] = useState('ALL');
  const [hoveredEntity, setHoveredEntity] = useState(null);

  // Fetch samples
  useEffect(() => {
    fetch('/api/scan/samples')
      .then((r) => r.ok ? r.json() : Promise.reject())
      .then((data) => {
        const list = Array.isArray(data) ? data : data.samples || [];
        setSamples(list);
      })
      .catch(() => setSamples([]));
  }, []);

  // Fetch entity registry
  useEffect(() => {
    if (registryOpen && entityRegistry.length === 0) {
      fetch('/api/scan/entity-registry')
        .then((r) => r.ok ? r.json() : Promise.reject())
        .then((data) => setEntityRegistry(Array.isArray(data) ? data : data.entities || []))
        .catch(() => setEntityRegistry([]));
    }
  }, [registryOpen, entityRegistry.length]);

  const handleSampleSelect = (sample) => {
    setSelectedSample(sample.name || sample.label || '');
    setText(sample.text || sample.content || '');
    setResults(null);
    setProtectResult(null);
    setRestoreResult(null);
  };

  const handleScan = async () => {
    setScanning(true);
    setResults(null);
    setProtectResult(null);
    setRestoreResult(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      });
      if (res.ok) {
        setResults(await res.json());
      } else {
        setResults({ error: 'Scan failed', entities: [] });
      }
    } catch {
      setResults({ error: 'Network error', entities: [] });
    } finally {
      setScanning(false);
    }
  };

  const handleBatchScan = async () => {
    setScanning(true);
    setBatchResults(null);
    try {
      const res = await fetch('/api/scan/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ texts: batchTexts.filter((t) => t.trim()) }),
      });
      if (res.ok) {
        setBatchResults(await res.json());
      } else {
        setBatchResults({ error: 'Batch scan failed' });
      }
    } catch {
      setBatchResults({ error: 'Network error' });
    } finally {
      setScanning(false);
    }
  };

  const handleProtect = async () => {
    if (!results?.entities?.length) return;
    setProtecting(true);
    setProtectResult(null);
    setRestoreResult(null);
    try {
      const res = await fetch('/api/protect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, entities: results.entities, mode: protectMode }),
      });
      if (res.ok) {
        setProtectResult(await res.json());
      }
    } catch {} finally {
      setProtecting(false);
    }
  };

  const handleRestore = async () => {
    if (!protectResult?.vault_ref) return;
    setRestoring(true);
    setRestoreResult(null);
    try {
      const res = await fetch('/api/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vault_ref: protectResult.vault_ref, sanitized_text: protectResult.sanitized_text }),
      });
      if (res.ok) {
        const data = await res.json();
        setRestoreResult(data);
      }
    } catch {} finally {
      setRestoring(false);
    }
  };

  const getCategoryStyle = (category) => CATEGORY_COLORS[category] || CATEGORY_COLORS.CUSTOM;

  // Build highlighted text with inline entity spans
  const renderHighlightedText = () => {
    if (!results?.entities?.length) return <span className="text-slate-300">{text}</span>;
    const sorted = [...results.entities].sort((a, b) => a.start - b.start);
    const parts = [];
    let lastEnd = 0;
    for (let i = 0; i < sorted.length; i++) {
      const ent = sorted[i];
      if (ent.start > lastEnd) {
        parts.push(<span key={`t-${lastEnd}`} className="text-slate-300">{text.slice(lastEnd, ent.start)}</span>);
      }
      const cat = ent.category || 'CUSTOM';
      const style = getCategoryStyle(cat);
      parts.push(
        <span
          key={`e-${i}`}
          className={`${style.bg} ${style.text} ${style.border} border rounded px-0.5 py-px inline-block cursor-pointer relative transition-all hover:scale-105`}
          onMouseEnter={() => setHoveredEntity(i)}
          onMouseLeave={() => setHoveredEntity(null)}
        >
          {text.slice(ent.start, ent.end)}
          {hoveredEntity === i && (
            <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 bg-slate-900 border border-slate-600 rounded-lg p-3 text-xs whitespace-nowrap z-50 shadow-xl">
              <div className="text-white font-semibold">{ent.type}</div>
              <div className="text-slate-400">Category: {cat}</div>
              <div className="text-slate-400">Confidence: {((ent.confidence || 0) * 100).toFixed(1)}%</div>
              {ent.risk_level && <div className="text-slate-400">Risk: {ent.risk_level}</div>}
              {ent.regulatory_basis && <div className="text-slate-400 mt-1">{ent.regulatory_basis}</div>}
            </span>
          )}
        </span>
      );
      lastEnd = ent.end;
    }
    if (lastEnd < text.length) {
      parts.push(<span key={`t-${lastEnd}`} className="text-slate-300">{text.slice(lastEnd)}</span>);
    }
    return parts;
  };

  // Summarize entities by category
  const categorySummary = () => {
    if (!results?.entities) return {};
    const map = {};
    for (const e of results.entities) {
      const cat = e.category || 'CUSTOM';
      map[cat] = (map[cat] || 0) + 1;
    }
    return map;
  };

  // Entity registry filtering
  const filteredRegistry = entityRegistry.filter((e) => {
    const matchSearch = !registrySearch || e.type?.toLowerCase().includes(registrySearch.toLowerCase()) || e.category?.toLowerCase().includes(registrySearch.toLowerCase());
    const matchFilter = registryFilter === 'ALL' || e.category === registryFilter;
    return matchSearch && matchFilter;
  });
  const registryCategories = [...new Set(entityRegistry.map((e) => e.category))];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">PII Scanner</h1>
        {results?.entities?.length > 0 && (
          <span className="px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-400 text-sm font-semibold">
            {results.entities.length} entities found
          </span>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        <button onClick={() => setTab('single')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${tab === 'single' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800/70 text-slate-400 border border-slate-700 hover:text-white'}`}>
          Single Scan
        </button>
        <button onClick={() => setTab('batch')} className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${tab === 'batch' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800/70 text-slate-400 border border-slate-700 hover:text-white'}`}>
          Batch Scan
        </button>
      </div>

      {tab === 'single' ? (
        <>
          {/* Sample Selector */}
          {samples.length > 0 && (
            <div className="flex gap-2 flex-wrap">
              {samples.map((s, i) => (
                <button
                  key={i}
                  onClick={() => handleSampleSelect(s)}
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all hover:scale-105 ${
                    selectedSample === (s.name || s.label)
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      : 'bg-slate-800/70 text-slate-400 border border-slate-700 hover:text-white'
                  }`}
                >
                  {s.name || s.label || `Sample ${i + 1}`}
                </button>
              ))}
            </div>
          )}

          {/* Main Scanner Area */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Input + Highlighted */}
            <div className="space-y-4">
              <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-4">
                <label className="text-sm font-medium text-slate-300 mb-2 block">Input Text</label>
                <textarea
                  value={text}
                  onChange={(e) => { setText(e.target.value); setResults(null); setProtectResult(null); setRestoreResult(null); }}
                  className="w-full h-64 bg-slate-900/50 border border-slate-700/50 rounded-lg p-4 text-sm text-slate-300 font-mono resize-none focus:outline-none focus:border-emerald-500/50 placeholder-slate-600"
                  placeholder="Paste text containing PII, PHI, PCI data..."
                />
                <button
                  onClick={handleScan}
                  disabled={scanning || !text.trim()}
                  className="mt-3 w-full py-3 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg font-semibold transition-all flex items-center justify-center gap-2 hover:scale-[1.01]"
                >
                  {scanning ? (
                    <>
                      <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/></svg>
                      Scanning...
                    </>
                  ) : 'Scan'}
                </button>
              </div>

              {/* Highlighted Text View */}
              {results && results.entities?.length > 0 && (
                <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-4">
                  <label className="text-sm font-medium text-slate-300 mb-2 block">Highlighted Results</label>
                  <div className="bg-slate-900/50 rounded-lg p-4 text-sm font-mono leading-relaxed whitespace-pre-wrap">
                    {renderHighlightedText()}
                  </div>
                </div>
              )}
            </div>

            {/* Right: Results Panel */}
            <div className="space-y-4">
              {results ? (
                <>
                  {results.error && (
                    <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-red-400 text-sm">{results.error}</div>
                  )}

                  {/* Summary */}
                  <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-sm font-semibold text-slate-300">Scan Results</h3>
                      <div className="flex items-center gap-3 text-xs text-slate-500">
                        {results.scan_id && <span>ID: {results.scan_id}</span>}
                        {results.latency_ms != null && <span className="text-emerald-400">{results.latency_ms}ms</span>}
                      </div>
                    </div>
                    <div className="text-3xl font-bold text-emerald-400 mb-2">{results.entities?.length || 0}</div>
                    <div className="text-sm text-slate-400 mb-3">entities detected</div>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(categorySummary()).map(([cat, count]) => {
                        const style = getCategoryStyle(cat);
                        return (
                          <span key={cat} className={`text-xs px-2 py-1 rounded-full ${style.bg} ${style.text} ${style.border} border font-medium`}>
                            {cat}: {count}
                          </span>
                        );
                      })}
                    </div>
                  </div>

                  {/* Entity Cards */}
                  {results.entities?.length > 0 && (
                    <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-4">
                      <h3 className="text-sm font-semibold text-slate-300 mb-3">Detected Entities</h3>
                      <div className="space-y-2 max-h-[400px] overflow-y-auto">
                        {results.entities.map((ent, i) => {
                          const cat = ent.category || 'CUSTOM';
                          const style = getCategoryStyle(cat);
                          return (
                            <div key={i} className="p-3 rounded-lg bg-slate-900/50 border border-slate-700/30 hover:border-slate-600/50 transition-all">
                              <div className="flex items-center justify-between mb-1">
                                <div className="flex items-center gap-2">
                                  <span className={`text-xs px-2 py-0.5 rounded font-mono font-medium border ${style.bg} ${style.text} ${style.border}`}>{ent.type}</span>
                                  {ent.risk_level && (
                                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                                      ent.risk_level === 'CRITICAL' ? 'bg-red-500/10 text-red-400' :
                                      ent.risk_level === 'HIGH' ? 'bg-orange-500/10 text-orange-400' :
                                      ent.risk_level === 'MEDIUM' ? 'bg-yellow-500/10 text-yellow-400' :
                                      'bg-blue-500/10 text-blue-400'
                                    }`}>{ent.risk_level}</span>
                                  )}
                                </div>
                                <div className="flex items-center gap-2">
                                  <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                                    <div className="h-full bg-emerald-400 rounded-full" style={{ width: `${(ent.confidence || 0) * 100}%` }} />
                                  </div>
                                  <span className="text-xs text-slate-400 w-12 text-right">{((ent.confidence || 0) * 100).toFixed(1)}%</span>
                                </div>
                              </div>
                              <div className="text-sm text-slate-300 font-mono truncate">{ent.value || text.slice(ent.start, ent.end)}</div>
                              {ent.regulatory_basis && <div className="text-xs text-slate-500 mt-1">{ent.regulatory_basis}</div>}
                              {ent.default_action && <div className="text-xs text-slate-500">Action: {ent.default_action}</div>}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-12 flex flex-col items-center justify-center text-center">
                  <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center mb-4">
                    <svg className="w-8 h-8 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-medium text-slate-400 mb-1">Ready to Scan</h3>
                  <p className="text-sm text-slate-500">Enter or select sample text and click Scan to detect entities.</p>
                </div>
              )}
            </div>
          </div>

          {/* Protect Section */}
          {results?.entities?.length > 0 && (
            <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-slate-300 mb-4">Protect Data</h3>
              <div className="flex flex-wrap gap-3 mb-4">
                {PROTECT_MODES.map((mode) => (
                  <label key={mode} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="protectMode"
                      value={mode}
                      checked={protectMode === mode}
                      onChange={() => setProtectMode(mode)}
                      className="accent-emerald-500"
                    />
                    <span className={`text-sm ${protectMode === mode ? 'text-emerald-400 font-medium' : 'text-slate-400'}`}>{mode}</span>
                  </label>
                ))}
              </div>
              <button
                onClick={handleProtect}
                disabled={protecting}
                className="px-6 py-2.5 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg font-semibold transition-all hover:scale-[1.01]"
              >
                {protecting ? 'Protecting...' : `Protect with ${protectMode}`}
              </button>

              {protectResult && (
                <div className="mt-4 space-y-4">
                  <div>
                    <label className="text-xs font-medium text-slate-400 mb-1 block">Sanitized Output</label>
                    <textarea
                      readOnly
                      value={protectResult.sanitized_text || ''}
                      className="w-full h-40 bg-slate-950 border border-slate-700/50 rounded-lg p-4 text-sm text-emerald-300 font-mono resize-none"
                    />
                  </div>

                  {/* Mapping Table */}
                  {protectResult.entity_mapping?.length > 0 && (
                    <div>
                      <label className="text-xs font-medium text-slate-400 mb-2 block">Entity Mapping</label>
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                              <th className="text-left py-2 font-medium">Original</th>
                              <th className="text-left py-2 font-medium">Replacement</th>
                              <th className="text-left py-2 font-medium">Type</th>
                            </tr>
                          </thead>
                          <tbody>
                            {protectResult.entity_mapping.map((m, i) => (
                              <tr key={i} className="border-b border-slate-800/50">
                                <td className="py-2 text-red-400 font-mono text-xs">{m.original}</td>
                                <td className="py-2 text-emerald-400 font-mono text-xs">{m.replacement || m.token}</td>
                                <td className="py-2 text-slate-400 text-xs">{m.type}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Restore */}
                  {protectResult.vault_ref && (
                    <div className="border-t border-slate-700/50 pt-4">
                      <div className="flex items-center gap-3">
                        <button
                          onClick={handleRestore}
                          disabled={restoring}
                          className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg font-semibold transition-all hover:scale-[1.01]"
                        >
                          {restoring ? 'Restoring...' : 'Restore Original'}
                        </button>
                        <span className="text-xs text-slate-500">Vault: {protectResult.vault_ref}</span>
                      </div>
                      {restoreResult && (
                        <div className="mt-3">
                          <textarea
                            readOnly
                            value={restoreResult.restored_text || ''}
                            className="w-full h-32 bg-slate-950 border border-slate-700/50 rounded-lg p-4 text-sm text-slate-300 font-mono resize-none"
                          />
                          {restoreResult.restored_text === text && (
                            <div className="flex items-center gap-2 mt-2 text-emerald-400 text-sm">
                              <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                              </svg>
                              Restore matches original text
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        /* Batch Scan Tab */
        <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Batch Scan</h3>
          <div className="space-y-3">
            {batchTexts.map((bt, i) => (
              <div key={i} className="flex gap-2">
                <textarea
                  value={bt}
                  onChange={(e) => {
                    const next = [...batchTexts];
                    next[i] = e.target.value;
                    setBatchTexts(next);
                  }}
                  className="flex-1 h-24 bg-slate-900/50 border border-slate-700/50 rounded-lg p-3 text-sm text-slate-300 font-mono resize-none focus:outline-none focus:border-emerald-500/50"
                  placeholder={`Text #${i + 1}...`}
                />
                {batchTexts.length > 1 && (
                  <button onClick={() => setBatchTexts(batchTexts.filter((_, j) => j !== i))} className="text-red-400 hover:text-red-300 text-sm px-2">Remove</button>
                )}
              </div>
            ))}
            <div className="flex gap-3">
              <button onClick={() => setBatchTexts([...batchTexts, ''])} className="text-sm text-emerald-400 hover:text-emerald-300">+ Add text</button>
              <button
                onClick={handleBatchScan}
                disabled={scanning || batchTexts.every((t) => !t.trim())}
                className="px-6 py-2.5 bg-emerald-500 hover:bg-emerald-600 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-lg font-semibold transition-all"
              >
                {scanning ? 'Scanning...' : 'Scan All'}
              </button>
            </div>
          </div>

          {batchResults && (
            <div className="mt-4 space-y-3">
              {batchResults.error ? (
                <div className="text-red-400 text-sm">{batchResults.error}</div>
              ) : (
                (batchResults.results || []).map((r, i) => (
                  <div key={i} className="p-3 rounded-lg bg-slate-900/50 border border-slate-700/30">
                    <div className="text-sm font-semibold text-white mb-1">Text #{i + 1}: {r.entities?.length || 0} entities</div>
                    <div className="flex flex-wrap gap-1">
                      {(r.entities || []).map((e, j) => (
                        <span key={j} className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400">{e.type}: {e.value || ''}</span>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}

      {/* Entity Registry (Collapsible) */}
      <div className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl">
        <button
          onClick={() => setRegistryOpen(!registryOpen)}
          className="w-full p-4 flex items-center justify-between text-left"
        >
          <h3 className="text-sm font-semibold text-slate-300">Entity Registry ({entityRegistry.length} types)</h3>
          <svg className={`w-5 h-5 text-slate-400 transition-transform ${registryOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {registryOpen && (
          <div className="px-4 pb-4">
            <div className="flex flex-wrap gap-3 mb-3">
              <input
                type="text"
                value={registrySearch}
                onChange={(e) => setRegistrySearch(e.target.value)}
                placeholder="Search entity types..."
                className="px-3 py-2 bg-slate-900/50 border border-slate-700/50 rounded-lg text-sm text-slate-300 focus:outline-none focus:border-emerald-500/50"
              />
              <select
                value={registryFilter}
                onChange={(e) => setRegistryFilter(e.target.value)}
                className="px-3 py-2 bg-slate-900/50 border border-slate-700/50 rounded-lg text-sm text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Categories</option>
                {registryCategories.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div className="max-h-80 overflow-y-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-slate-800">
                  <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                    <th className="text-left py-2 font-medium">Type</th>
                    <th className="text-left py-2 font-medium">Category</th>
                    <th className="text-left py-2 font-medium">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRegistry.map((e, i) => {
                    const style = getCategoryStyle(e.category);
                    return (
                      <tr key={i} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                        <td className="py-2 text-slate-300 font-mono text-xs">{e.type}</td>
                        <td className="py-2"><span className={`text-xs px-2 py-0.5 rounded ${style.bg} ${style.text}`}>{e.category}</span></td>
                        <td className="py-2 text-slate-400 text-xs">{e.description || '--'}</td>
                      </tr>
                    );
                  })}
                  {filteredRegistry.length === 0 && (
                    <tr><td colSpan={3} className="py-4 text-center text-slate-500 text-sm">No entities found</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
