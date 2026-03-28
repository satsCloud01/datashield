import React, { useState, useEffect, useCallback } from 'react';

const STATUS_COLORS = {
  COMPLIANT: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  PARTIAL: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  NON_COMPLIANT: 'text-red-400 bg-red-500/10 border-red-500/20',
};

const FRAMEWORK_ICONS = {
  GDPR: (<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>),
  HIPAA: (<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" /></svg>),
  'PCI-DSS': (<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" /></svg>),
  CCPA: (<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" /></svg>),
  SOX: (<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>),
  'EU-AI-ACT': (<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>),
  'ISO-27701': (<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" /></svg>),
  FERPA: (<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253" /></svg>),
};

const CONTROL_ICONS = {
  PASS: (<svg className="w-4 h-4 text-emerald-400" fill="currentColor" viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" /></svg>),
  FAIL: (<svg className="w-4 h-4 text-red-400" fill="currentColor" viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12 19 6.41z" /></svg>),
  NOT_ASSESSED: (<svg className="w-4 h-4 text-slate-500" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" /></svg>),
};

export default function Compliance() {
  const [summary, setSummary] = useState(null);
  const [frameworks, setFrameworks] = useState([]);
  const [selectedCode, setSelectedCode] = useState(null);
  const [frameworkDetail, setFrameworkDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [assessing, setAssessing] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [error, setError] = useState(null);

  const fetchSummary = useCallback(async () => {
    try {
      const res = await fetch('/api/compliance/summary');
      if (res.ok) setSummary(await res.json());
    } catch { setError('Failed to load compliance summary'); }
  }, []);

  const fetchFrameworks = useCallback(async () => {
    try {
      const res = await fetch('/api/compliance/frameworks');
      if (res.ok) {
        const d = await res.json();
        setFrameworks(Array.isArray(d) ? d : d.frameworks || []);
      }
    } catch { setError('Failed to load frameworks'); }
  }, []);

  useEffect(() => {
    setLoading(true);
    Promise.all([fetchSummary(), fetchFrameworks()]).finally(() => setLoading(false));
  }, [fetchSummary, fetchFrameworks]);

  const selectFramework = async (code) => {
    setSelectedCode(code);
    setDetailLoading(true);
    try {
      const res = await fetch(`/api/compliance/frameworks/${code}`);
      if (res.ok) setFrameworkDetail(await res.json());
    } catch {}
    setDetailLoading(false);
  };

  const handleAssess = async (code) => {
    setAssessing(true);
    try {
      const res = await fetch(`/api/compliance/assess/${code}`, { method: 'POST' });
      if (res.ok) {
        const d = await res.json();
        setFrameworkDetail(d);
        await fetchSummary();
        await fetchFrameworks();
      }
    } catch {}
    setAssessing(false);
  };

  const handleGenerateReport = async () => {
    try {
      const res = await fetch('/api/compliance/report');
      if (res.ok) {
        const d = await res.json();
        setReportData(d);
      }
    } catch {}
  };

  const overallScore = summary?.overall_score ?? 0;
  const circumference = 2 * Math.PI * 70;
  const dashOffset = circumference - (overallScore / 100) * circumference;
  const scoreColor = overallScore > 85 ? '#10b981' : overallScore >= 65 ? '#f59e0b' : '#ef4444';

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin w-8 h-8 border-2 border-emerald-500 border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Compliance</h1>
        <button onClick={handleGenerateReport}
          className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg text-sm font-medium transition-all">
          Generate Report
        </button>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{error}
          <button onClick={() => setError(null)} className="ml-3 text-red-300 hover:text-white">Dismiss</button>
        </div>
      )}

      {/* Overall Score + Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-6 flex flex-col items-center justify-center">
          <svg className="w-44 h-44" viewBox="0 0 160 160">
            <circle cx="80" cy="80" r="70" fill="none" stroke="#1e293b" strokeWidth="10" />
            <circle cx="80" cy="80" r="70" fill="none" stroke={scoreColor} strokeWidth="10" strokeLinecap="round"
              strokeDasharray={circumference} strokeDashoffset={dashOffset}
              transform="rotate(-90 80 80)" className="transition-all duration-1000" />
            <text x="80" y="72" textAnchor="middle" className="text-3xl font-bold" fill={scoreColor}>{overallScore}%</text>
            <text x="80" y="95" textAnchor="middle" className="text-xs" fill="#64748b">Overall Score</text>
          </svg>
        </div>
        <div className="md:col-span-3 grid grid-cols-3 md:grid-cols-5 gap-4">
          {[
            { label: 'Compliant', value: summary?.frameworks_compliant ?? '-', color: 'text-emerald-400' },
            { label: 'Partial', value: summary?.partial ?? '-', color: 'text-amber-400' },
            { label: 'Non-Compliant', value: summary?.non_compliant ?? '-', color: 'text-red-400' },
            { label: 'Total Controls', value: summary?.controls_total ?? '-', color: 'text-white' },
            { label: 'Controls Passing', value: summary?.controls_passing ?? '-', color: 'text-emerald-400' },
          ].map((m) => (
            <div key={m.label} className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-4 text-center">
              <div className={`text-2xl font-bold ${m.color}`}>{m.value}</div>
              <div className="text-xs text-slate-500 mt-1">{m.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Framework Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {frameworks.map((f) => {
          const code = f.code || f.id;
          const pct = f.controls_total > 0 ? ((f.controls_passing / f.controls_total) * 100).toFixed(0) : 0;
          const status = (f.status || '').toUpperCase();
          const icon = FRAMEWORK_ICONS[code?.toUpperCase()] || FRAMEWORK_ICONS['GDPR'];
          return (
            <div key={code} onClick={() => selectFramework(code)}
              className={`bg-slate-800/70 border backdrop-blur-sm rounded-xl p-5 cursor-pointer transition-all hover:border-emerald-500/30 ${
                selectedCode === code ? 'border-emerald-500/50' : 'border-slate-700'
              }`}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">{icon}</span>
                  <h3 className="text-lg font-bold text-white">{f.name}</h3>
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium border ${STATUS_COLORS[status] || 'text-slate-400 bg-slate-700/50 border-slate-600'}`}>
                  {status || 'UNKNOWN'}
                </span>
              </div>
              <div className="text-[10px] text-cyan-400 mb-1">{f.category}</div>
              <p className="text-xs text-slate-400 mb-3 line-clamp-2">{f.description}</p>
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-slate-500">{f.controls_passing}/{f.controls_total} controls</span>
                <span className="text-emerald-400">{pct}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${pct}%`, background: pct > 85 ? '#10b981' : pct >= 65 ? '#f59e0b' : '#ef4444' }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Framework Detail */}
      {selectedCode && (
        <div className="bg-slate-800/70 border border-slate-700 backdrop-blur-sm rounded-xl p-6">
          {detailLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full" />
            </div>
          ) : frameworkDetail ? (
            <>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-xl font-bold text-white">{frameworkDetail.name}</h3>
                  <p className="text-sm text-slate-400">{frameworkDetail.description}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-cyan-400">{frameworkDetail.category}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium border ${
                      STATUS_COLORS[(frameworkDetail.status || '').toUpperCase()] || ''
                    }`}>{(frameworkDetail.status || '').toUpperCase()}</span>
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => handleAssess(selectedCode)} disabled={assessing}
                    className="px-4 py-2 bg-cyan-500 hover:bg-cyan-600 disabled:bg-slate-700 text-white rounded-lg text-sm font-medium transition-all">
                    {assessing ? 'Assessing...' : 'Run Assessment'}
                  </button>
                  <button onClick={() => { setSelectedCode(null); setFrameworkDetail(null); }}
                    className="text-slate-400 hover:text-white p-2">
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                  </button>
                </div>
              </div>

              {/* Pass/Fail bar */}
              {frameworkDetail.controls && frameworkDetail.controls.length > 0 && (() => {
                const passing = frameworkDetail.controls.filter((c) => (c.status || '').toUpperCase() === 'PASS').length;
                const total = frameworkDetail.controls.length;
                const pct = total > 0 ? ((passing / total) * 100).toFixed(0) : 0;
                return (
                  <div className="mb-4">
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-500">{passing} passing / {total} total</span>
                      <span className="text-emerald-400">{pct}%</span>
                    </div>
                    <div className="w-full h-2 bg-slate-700 rounded-full overflow-hidden">
                      <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })()}

              {/* Controls table */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-slate-500 text-xs border-b border-slate-700/50">
                      <th className="text-left py-2 px-2 font-medium w-8"></th>
                      <th className="text-left py-2 px-2 font-medium">Control ID</th>
                      <th className="text-left py-2 px-2 font-medium">Name</th>
                      <th className="text-left py-2 px-2 font-medium">Description</th>
                      <th className="text-left py-2 px-2 font-medium">Evidence</th>
                      <th className="text-left py-2 px-2 font-medium">Severity</th>
                      <th className="text-left py-2 px-2 font-medium">Last Checked</th>
                      <th className="text-left py-2 px-2 font-medium">Remediation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(frameworkDetail.controls || []).map((c) => {
                      const st = (c.status || '').toUpperCase();
                      return (
                        <tr key={c.control_id || c.id} className="border-b border-slate-800/50">
                          <td className="py-2 px-2">{CONTROL_ICONS[st] || CONTROL_ICONS.NOT_ASSESSED}</td>
                          <td className="py-2 px-2 text-slate-400 font-mono text-xs">{c.control_id || c.id}</td>
                          <td className="py-2 px-2 text-white text-xs">{c.name}</td>
                          <td className="py-2 px-2 text-slate-400 text-xs max-w-[200px]">{c.description || c.desc}</td>
                          <td className="py-2 px-2 text-slate-500 text-xs">{c.evidence_type || '-'}</td>
                          <td className="py-2 px-2">
                            {c.severity && (
                              <span className={`text-xs px-2 py-0.5 rounded-full ${
                                c.severity === 'HIGH' || c.severity === 'CRITICAL' ? 'text-red-400 bg-red-500/10'
                                : c.severity === 'MEDIUM' ? 'text-amber-400 bg-amber-500/10'
                                : 'text-blue-400 bg-blue-500/10'
                              }`}>{c.severity}</span>
                            )}
                          </td>
                          <td className="py-2 px-2 text-slate-500 text-xs">{c.last_checked ? new Date(c.last_checked).toLocaleDateString() : '-'}</td>
                          <td className="py-2 px-2 text-xs text-slate-400 max-w-[180px]">{c.remediation_hint || c.remediation || '-'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <div className="text-center text-slate-500 py-8">No detail available</div>
          )}
        </div>
      )}

      {/* Top Gaps */}
      {summary?.top_gaps && summary.top_gaps.length > 0 && (
        <div className="bg-red-500/5 border border-red-500/20 backdrop-blur-sm rounded-xl p-5">
          <h3 className="text-lg font-semibold text-red-400 mb-4 flex items-center gap-2">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Top Compliance Gaps
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-slate-500 text-xs border-b border-red-500/10">
                  <th className="text-left py-2 px-2 font-medium">Framework</th>
                  <th className="text-left py-2 px-2 font-medium">Control ID</th>
                  <th className="text-left py-2 px-2 font-medium">Name</th>
                  <th className="text-left py-2 px-2 font-medium">Severity</th>
                  <th className="text-left py-2 px-2 font-medium">Remediation</th>
                </tr>
              </thead>
              <tbody>
                {summary.top_gaps.map((g, i) => (
                  <tr key={i} className="border-b border-slate-800/30">
                    <td className="py-2 px-2 text-white text-xs font-medium">{g.framework}</td>
                    <td className="py-2 px-2 text-slate-400 font-mono text-xs">{g.control_id}</td>
                    <td className="py-2 px-2 text-slate-300 text-xs">{g.name}</td>
                    <td className="py-2 px-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                        g.severity === 'HIGH' || g.severity === 'CRITICAL' ? 'text-red-400 bg-red-500/10'
                        : g.severity === 'MEDIUM' ? 'text-amber-400 bg-amber-500/10'
                        : 'text-blue-400 bg-blue-500/10'
                      }`}>{g.severity}</span>
                    </td>
                    <td className="py-2 px-2 text-slate-400 text-xs">{g.remediation_hint || g.remediation || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Report Modal */}
      {reportData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm" onClick={() => setReportData(null)}>
          <div className="bg-slate-800/90 border border-slate-700 rounded-xl p-6 max-w-3xl w-full mx-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Compliance Report</h3>
              <div className="flex gap-2">
                <button onClick={() => {
                  const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `compliance-report-${new Date().toISOString().slice(0, 10)}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }} className="px-3 py-1.5 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg text-xs">Download JSON</button>
                <button onClick={() => setReportData(null)} className="text-slate-400 hover:text-white">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </div>
            </div>
            <pre className="text-xs text-slate-300 font-mono bg-slate-900/50 rounded-lg p-4 overflow-auto max-h-[60vh] whitespace-pre-wrap">
              {JSON.stringify(reportData, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
