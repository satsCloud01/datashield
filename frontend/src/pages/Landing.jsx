import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

/* ── Animated Counter ── */
function AnimatedCounter({ end, suffix = '', duration = 2000 }) {
  const [count, setCount] = useState(0);
  const ref = useRef(null);
  const started = useRef(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started.current) {
          started.current = true;
          const startTime = Date.now();
          const numEnd = parseFloat(end) || 0;
          const tick = () => {
            const elapsed = Date.now() - startTime;
            const progress = Math.min(elapsed / duration, 1);
            setCount(Math.floor(numEnd * progress));
            if (progress < 1) requestAnimationFrame(tick);
            else setCount(numEnd);
          };
          tick();
        }
      },
      { threshold: 0.3 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [end, duration]);

  return <span ref={ref}>{count}{suffix}</span>;
}

/* ── Data ── */
const threats = [
  { icon: 'M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21', title: 'Silent PII Leakage', desc: 'Sensitive data flows undetected through agent conversations and tool calls.' },
  { icon: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4', title: 'Uncontrolled RAG Retrieval', desc: 'Retrieval pipelines surface confidential documents without access controls.' },
  { icon: 'M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01', title: 'Cross-Agent Privilege Escalation', desc: 'Agents inherit and propagate permissions beyond their intended scope.' },
  { icon: 'M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4', title: 'Untraceable Data Exchange', desc: 'No audit trail for data moving between agents via MCP and A2A protocols.' },
  { icon: 'M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0zM9.75 9.75c0-1.38 1.12-2.5 2.25-2.5s2.25 1.12 2.25 2.5', title: 'Prompt Injection Exfiltration', desc: 'Crafted prompts trick agents into revealing protected information.' },
];

const solutionSteps = [
  { num: '01', title: 'Intercept', color: 'cyan', desc: 'Catch data flowing through any agentic surface before it reaches the LLM.', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  { num: '02', title: 'Detect', color: 'emerald', desc: 'Identify PII, PHI, PCI, secrets, and custom entities with ML + regex + context.', icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' },
  { num: '03', title: 'Protect', color: 'amber', desc: 'Tokenize, mask, or redact based on policy. Format-preserving, reversible tokens.', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
  { num: '04', title: 'Restore', color: 'purple', desc: 'Authorized agents restore original values. Full audit trail. Zero data loss.', icon: 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15' },
];

const stepColorMap = {
  cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
  emerald: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  amber: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  purple: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
};

const capabilities = [
  { title: 'Detection Engine', desc: '57 entity types, 6 categories, contextual scoring', icon: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z' },
  { title: 'Reversible Tokenization', desc: '6 obfuscation modes, session-scoped vault', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
  { title: 'Agentic Interceptor', desc: 'MCP, A2A, LLM API, RAG surface coverage', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  { title: 'Policy Engine', desc: 'YAML-based, GitOps-compatible, conflict detection', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
  { title: 'Semantic Validator', desc: '5 threat models, behavioral analysis, auto-block', icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z' },
  { title: 'Compliance Engine', desc: '8 frameworks, 78 controls, automated assessment', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2' },
];

const stats = [
  { value: 57, suffix: '+', label: 'Entity Types' },
  { value: 5, suffix: 'ms', label: 'Latency', prefix: '<' },
  { value: 6, suffix: '', label: 'Obfuscation Modes' },
  { value: 8, suffix: '', label: 'Compliance Frameworks' },
  { value: 5, suffix: '', label: 'Threat Models' },
];

const comparisonRows = [
  { feature: 'Agentic Surface Coverage', them: false, us: true },
  { feature: 'MCP / A2A Protocol Aware', them: false, us: true },
  { feature: 'Reversible Tokenization', them: false, us: true },
  { feature: 'Real-time (<5ms)', them: false, us: true },
  { feature: 'Context-Aware Detection', them: false, us: true },
  { feature: 'Policy-as-Code (YAML)', them: false, us: true },
  { feature: 'Semantic Threat Validation', them: false, us: true },
  { feature: 'Session-Scoped Vault', them: false, us: true },
];

const comparisonCols = ['DLP', 'DSPM', 'Legacy Masking', 'Open Source', 'AI Firewalls'];

const industries = [
  { name: 'BFSI', icon: 'M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z' },
  { name: 'Healthcare', icon: 'M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.682a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z' },
  { name: 'Tech / SaaS', icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4' },
  { name: 'Government', icon: 'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4' },
  { name: 'Legal', icon: 'M3 6l3 1m0 0l-3 9a5.002 5.002 0 006.001 0M6 7l3 9M6 7l6-2m6 2l3-1m-3 1l3 9a5.002 5.002 0 006.001 0M18 7l3 9m-3-9l-6-2m0-2v2m0 16V5m0 16H9m3 0h3' },
  { name: 'Retail', icon: 'M16 11V7a4 4 0 00-8 0v4M5 9h14l1 12H4L5 9z' },
];

export default function Landing() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-950 overflow-x-hidden">
      {/* Nav */}
      <nav className="fixed top-0 w-full z-50 glass border-b border-slate-700/50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/20 flex items-center justify-center text-emerald-400">
              <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
              </svg>
            </div>
            <span className="text-xl font-bold text-white">DataShield AI</span>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => navigate('/dashboard')} className="px-5 py-2 bg-emerald-500 hover:bg-emerald-600 text-white rounded-lg font-medium text-sm transition-all hover:scale-105">
              Launch Dashboard
            </button>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="hero-bg">
        {/* Animated background layers */}
        <div className="hero-grid" />
        <div className="hero-nodes" />
        <div className="hero-particles" />
        <div className="hero-matrix" />
        <div className="hero-overlay" />

        {/* Ambient glow blobs */}
        <div className="absolute inset-0 overflow-hidden" style={{ zIndex: 0 }}>
          <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[800px] h-[800px] bg-emerald-500/5 rounded-full blur-3xl" />
          <div className="absolute top-1/3 left-1/4 w-[400px] h-[400px] bg-cyan-500/5 rounded-full blur-3xl" />
        </div>

        {/* Hero content */}
        <div className="relative z-10 flex flex-col items-center justify-center min-h-screen pt-16 pb-24 px-6">
          <div className="max-w-5xl mx-auto text-center">
            <div className="inline-block mb-8">
              <div className="w-28 h-28 mx-auto rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center animate-shield-pulse">
                <svg className="w-16 h-16 text-emerald-400" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>
                </svg>
              </div>
            </div>
            <h1 className="text-5xl md:text-6xl font-extrabold tracking-tight mb-6">
              <span className="bg-gradient-to-r from-emerald-400 via-cyan-400 to-emerald-400 bg-clip-text text-transparent">DataShield AI</span>
            </h1>
            <p className="text-2xl text-slate-300 mb-4 font-light">
              Your AI agents should know what <span className="text-cyan-400 font-medium">not</span> to know.
            </p>
            <p className="text-lg text-slate-400 mb-10 max-w-2xl mx-auto">
              Real-time PII detection and reversible tokenization for the agentic AI era.
              Guard every MCP server, A2A protocol, LLM API, and RAG pipeline.
            </p>
            <div className="flex gap-4 justify-center flex-wrap">
              <button
                onClick={() => navigate('/dashboard')}
                className="px-8 py-3.5 bg-emerald-500 hover:bg-emerald-600 text-white rounded-xl font-semibold text-lg transition-all shadow-lg shadow-emerald-500/25 hover:shadow-emerald-500/40 hover:scale-105"
              >
                Launch Dashboard
              </button>
              <button
                onClick={() => navigate('/scanner')}
                className="px-8 py-3.5 border border-slate-600 hover:border-emerald-500/50 text-slate-300 hover:text-white rounded-xl font-semibold text-lg transition-all hover:scale-105"
              >
                Try Scanner Demo
              </button>
            </div>
          </div>

          {/* Scroll down indicator */}
          <div className="absolute bottom-8 left-1/2 -translate-x-1/2 scroll-indicator flex flex-col items-center gap-2">
            <span className="text-xs text-slate-500 uppercase tracking-widest">Scroll</span>
            <svg className="w-5 h-5 text-emerald-400/60" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 14l-7 7m0 0l-7-7m7 7V3" />
            </svg>
          </div>
        </div>
      </section>

      {/* Problem Section */}
      <section className="py-20 px-6 bg-slate-900/40">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-center text-white mb-4">The Agentic AI Data Crisis</h2>
          <p className="text-slate-400 text-center mb-12 max-w-2xl mx-auto">
            As AI agents become the primary interface to enterprise data, traditional security fails.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-5">
            {threats.map((t) => (
              <div key={t.title} className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5 hover:border-red-500/40 transition-all duration-300 hover:-translate-y-1 hover:scale-[1.02]">
                <div className="w-10 h-10 rounded-lg bg-red-500/10 flex items-center justify-center text-red-400 mb-3">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d={t.icon} />
                  </svg>
                </div>
                <h3 className="text-sm font-semibold text-white mb-1">{t.title}</h3>
                <p className="text-xs text-slate-400 leading-relaxed">{t.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Solution Section */}
      <section className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold text-center text-white mb-12">How DataShield Protects</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {solutionSteps.map((s, i) => (
              <div key={s.num} className="relative">
                <div className={`bg-slate-800/70 backdrop-blur-sm border rounded-xl p-6 text-center transition-all duration-300 hover:-translate-y-1 hover:scale-105 ${stepColorMap[s.color].split(' ').slice(2).join(' ') || 'border-slate-700'}`}>
                  <div className={`w-12 h-12 mx-auto rounded-lg ${stepColorMap[s.color].split(' ').slice(1, 2).join(' ')} flex items-center justify-center ${stepColorMap[s.color].split(' ')[0]} mb-3`}>
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" d={s.icon} />
                    </svg>
                  </div>
                  <div className="text-3xl font-black opacity-20 mb-1">{s.num}</div>
                  <h3 className={`text-lg font-bold mb-2 ${stepColorMap[s.color].split(' ')[0]}`}>{s.title}</h3>
                  <p className="text-sm text-slate-400">{s.desc}</p>
                </div>
                {i < 3 && (
                  <div className="hidden md:block absolute top-1/2 -right-3 transform -translate-y-1/2 text-emerald-500/30">
                    <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M10 6l6 6-6 6V6z" />
                    </svg>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Capabilities */}
      <section className="py-20 px-6 bg-slate-900/40">
        <div className="max-w-6xl mx-auto">
          <h2 className="text-3xl font-bold text-center text-white mb-4">Core Capabilities</h2>
          <p className="text-slate-400 text-center mb-12 max-w-2xl mx-auto">Six pillars of protection for the agentic AI stack.</p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {capabilities.map((c) => (
              <div key={c.title} className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-6 transition-all duration-300 hover:-translate-y-1 hover:border-emerald-500/30 hover:scale-[1.02]">
                <div className="w-12 h-12 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 mb-4">
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d={c.icon} />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">{c.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">{c.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Stats Bar */}
      <section className="py-10 border-y border-slate-800 bg-slate-950">
        <div className="max-w-6xl mx-auto px-6 grid grid-cols-2 md:grid-cols-5 gap-8">
          {stats.map((s) => (
            <div key={s.label} className="text-center">
              <div className="text-3xl font-bold text-emerald-400">
                {s.prefix || ''}<AnimatedCounter end={s.value} suffix={s.suffix} />
              </div>
              <div className="text-sm text-slate-400 mt-1">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Competitive Section */}
      <section className="py-20 px-6">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold text-center text-white mb-4">Why Not Existing Tools?</h2>
          <p className="text-slate-400 text-center mb-12">Traditional solutions were not built for the agentic AI era.</p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-slate-300 font-semibold">Feature</th>
                  {comparisonCols.map((c) => (
                    <th key={c} className="text-center py-3 px-3 text-slate-400 font-medium text-xs">{c}</th>
                  ))}
                  <th className="text-center py-3 px-3 text-emerald-400 font-semibold">DataShield</th>
                </tr>
              </thead>
              <tbody>
                {comparisonRows.map((r) => (
                  <tr key={r.feature} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                    <td className="py-3 px-4 text-slate-300">{r.feature}</td>
                    {comparisonCols.map((c) => (
                      <td key={c} className="text-center py-3 px-3">
                        <span className="text-red-400">&#10007;</span>
                      </td>
                    ))}
                    <td className="text-center py-3 px-3">
                      <span className="text-emerald-400">&#10003;</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Industries */}
      <section className="py-20 px-6 bg-slate-900/40">
        <div className="max-w-5xl mx-auto">
          <h2 className="text-3xl font-bold text-center text-white mb-12">Built for Regulated Industries</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-5">
            {industries.map((ind) => (
              <div key={ind.name} className="bg-slate-800/70 backdrop-blur-sm border border-slate-700 rounded-xl p-5 text-center transition-all duration-300 hover:-translate-y-1 hover:border-emerald-500/30 hover:scale-105">
                <div className="w-10 h-10 mx-auto rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 mb-3">
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" d={ind.icon} />
                  </svg>
                </div>
                <div className="text-sm font-semibold text-white">{ind.name}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-6 border-t border-slate-800">
        <div className="max-w-5xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="text-sm text-slate-500">DataShield AI v1.0 -- Built for the agentic era.</div>
          <div className="flex gap-6">
            <button onClick={() => navigate('/dashboard')} className="text-sm text-slate-400 hover:text-emerald-400 transition-colors">Dashboard</button>
            <button onClick={() => navigate('/scanner')} className="text-sm text-slate-400 hover:text-emerald-400 transition-colors">Scanner</button>
          </div>
        </div>
      </footer>
    </div>
  );
}
