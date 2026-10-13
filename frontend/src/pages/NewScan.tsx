import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Globe, Zap, Target, AlertTriangle, ChevronRight,
  Shield, Check, Cpu, Lock, Terminal, ShieldAlert, FileCode, Layers, RefreshCw
} from 'lucide-react';
import { createScan } from '../api/client';

type Profile = 'quick' | 'standard';

const PROFILES: {
  id: Profile;
  label: string;
  icon: typeof Zap;
  time: string;
  depth: string;
  desc: string;
  badgeColor: string;
  borderColor: string;
}[] = [
  {
    id: 'quick',
    label: 'Quick Scan',
    icon: Zap,
    time: '~1–2 min',
    depth: 'Depth 1 · 50 endpoints',
    desc: 'Single-depth crawl with core detectors. Ideal for rapid feedback during development.',
    badgeColor: 'var(--sev-info)',
    borderColor: 'var(--sev-info-bd)',
  },
  {
    id: 'standard',
    label: 'Standard Scan',
    icon: Target,
    time: '~5–10 min',
    depth: 'Depth 2 · 200 endpoints',
    desc: 'Deep crawl with full payload library. Comprehensive security verification before deployment.',
    badgeColor: 'var(--accent)',
    borderColor: 'var(--accent-dim)',
  },
];

const DETECTORS = [
  { label: 'Reflected Cross-Site Scripting (XSS)', icon: Zap, color: 'text-amber-500', tag: 'High' },
  { label: 'SQL Injection (Error-based)', icon: ShieldAlert, color: 'text-rose-500', tag: 'High' },
  { label: 'Security Headers Audit (CSP, HSTS)', icon: Shield, color: 'text-emerald-500', tag: 'Low' },
  { label: 'Open Redirect & URL Parameter Fuzzing', icon: RefreshCw, color: 'text-cyan-500', tag: 'Medium' },
  { label: 'Path Traversal & File Inclusion', icon: FileCode, color: 'text-indigo-500', tag: 'High' },
  { label: 'Server-Side Template Injection (SSTI)', icon: Cpu, color: 'text-purple-500', tag: 'Critical' },
  { label: 'Sensitive Data Exposure (Passive)', icon: Layers, color: 'text-blue-500', tag: 'High' },
  { label: 'Cookie Security Flags', icon: Lock, color: 'text-orange-500', tag: 'Medium' },
  { label: 'Credentialed CORS Reflection', icon: Globe, color: 'text-cyan-500', tag: 'High' },
  { label: 'Debug / Directory Disclosure', icon: Terminal, color: 'text-rose-500', tag: 'Medium' },
];

export default function NewScan() {
  const navigate = useNavigate();
  const [url, setUrl]         = useState('');
  const [profile, setProfile] = useState<Profile>('quick');
  const [consent, setConsent] = useState(false);
  const [busy, setBusy]       = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [urlErr, setUrlErr]   = useState<string | null>(null);

  function validateUrl(v: string) {
    if (!v.trim()) return 'Target URL is required.';
    try {
      const u = new URL(v);
      if (!['http:', 'https:'].includes(u.protocol)) return 'Target URL must start with http:// or https://';
    } catch { return 'Please enter a valid URL (e.g. http://localhost:5500)'; }
    return null;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const ve = validateUrl(url);
    if (ve) { setUrlErr(ve); return; }
    if (!consent) { setError('You must confirm written authorization to scan this target.'); return; }
    setBusy(true); setError(null);
    try {
      const r = await createScan({ target_url: url, profile, consent_confirmed: true });
      navigate(`/scans/${r.scan_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to start security scan');
      setBusy(false);
    }
  }

  const QUICK_URLS = ['https://demo.owasp-juice.shop', 'http://localhost:5500', 'http://localhost:3000'];

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-deep)' }}>

      {/* Compact Header Bar */}
      <div className="page-header justify-between">
        <div className="flex items-center gap-2.5">
          <Shield size={16} className="text-emerald-500" />
          <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>New Security Scan</p>
          <span className="text-[11px] font-bold px-2 py-0.5 rounded-full"
            style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>
            DAST Engine
          </span>
        </div>
      </div>

      <div className="page-content py-6">
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-6 max-w-6xl">

          {/* ── Left Column: Form Controls ─────────────────────── */}
          <div className="space-y-6">

            <form onSubmit={handleSubmit} noValidate className="space-y-6">

              {/* Target URL Card */}
              <div className="card p-5">
                <div className="flex items-center justify-between mb-2">
                  <label htmlFor="target-url-input" className="heading-sm block"
                    style={{ color: 'var(--text-primary)' }}>
                    Target Web Application URL
                  </label>
                  <span className="text-[11px] font-medium" style={{ color: 'var(--text-muted)' }}>
                    HTTP / HTTPS Target
                  </span>
                </div>

                <div className="relative mt-2">
                  <Globe size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2"
                    style={{ color: 'var(--text-muted)' }} />
                  <input
                    id="target-url-input"
                    type="url"
                    value={url}
                    onChange={e => { setUrl(e.target.value); setUrlErr(null); }}
                    onBlur={() => { if (url) setUrlErr(validateUrl(url)); }}
                    placeholder="http://localhost:5500"
                    autoComplete="off"
                    spellCheck={false}
                    className="input pl-10 text-sm"
                    style={{ fontFamily: "'JetBrains Mono', monospace" }}
                  />
                </div>

                {urlErr && (
                  <p className="mt-2 text-xs flex items-center gap-1.5 font-medium" style={{ color: 'var(--danger)' }}>
                    <AlertTriangle size={13} /> {urlErr}
                  </p>
                )}

                <p className="mt-2 text-[11px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                  Public HTTPS practice target: OWASP Juice Shop. Local/private targets require an explicit backend lab setting and are blocked by default.
                </p>

                {/* Quick-fill pills */}
                <div className="flex items-center gap-2 mt-3 flex-wrap">
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>Presets:</span>
                  {QUICK_URLS.map(u => (
                    <button
                      key={u} type="button"
                      onClick={() => { setUrl(u); setUrlErr(null); }}
                      className="text-xs px-2.5 py-0.5 rounded-md border font-mono transition-all"
                      style={{
                        background: url === u ? 'var(--accent-dim)' : 'var(--bg-subtle)',
                        borderColor: url === u ? 'var(--accent)' : 'var(--border)',
                        color: url === u ? 'var(--accent)' : 'var(--text-secondary)',
                      }}
                    >
                      {u}
                    </button>
                  ))}
                </div>
              </div>

              {/* Profile Selection Card */}
              <div className="card p-5">
                <p className="heading-sm mb-1" style={{ color: 'var(--text-primary)' }}>Scan Profile & Depth</p>
                <p className="text-xs mb-3.5" style={{ color: 'var(--text-muted)' }}>
                  Configure crawler breadth and attack vector depth.
                </p>

                <div className="grid sm:grid-cols-2 gap-3.5">
                  {PROFILES.map(p => {
                    const Icon = p.icon;
                    const sel = profile === p.id;
                    return (
                      <button
                        key={p.id} type="button" id={`profile-${p.id}`}
                        onClick={() => setProfile(p.id)}
                        className="text-left p-4 rounded-xl border transition-all relative overflow-hidden"
                        style={{
                          background: sel ? 'var(--accent-dim)' : 'var(--bg-card-alt)',
                          borderColor: sel ? 'var(--accent)' : 'var(--border)',
                          boxShadow: sel ? 'var(--shadow-card)' : 'none',
                        }}
                      >
                        {sel && (
                          <div className="absolute top-3 right-3 w-2.5 h-2.5 rounded-full pulse-dot"
                            style={{ background: 'var(--accent)' }} />
                        )}

                        <div className="w-8 h-8 rounded-lg flex items-center justify-center mb-2.5"
                          style={{
                            background: sel ? 'var(--accent)' : 'var(--bg-subtle)',
                            color: sel ? 'var(--accent-text)' : 'var(--text-muted)',
                            border: '1px solid var(--border)',
                          }}>
                          <Icon size={16} />
                        </div>

                        <p className="text-sm font-bold mb-1" style={{ color: 'var(--text-primary)' }}>
                          {p.label}
                        </p>
                        <p className="text-xs leading-relaxed mb-3" style={{ color: 'var(--text-muted)' }}>
                          {p.desc}
                        </p>
                        <div className="flex gap-2">
                          <span className="text-[11px] font-semibold px-2 py-0.5 rounded-md"
                            style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                            {p.time}
                          </span>
                          <span className="text-[11px] font-semibold px-2 py-0.5 rounded-md"
                            style={{ background: 'var(--bg-subtle)', color: 'var(--text-secondary)', border: '1px solid var(--border)' }}>
                            {p.depth}
                          </span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Consent Card */}
              <div className="card p-4">
                <label
                  className="flex items-start gap-3 cursor-pointer p-3 rounded-lg border transition-all"
                  style={{
                    background: consent ? 'var(--accent-dim)' : 'var(--bg-card-alt)',
                    borderColor: consent ? 'var(--accent)' : 'var(--border)',
                  }}
                >
                  <button
                    type="button" role="checkbox" id="consent-checkbox" aria-checked={consent}
                    onClick={() => setConsent(v => !v)}
                    className="w-4 h-4 rounded flex-shrink-0 mt-0.5 flex items-center justify-center transition-all"
                    style={{
                      background: consent ? 'var(--accent)' : 'transparent',
                      border: `2px solid ${consent ? 'var(--accent)' : 'var(--border-light)'}`,
                    }}
                  >
                    {consent && <Check size={11} strokeWidth={3} style={{ color: 'var(--accent-text)' }} />}
                  </button>
                  <div>
                    <p className="text-xs font-bold" style={{ color: 'var(--text-primary)' }}>
                      Authorization Confirmation
                    </p>
                    <p className="text-[11px] mt-0.5 leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                      I possess written authorization to perform security testing against this target URL.
                    </p>
                  </div>
                </label>
              </div>

              {/* Error Message */}
              {error && (
                <div className="p-3.5 rounded-xl flex items-center gap-3 text-sm font-medium"
                  style={{ background: 'var(--sev-critical-bg)', border: '1px solid var(--sev-critical-bd)', color: 'var(--sev-critical)' }}>
                  <AlertTriangle size={15} className="flex-shrink-0" /> {error}
                </div>
              )}

              {/* Submit Button */}
              <div className="flex items-center gap-4">
                <button
                  id="launch-scan-btn" type="submit"
                  disabled={busy || !url || !consent}
                  className="btn btn-primary btn-lg"
                >
                  {busy ? (
                    <>
                      <RefreshCw size={16} className="animate-spin" />
                      Initializing DAST Scan…
                    </>
                  ) : (
                    <>
                      <Zap size={16} />
                      Launch DAST Security Scan
                      <ChevronRight size={16} />
                    </>
                  )}
                </button>
                <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                  Live WebSocket Stream
                </p>
              </div>
            </form>
          </div>

          {/* ── Right Column: Active Detectors & Info ───────────────── */}
          <aside className="space-y-5">

            {/* Detector Coverage Card */}
            <div className="card p-4">
              <div className="flex items-center justify-between mb-3">
                <p className="heading-sm flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                  <Shield size={15} className="text-emerald-500" />
                  Active Detectors
                </p>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded"
                  style={{ background: 'var(--bg-subtle)', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                  10 Enabled
                </span>
              </div>
              <div className="space-y-2">
                {DETECTORS.map(d => {
                  const Icon = d.icon;
                  return (
                    <div key={d.label} className="flex items-center gap-2.5 p-2 rounded-lg" style={{ background: 'var(--bg-card-alt)' }}>
                      <Icon size={14} className={d.color} />
                      <span className="text-xs font-semibold flex-1 truncate" style={{ color: 'var(--text-primary)' }}>
                        {d.label}
                      </span>
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                        style={{
                          background: d.tag === 'Critical' ? 'var(--sev-critical-bg)' : d.tag === 'High' ? 'var(--sev-high-bg)' : 'var(--sev-low-bg)',
                          color: d.tag === 'Critical' ? 'var(--sev-critical)' : d.tag === 'High' ? 'var(--sev-high)' : 'var(--sev-low)',
                        }}>
                        {d.tag}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Pipeline Stage Card */}
            <div className="card p-4">
              <p className="heading-sm mb-3 flex items-center gap-2" style={{ color: 'var(--text-primary)' }}>
                <Terminal size={15} className="text-blue-500" />
                Pipeline Execution
              </p>
              <ol className="space-y-2.5">
                {[
                  { num: '01', label: 'BFS Crawler', desc: 'Discovers endpoints, forms, and inputs' },
                  { num: '02', label: 'Payload Injection', desc: 'Fuzzes parameters with specialized vectors' },
                  { num: '03', label: 'Baseline Diff', desc: 'Filters out false positives against baseline' },
                  { num: '04', label: 'AI Remediation', desc: 'Generates context-aware fix guidance' },
                ].map(s => (
                  <li key={s.label} className="flex gap-2.5 items-start">
                    <span className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded"
                      style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>
                      {s.num}
                    </span>
                    <div>
                      <p className="text-xs font-bold" style={{ color: 'var(--text-primary)' }}>{s.label}</p>
                      <p className="text-[11px]" style={{ color: 'var(--text-muted)' }}>{s.desc}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>

            {/* Security Notice */}
            <div className="card-sm p-3 flex items-start gap-2.5">
              <Lock size={14} className="text-amber-500 flex-shrink-0 mt-0.5" />
              <p className="text-[11px] leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                Always perform vulnerability testing within isolated environments or on target systems where explicit consent is granted.
              </p>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
