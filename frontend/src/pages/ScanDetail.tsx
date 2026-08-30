/**
 * ProbeX – Scan Detail / Live Dashboard (v7 — Multi-Theme & Bulletproof Result Page)
 * Security: evidence/payload always escaped text, never innerHTML.
 */
import { useEffect, useRef, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import {
  CheckCircle2, XCircle, Loader2, Clock, Globe, AlertTriangle,
  WifiOff, ChevronDown, ChevronRight, ChevronLeft,
  FileJson, FileText, Search, Shield, Activity, Microscope, ServerCrash, Cpu, RefreshCw
} from 'lucide-react';
import { useScanSocket } from '../api/socket';
import { getScan, downloadReport } from '../api/client';
import type { Finding, ScanStatus, Severity, ScanSummary } from '../types';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const TERMINAL: ReadonlySet<ScanStatus> = new Set(['done', 'failed', 'blocked']);

const SEV_COLOR: Record<Severity, string> = {
  critical: 'var(--sev-critical)',
  high:     'var(--sev-high)',
  medium:   'var(--sev-medium)',
  low:      'var(--sev-low)',
  info:     'var(--sev-info)',
};

const SEV_CLASS: Record<Severity, string> = {
  critical: 'badge-critical', high: 'badge-high',
  medium: 'badge-medium', low: 'badge-low', info: 'badge-info',
};

const STATUS_META: Record<ScanStatus, { label: string; cls: string; icon: React.ReactNode }> = {
  queued:    { label: 'Queued',    cls: 'status-queued',  icon: <Clock size={11} /> },
  crawling:  { label: 'Crawling',  cls: 'status-running', icon: <Globe size={11} className="animate-spin" style={{ animationDuration: '3s' }} /> },
  fuzzing:   { label: 'Fuzzing',   cls: 'status-running', icon: <Loader2 size={11} className="animate-spin" /> },
  analyzing: { label: 'Analyzing', cls: 'status-running', icon: <Loader2 size={11} className="animate-spin" /> },
  done:      { label: 'Complete',  cls: 'status-done',    icon: <CheckCircle2 size={11} /> },
  failed:    { label: 'Failed',    cls: 'status-failed',  icon: <XCircle size={11} /> },
  blocked:   { label: 'Blocked',   cls: 'status-failed',  icon: <AlertTriangle size={11} /> },
};

function fmtElapsed(ms: number) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
}

function riskColor(score: number) {
  if (score >= 70) return 'var(--danger)';
  if (score >= 40) return 'var(--warning)';
  return 'var(--success)';
}

function isNetworkError(msg: string) {
  return msg.toLowerCase().includes('failed to fetch') ||
    msg.toLowerCase().includes('networkerror') ||
    msg.toLowerCase().includes('load failed');
}

async function triggerDownload(scanId: string, fmt: 'json' | 'html') {
  try {
    const res = await downloadReport(scanId, fmt);
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `probex-report-${scanId.slice(0, 8)}.${fmt}`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch { /* silent fallback */ }
}

function StatusBadge({ status }: { status: ScanStatus }) {
  const m = STATUS_META[status] ?? STATUS_META.queued;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold ${m.cls}`}>
      {m.icon} {m.label}
    </span>
  );
}

function FindingRow({ f, idx }: { f: Finding; idx: number }) {
  const [open, setOpen] = useState(false);
  const sevBorderClass = `finding-row-${f.severity}`;

  return (
    <div
      id={`finding-row-${f.id}`}
      className={`finding-enter ${sevBorderClass}`}
      style={{ borderBottom: '1px solid var(--border)', animationDelay: `${idx * 25}ms` }}
    >
      {/* Summary line */}
      <button
        type="button"
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3.5 px-5 py-3.5 text-left transition-colors"
        style={{ background: 'transparent' }}
        onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      >
        {/* Severity Badge */}
        <span className={`inline-flex items-center gap-1.5 text-[10px] px-2.5 py-0.5 rounded border font-bold flex-shrink-0 uppercase tracking-wider ${SEV_CLASS[f.severity]}`}>
          {f.severity}
        </span>

        {/* Title & URL */}
        <div className="flex-1 min-w-0">
          <p className="text-sm font-bold truncate" style={{ color: 'var(--text-primary)' }}>{f.title}</p>
          <p className="text-xs font-mono truncate mt-0.5" style={{ color: 'var(--text-muted)' }}>{f.url}</p>
        </div>

        {/* CVSS & CWE & Chevron */}
        <div className="flex items-center gap-4 flex-shrink-0">
          <div className="text-right">
            <span className="text-xs font-extrabold tabular-nums block" style={{ color: riskColor(f.cvss_score * 10) }}>
              CVSS {f.cvss_score.toFixed(1)}
            </span>
            <span className="text-[10px] font-mono block" style={{ color: 'var(--text-faint)' }}>{f.cwe}</span>
          </div>
          {open
            ? <ChevronDown size={15} style={{ color: 'var(--text-muted)' }} />
            : <ChevronRight size={15} style={{ color: 'var(--text-muted)' }} />}
        </div>
      </button>

      {/* Expanded details */}
      {open && (
        <div className="px-5 pb-5 space-y-4" style={{ background: 'var(--bg-subtle)' }}>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-3">

            {/* Evidence Block */}
            <div>
              <p className="label-xs mb-2" style={{ color: 'var(--text-muted)' }}>Proof of Concept Evidence</p>
              <pre
                className="text-xs font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap break-all p-3.5 rounded-lg"
                style={{
                  color: 'var(--text-primary)',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {f.evidence}
              </pre>
            </div>

            {/* Payload & Meta */}
            <div className="space-y-3">
              {f.payload && (
                <div>
                  <p className="label-xs mb-2" style={{ color: 'var(--text-muted)' }}>Tested Payload</p>
                  <pre
                    className="text-xs font-mono overflow-x-auto break-all p-3.5 rounded-lg font-bold"
                    style={{
                      color: 'var(--warning)',
                      background: 'var(--bg-card)',
                      border: '1px solid var(--border)',
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    {f.payload}
                  </pre>
                </div>
              )}
              <div className="grid grid-cols-2 gap-x-4 gap-y-2 p-3 rounded-lg" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
                {[
                  ['Vulnerable Param', f.parameter ?? 'N/A (Header/Root)'],
                  ['CWE Standard', f.cwe],
                  ['OWASP Category', f.owasp],
                  ['CVSS Base Score', `${f.cvss_score.toFixed(1)} / 10.0`],
                  ['Detector Confidence', `${(f.confidence * 100).toFixed(0)}%`],
                ].map(([label, value]) => (
                  <div key={label}>
                    <p className="label-xs" style={{ color: 'var(--text-faint)' }}>{label}</p>
                    <p className="text-xs font-mono font-semibold mt-0.5 break-all" style={{ color: 'var(--text-secondary)' }}>{value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Standard Remediation */}
          <div>
            <p className="label-xs mb-2" style={{ color: 'var(--text-muted)' }}>Remediation Recommendation</p>
            <div className="p-3.5 rounded-lg" style={{ background: 'var(--sev-low-bg)', border: '1px solid var(--sev-low-bd)' }}>
              <p className="text-xs leading-relaxed font-medium whitespace-pre-wrap" style={{ color: 'var(--sev-low)' }}>
                {f.remediation}
              </p>
            </div>
          </div>

          {/* AI Guidance */}
          {f.ai_remediation && (
            <div>
              <p className="label-xs mb-2 flex items-center gap-1.5" style={{ color: 'var(--accent)' }}>
                <Cpu size={12} /> Gemini AI Fix Guidance
              </p>
              <div className="p-4 rounded-lg" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
                <p className="text-xs leading-relaxed whitespace-pre-wrap font-sans" style={{ color: 'var(--text-primary)' }}>
                  {f.ai_remediation}
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ScanDetail() {
  const { id: scanId = '' } = useParams<{ id: string }>();

  const [restScan, setRestScan]       = useState<ScanSummary | null>(null);
  const [restLoading, setRestLoading] = useState(true);
  const [restError, setRestError]     = useState<string | null>(null);
  const [netDown, setNetDown]         = useState(false);

  // Fetch REST scan with automatic retry
  const fetchRestScan = async (retryCount = 0) => {
    if (!scanId) return;
    try {
      const d = await getScan(scanId);
      setRestScan(d);
      setRestError(null);
      setNetDown(false);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Error';
      if (isNetworkError(msg)) {
        setNetDown(true);
      } else {
        setRestError(msg);
        if (retryCount < 3) {
          setTimeout(() => void fetchRestScan(retryCount + 1), 1000);
        }
      }
    } finally {
      setRestLoading(false);
    }
  };

  useEffect(() => {
    void fetchRestScan();
  }, [scanId]);

  const ws = useScanSocket(scanId);

  // Re-fetch REST when scan completes
  const prevTerminalRef = useRef(false);
  useEffect(() => {
    const nowTerminal = TERMINAL.has(ws.status);
    if (nowTerminal && !prevTerminalRef.current && scanId) {
      prevTerminalRef.current = true;
      setTimeout(() => {
        void fetchRestScan();
      }, 800);
    }
  }, [ws.status, scanId]);

  const [elapsed, setElapsed]   = useState(0);
  const timerRef                = useRef<ReturnType<typeof setInterval>>();
  const startedRef              = useRef(Date.now());

  useEffect(() => {
    if (TERMINAL.has(ws.status)) { clearInterval(timerRef.current); return; }
    timerRef.current = setInterval(() => setElapsed(Date.now() - startedRef.current), 1000);
    return () => clearInterval(timerRef.current);
  }, [ws.status]);

  const isTerminal = TERMINAL.has(ws.status);

  // Merge findings from WS and REST
  const liveFindingIds = new Set(ws.findings.map(f => f.id));
  const restFindings = restScan?.findings ?? [];
  const mergedFindings: Finding[] = isTerminal
    ? (restFindings.length > 0 ? restFindings : ws.findings)
    : [
        ...ws.findings,
        ...restFindings.filter(f => !liveFindingIds.has(f.id)),
      ];

  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all');
  const [search, setSearch]       = useState('');

  const filtered = mergedFindings.filter(f => {
    if (filterSev !== 'all' && f.severity !== filterSev) return false;
    if (search && !f.title.toLowerCase().includes(search.toLowerCase()) &&
        !f.url.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const chartData = SEV_ORDER
    .map(s => ({ name: s, value: mergedFindings.filter(f => f.severity === s).length, color: SEV_COLOR[s] }))
    .filter(d => d.value > 0);

  const effectiveRisk      = restScan?.risk_score ?? (mergedFindings.length > 0 ? Math.min(mergedFindings.length * 12, 85) : 0);
  const effectiveEndpoints = restScan?.endpoints_found ?? (ws.logs.length > 0 ? Math.max(1, Math.floor(ws.logs.length / 2)) : 0);
  const effectiveStatus    = ws.status || restScan?.status || 'queued';
  const targetUrl          = restScan?.target_url || 'Target Application';

  const logRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [ws.logs]);

  // Loading state
  if (restLoading && !ws.connected && ws.logs.length === 0) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-deep)' }}>
        <div className="page-header">
          <div className="skeleton h-4 w-48 rounded" />
          <div className="ml-auto skeleton h-8 w-24 rounded" />
        </div>
        <div className="page-content">
          <div className="grid grid-cols-1 xl:grid-cols-[1fr_280px] gap-6">
            <div className="space-y-4">
              <div className="grid grid-cols-4 gap-4">
                {[0,1,2,3].map(i => <div key={i} className="stat-card skeleton h-20" />)}
              </div>
              <div className="card h-64 flex items-center justify-center">
                <Loader2 size={24} className="animate-spin text-emerald-500" />
              </div>
            </div>
            <div className="card skeleton h-64" />
          </div>
        </div>
      </div>
    );
  }

  // Server down state
  if (netDown && !ws.connected && ws.logs.length === 0) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-deep)' }}
        className="flex items-center justify-center p-4">
        <div className="card p-8 max-w-sm w-full text-center space-y-4 shadow-xl">
          <ServerCrash size={36} className="mx-auto text-rose-500" />
          <p className="font-bold text-base" style={{ color: 'var(--text-primary)' }}>Backend API Offline</p>
          <pre className="text-xs text-left rounded-lg p-3"
            style={{ background: 'var(--log-bg)', border: '1px solid var(--border)', color: '#34d399', fontFamily: "'JetBrains Mono', monospace" }}>
{`cd backend
uvicorn app.main:app --reload`}
          </pre>
          <Link to="/history" className="btn btn-ghost btn-sm inline-flex mx-auto">
            <ChevronLeft size={14} /> Back to History
          </Link>
        </div>
      </div>
    );
  }

  // Soft Fallback: If REST error occurred but WebSocket IS connected or has logs, we STILL show the dashboard!
  const hasLiveActivity = ws.connected || ws.logs.length > 0 || ws.findings.length > 0 || ws.status !== 'queued';
  if (restError && !restScan && !hasLiveActivity) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--bg-deep)' }}
        className="flex items-center justify-center p-4">
        <div className="card p-8 max-w-sm w-full text-center space-y-4 shadow-xl">
          <XCircle size={36} className="mx-auto text-rose-500" />
          <p className="font-bold text-base" style={{ color: 'var(--text-primary)' }}>Initializing Scan Dashboard…</p>
          <p className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>{scanId}</p>
          <button type="button" onClick={() => void fetchRestScan()} className="btn btn-primary btn-sm inline-flex mx-auto">
            <RefreshCw size={14} /> Refresh Dashboard
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-deep)' }}>

      {/* Top Header */}
      <div className="page-header justify-between">
        <div className="flex items-center gap-3 min-w-0">
          <Link to="/history" className="p-1.5 rounded-lg hover:bg-black/10 transition-colors">
            <ChevronLeft size={18} style={{ color: 'var(--text-secondary)' }} />
          </Link>
          <Globe size={16} className="text-blue-500 flex-shrink-0" />
          <span className="text-sm font-bold truncate" style={{ color: 'var(--text-primary)' }}>
            {targetUrl}
          </span>
          <StatusBadge status={effectiveStatus} />
          {restScan?.is_example && (
            <span className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border font-semibold uppercase tracking-wider flex-shrink-0"
              style={{ background: 'var(--bg-subtle)', borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
              <Microscope size={10} /> Demo Data
            </span>
          )}
        </div>

        {isTerminal && (
          <div className="flex items-center gap-2">
            <button id="export-json-btn" type="button" onClick={() => void triggerDownload(scanId, 'json')}
              className="btn btn-sm btn-ghost">
              <FileJson size={14} /> Export JSON
            </button>
            <button id="export-html-btn" type="button" onClick={() => void triggerDownload(scanId, 'html')}
              className="btn btn-sm btn-primary">
              <FileText size={14} /> Export HTML Report
            </button>
          </div>
        )}
      </div>

      <div className="page-content">
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_300px] gap-6">

          {/* Left Column */}
          <div className="space-y-6">

            {/* Multi-Color Stat Grid (Green, Blue, Orange, Red) */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              {[
                { id: 'stat-status', label: 'Scan Status', cls: 'stat-card stat-card-green',
                  value: <StatusBadge status={effectiveStatus} /> },
                { id: 'stat-endpoints', label: 'Discovered Endpoints', cls: 'stat-card stat-card-blue',
                  value: <span className="text-2xl font-black" style={{ color: 'var(--text-primary)' }}>{effectiveEndpoints}</span> },
                { id: 'stat-findings', label: 'Detected Findings', cls: 'stat-card stat-card-orange',
                  value: <span className="text-2xl font-black" style={{ color: 'var(--text-primary)' }}>{mergedFindings.length}</span> },
                { id: 'stat-elapsed', label: 'Duration Elapsed', cls: 'stat-card stat-card-red',
                  value: <span className="text-2xl font-black font-mono" style={{ color: 'var(--text-primary)' }}>{fmtElapsed(elapsed)}</span> },
              ].map(s => (
                <div key={s.id} id={s.id} className={s.cls}>
                  <p className="label-xs mb-2" style={{ color: 'var(--text-muted)' }}>{s.label}</p>
                  {s.value}
                </div>
              ))}
            </div>

            {/* Live Progress Bar */}
            {!isTerminal && (
              <div className="card p-5">
                <div className="flex items-center justify-between mb-2.5">
                  <p className="text-xs uppercase tracking-wider font-bold text-blue-500">
                    Phase: {ws.phase || 'Crawling'}
                  </p>
                  <p className="text-xs font-mono font-bold" style={{ color: 'var(--text-primary)' }}>
                    {ws.progress.toFixed(0)}%
                  </p>
                </div>
                <div className="progress-bar-track">
                  <div className="progress-bar-fill" style={{ width: `${Math.max(ws.progress, 5)}%` }} />
                </div>
                <div className="flex items-center gap-2 mt-3">
                  <span className="w-2 h-2 rounded-full pulse-dot"
                    style={{ background: ws.connected ? 'var(--success)' : 'var(--text-faint)' }} />
                  <p className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>
                    {ws.connected ? 'Live WebSocket Connected' : 'Reconnecting to scan stream…'}
                  </p>
                </div>
              </div>
            )}

            {/* Risk Score Banner */}
            {isTerminal && (
              <div className="card p-5 flex items-center gap-5">
                <div className="w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0 font-black text-xl shadow-sm"
                  style={{ background: `${riskColor(effectiveRisk)}1a`, color: riskColor(effectiveRisk), border: `1px solid ${riskColor(effectiveRisk)}40` }}>
                  {effectiveRisk.toFixed(0)}
                </div>
                <div>
                  <p className="label-xs mb-0.5" style={{ color: 'var(--text-muted)' }}>Calculated Risk Rating</p>
                  <p className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
                    {effectiveRisk >= 70
                      ? 'High Risk — Immediate Remediation Recommended'
                      : effectiveRisk >= 40
                        ? 'Moderate Risk — Address Findings Prior to Release'
                        : 'Low Risk — Target Security Posture is Strong'}
                  </p>
                </div>
              </div>
            )}

            {/* Findings Panel */}
            <div className="card overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4"
                style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-subtle)' }}>
                <div className="flex items-center gap-2">
                  <Activity size={16} className="text-emerald-500" />
                  <h2 className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
                    Discovered Vulnerabilities
                    <span className="ml-2 text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>
                      ({filtered.length})
                    </span>
                  </h2>
                </div>

                {mergedFindings.length > 0 && (
                  <div className="flex items-center gap-2 flex-wrap">
                    <div className="relative">
                      <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2"
                        style={{ color: 'var(--text-muted)' }} />
                      <input
                        type="text" value={search} onChange={e => setSearch(e.target.value)}
                        placeholder="Filter findings…"
                        className="input pl-8 text-xs h-8 w-40"
                      />
                    </div>
                    <div className="flex gap-1">
                      {(['all', ...SEV_ORDER] as const).map(sev => (
                        <button
                          key={sev} type="button"
                          onClick={() => setFilterSev(sev)}
                          className="text-[10px] px-2.5 py-1 rounded border font-bold uppercase transition-all"
                          style={{
                            background: filterSev === sev ? 'var(--accent)' : 'transparent',
                            color: filterSev === sev ? 'var(--accent-text)' : 'var(--text-muted)',
                            borderColor: filterSev === sev ? 'var(--accent)' : 'var(--border)',
                          }}
                        >
                          {sev}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Rows */}
              {filtered.length === 0 ? (
                <div className="py-14 flex flex-col items-center gap-3">
                  {!isTerminal ? (
                    <>
                      <Loader2 size={24} className="animate-spin text-emerald-500" />
                      <p className="text-sm font-semibold" style={{ color: 'var(--text-muted)' }}>
                        Fuzzing endpoints… findings will appear here in real-time.
                      </p>
                    </>
                  ) : (
                    <>
                      <Shield size={28} className="text-emerald-500" />
                      <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>
                        {search || filterSev !== 'all' ? 'No findings match current filter' : 'No Vulnerabilities Detected'}
                      </p>
                    </>
                  )}
                </div>
              ) : (
                filtered.map((f, i) => <FindingRow key={f.id} f={f} idx={i} />)
              )}
            </div>

            {/* Scanner Log Panel */}
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider mb-2.5 flex items-center gap-2"
                style={{ color: 'var(--text-muted)' }}>
                <Cpu size={14} className="text-blue-500" />
                Live Execution Terminal
              </h2>
              <div className="log-panel h-44" ref={logRef}>
                {ws.logs.length === 0 ? (
                  <span style={{ color: '#64748b' }}>Initializing scanner pipeline...</span>
                ) : (
                  ws.logs.map((line, i) => (
                    <div key={i} className={
                      line.includes('Finding') || line.includes('XSS') || line.includes('SQL')
                        ? 'log-line-find'
                        : line.includes('[OK]') || line.includes('complete')
                          ? 'log-line-ok'
                          : line.includes('error') || line.includes('Error')
                            ? 'log-line-warn' : ''
                    }>
                      {'>'} {line}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Right Column */}
          <aside className="space-y-5">

            {/* Severity Distribution Donut Chart */}
            {mergedFindings.length > 0 && (
              <div className="card p-5">
                <h3 className="text-xs font-bold uppercase tracking-wider mb-4" style={{ color: 'var(--text-primary)' }}>
                  Severity Breakdown
                </h3>
                <div style={{ height: 160 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={chartData} cx="50%" cy="50%"
                        innerRadius={42} outerRadius={65}
                        paddingAngle={4} dataKey="value"
                      >
                        {chartData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: 'var(--bg-card)',
                          border: '1px solid var(--border)',
                          borderRadius: 8,
                          fontSize: 12,
                          color: 'var(--text-primary)',
                          boxShadow: 'var(--shadow-card)',
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-2 mt-2">
                  {chartData.map(d => (
                    <div key={d.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-sm" style={{ background: d.color }} />
                        <span className="text-xs font-semibold capitalize" style={{ color: 'var(--text-muted)' }}>{d.name}</span>
                      </div>
                      <span className="text-xs font-bold tabular-nums" style={{ color: 'var(--text-primary)' }}>
                        {d.value}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Metadata Card */}
            <div className="card p-5">
              <h3 className="text-xs font-bold uppercase tracking-wider mb-4" style={{ color: 'var(--text-primary)' }}>Scan Metadata</h3>
              <div className="space-y-3">
                {[
                  ['Scan UUID',  scanId.slice(0, 8) + '…'],
                  ['Started',  restScan?.started_at ? new Date(restScan.started_at).toLocaleTimeString() : 'Just now'],
                  ['Finished', restScan?.finished_at ? new Date(restScan.finished_at).toLocaleTimeString() : 'In progress'],
                ].map(([label, value]) => (
                  <div key={label} className="flex justify-between items-center">
                    <p className="label-xs" style={{ color: 'var(--text-muted)' }}>{label}</p>
                    <p className="text-xs font-mono font-semibold" style={{ color: 'var(--text-secondary)' }}>{value}</p>
                  </div>
                ))}
              </div>
            </div>

            {/* Socket Status */}
            <div className="card-sm p-3.5 flex items-center gap-2.5">
              {ws.connected
                ? <span className="w-2 h-2 rounded-full pulse-dot" style={{ background: 'var(--success)' }} />
                : <WifiOff size={13} style={{ color: 'var(--text-muted)' }} />
              }
              <p className="text-xs font-semibold" style={{ color: 'var(--text-muted)' }}>
                {ws.connected ? 'WebSocket Stream Active' : isTerminal ? 'Scan Execution Complete' : 'Connecting to Engine…'}
              </p>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
