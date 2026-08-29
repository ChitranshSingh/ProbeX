/**
 * ProbeX – Live scan dashboard (ScanDetail).
 *
 * Rendered at /scans/:id.
 *
 * Phases
 * ------
 * 1. While scan is running: WebSocket live feed — status badge, progress bar,
 *    elapsed timer, live findings list, log panel.
 * 2. Once status === 'done' / 'failed' / 'blocked': findings explorer with
 *    severity filter, expandable detail rows, Recharts donut chart,
 *    and JSON / HTML report export buttons.
 *
 * Security note
 * -------------
 * Evidence and payload text are ALWAYS rendered as escaped text via React's
 * default text rendering — never via dangerouslySetInnerHTML. A finding's
 * evidence can contain live XSS payloads and must never execute inside this
 * dashboard.
 */

import { useEffect, useRef, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import {
  Shield, History, Wifi, WifiOff,
  ChevronDown, ChevronUp, AlertTriangle, CheckCircle2,
  XCircle, Loader2, Clock, Globe, Search, FileJson, FileText,
  TriangleAlert,
} from 'lucide-react';

import { useScanSocket } from '../api/socket';
import { getScan, downloadReport } from '../api/client';
import type { Finding, ScanStatus, Severity, ScanSummary } from '../types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const TERMINAL: ReadonlySet<ScanStatus> = new Set(['done', 'failed', 'blocked']);

const SEV_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#4ade80',
  info:     '#60a5fa',
};

const SEV_LABEL_CLASS: Record<Severity, string> = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  info:     'badge-info',
};

const STATUS_META: Record<ScanStatus, { label: string; color: string; icon: React.ReactNode }> = {
  queued:    { label: 'Queued',    color: 'text-[#94a3b8]',  icon: <Clock size={14} /> },
  crawling:  { label: 'Crawling',  color: 'text-[#60a5fa]',  icon: <Globe size={14} className="animate-spin" style={{ animationDuration: '2s' }} /> },
  fuzzing:   { label: 'Fuzzing',   color: 'text-[#f59e0b]',  icon: <Loader2 size={14} className="animate-spin" /> },
  analyzing: { label: 'Analyzing', color: 'text-[#a78bfa]',  icon: <Loader2 size={14} className="animate-spin" /> },
  done:      { label: 'Done',      color: 'text-[#10b981]',  icon: <CheckCircle2 size={14} /> },
  failed:    { label: 'Failed',    color: 'text-[#ef4444]',  icon: <XCircle size={14} /> },
  blocked:   { label: 'Blocked',   color: 'text-[#f59e0b]',  icon: <AlertTriangle size={14} /> },
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function formatElapsed(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m ${s % 60}s`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function truncate(s: string, n: number) {
  return s.length <= n ? s : s.slice(0, n) + '…';
}

async function triggerDownload(id: string, format: 'json' | 'html') {
  try {
    const res = await downloadReport(id, format);
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `probex-${id.slice(0, 8)}.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    console.error('Download failed', e);
  }
}

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------

function SeverityBadge({ sev }: { sev: Severity }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-md border text-[11px] font-semibold uppercase tracking-wide ${SEV_LABEL_CLASS[sev]}`}>
      {sev}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Status badge
// ---------------------------------------------------------------------------

function StatusBadge({ status }: { status: ScanStatus }) {
  const meta = STATUS_META[status];
  return (
    <span className={`inline-flex items-center gap-1.5 font-semibold text-sm ${meta.color}`}>
      {meta.icon}
      {meta.label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Expandable finding row
// ---------------------------------------------------------------------------

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="border border-[var(--border)] rounded-xl overflow-hidden transition-all duration-200 hover:border-[rgba(0,212,255,0.25)]">
      {/* Summary row — always visible */}
      <button
        type="button"
        id={`finding-row-${finding.id}`}
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left bg-[var(--bg-card)] hover:bg-[var(--bg-hover)] transition-colors duration-150 cursor-pointer"
        aria-expanded={open}
      >
        <SeverityBadge sev={finding.severity} />

        <span className="flex-1 text-sm text-[var(--text-primary)] font-medium leading-snug">
          {finding.title}
        </span>

        <div className="hidden sm:flex items-center gap-4 text-xs text-[var(--text-muted)] flex-shrink-0">
          <span className="font-mono">{finding.cwe}</span>
          <span className="font-semibold tabular-nums">
            CVSS&nbsp;{finding.cvss_score.toFixed(1)}
          </span>
        </div>

        <span className="text-[var(--text-muted)] flex-shrink-0">
          {open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </span>
      </button>

      {/* Detail panel — only when open */}
      {open && (
        <div className="border-t border-[var(--border)] bg-[var(--bg-deep)] px-4 py-5 space-y-5 text-sm">

          {/* Metadata row */}
          <div className="flex flex-wrap gap-4">
            {[
              { label: 'CWE',      value: finding.cwe },
              { label: 'OWASP',    value: finding.owasp },
              { label: 'CVSS',     value: finding.cvss_score.toFixed(1) },
              { label: 'Confidence', value: `${Math.round(finding.confidence * 100)}%` },
              ...(finding.parameter ? [{ label: 'Parameter', value: finding.parameter }] : []),
            ].map(({ label, value }) => (
              <div key={label} className="flex flex-col gap-0.5">
                <span className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] font-semibold">{label}</span>
                <span className="text-xs font-mono text-[var(--text-primary)]">{value}</span>
              </div>
            ))}
          </div>

          {/* URL */}
          <div>
            <p className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] font-semibold mb-1">URL</p>
            <p className="font-mono text-xs text-[var(--accent)] break-all">{finding.url}</p>
          </div>

          {/* Payload — escaped text */}
          {finding.payload && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] font-semibold mb-1">Payload</p>
              <pre className="font-mono text-xs bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-[var(--warning)] overflow-x-auto whitespace-pre-wrap break-all">
                {/* NOTE: React renders text nodes escaped — this NEVER executes as HTML */}
                {finding.payload}
              </pre>
            </div>
          )}

          {/* Evidence — escaped text */}
          <div>
            <p className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] font-semibold mb-1">Evidence</p>
            <pre className="font-mono text-xs bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-[var(--text-primary)] overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
              {/* NOTE: React renders text nodes escaped — this NEVER executes as HTML.
                   A finding's evidence can contain live XSS payloads such as
                   <script>alert(1)</script> and they are displayed as literal text. */}
              {finding.evidence}
            </pre>
          </div>

          {/* Remediation */}
          <div className="rounded-xl border border-[rgba(16,185,129,0.3)] bg-[rgba(16,185,129,0.05)] p-4">
            <p className="text-[10px] uppercase tracking-widest text-[var(--success)] font-semibold mb-2">
              Remediation
            </p>
            <p className="text-xs text-[var(--text-primary)] leading-relaxed">
              {finding.remediation}
            </p>
          </div>

          {/* AI remediation (if present) */}
          {finding.ai_remediation && (
            <div className="rounded-xl border border-[rgba(167,139,250,0.3)] bg-[rgba(167,139,250,0.05)] p-4">
              <p className="text-[10px] uppercase tracking-widest text-[#a78bfa] font-semibold mb-2">
                AI-Generated Context (Gemini)
              </p>
              <p className="text-xs text-[var(--text-primary)] leading-relaxed">
                {finding.ai_remediation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Severity donut chart
// ---------------------------------------------------------------------------

function SeverityDonut({ findings }: { findings: Finding[] }) {
  const counts = SEVERITY_ORDER.reduce<Record<string, number>>((acc, sev) => {
    const n = findings.filter(f => f.severity === sev).length;
    if (n > 0) acc[sev] = n;
    return acc;
  }, {});

  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-40 text-[var(--text-muted)] text-sm">
        No findings yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={55}
          outerRadius={80}
          paddingAngle={3}
          dataKey="value"
        >
          {data.map(entry => (
            <Cell
              key={entry.name}
              fill={SEV_COLORS[entry.name as Severity]}
              stroke="transparent"
            />
          ))}
        </Pie>
        <Tooltip
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null;
            const { name, value } = payload[0];
            const label = String(name);
            return (
              <div style={{ background: '#111827', border: '1px solid #1e3a5f', borderRadius: 8, padding: '6px 10px', fontSize: 12, color: '#f1f5f9' }}>
                <span style={{ marginRight: 6 }}>{label.charAt(0).toUpperCase() + label.slice(1)}:</span>
                <strong>{String(value)}</strong>
              </div>
            );
          }}
        />
        <Legend
          formatter={(value: string) => (
            <span style={{ color: '#94a3b8', fontSize: 12 }}>
              {value.charAt(0).toUpperCase() + value.slice(1)}
            </span>
          )}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const scanId = id ?? '';

  // Initial REST load — ensures the page works on hard-reload when
  // the WS buffer may not have replayed yet.
  const [restScan, setRestScan] = useState<ScanSummary | null>(null);
  const [restLoading, setRestLoading] = useState(true);
  const [restError, setRestError] = useState<string | null>(null);
  const [networkDown, setNetworkDown] = useState(false);

  useEffect(() => {
    setRestLoading(true);
    getScan(scanId)
      .then(data => { setRestScan(data); setRestLoading(false); })
      .catch(e => {
        const msg = e instanceof Error ? e.message : 'Error';
        const isNet = msg.toLowerCase().includes('failed to fetch') ||
                      msg.toLowerCase().includes('networkerror') ||
                      msg.toLowerCase().includes('load failed');
        setNetworkDown(isNet);
        setRestError(msg);
        setRestLoading(false);
      });
  }, [scanId]);

  // WebSocket state
  const socket = useScanSocket(scanId);

  // Elapsed timer
  const [elapsed, setElapsed] = useState(0);
  const startRef = useRef(Date.now());

  useEffect(() => {
    if (TERMINAL.has(socket.status)) return;
    const t = setInterval(() => setElapsed(Date.now() - startRef.current), 1000);
    return () => clearInterval(t);
  }, [socket.status]);

  // On terminal status, re-fetch REST to pick up AI remediation written after scan end.
  useEffect(() => {
    if (!TERMINAL.has(socket.status)) return;
    getScan(scanId).then(setRestScan).catch(() => null);
  }, [socket.status, scanId]);

  // Merge WS findings + REST findings, deduplicated
  const allFindings: Finding[] = (() => {
    const base = restScan?.findings ?? socket.findings;
    const wsIds = new Set(socket.findings.map(f => f.id));
    const restExtra = (restScan?.findings ?? []).filter(f => !wsIds.has(f.id));
    return socket.findings.length > 0
      ? [...socket.findings, ...restExtra]
      : base;
  })();

  // Severity filter (explorer mode)
  const [filterSev, setFilterSev] = useState<Severity | 'all'>('all');
  const [search, setSearch] = useState('');

  const filteredFindings = allFindings.filter(f => {
    const sevMatch = filterSev === 'all' || f.severity === filterSev;
    const q = search.toLowerCase();
    const textMatch = !q
      || f.title.toLowerCase().includes(q)
      || f.url.toLowerCase().includes(q)
      || f.cwe.toLowerCase().includes(q)
      || f.owasp.toLowerCase().includes(q);
    return sevMatch && textMatch;
  });

  // Scroll log panel to bottom on new entries
  const logRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (logRef.current)
      logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [socket.logs.length]);

  const isTerminal = TERMINAL.has(socket.status);
  const isDone = socket.status === 'done';
  const effectiveStatus = restScan?.status ?? socket.status;

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-[var(--bg-deep)] flex flex-col">

      {/* Ambient glow */}
      <div aria-hidden="true" className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-64 -left-64 w-[600px] h-[600px] rounded-full bg-[var(--accent)] opacity-[0.03] blur-[120px]" />
      </div>

      {/* ── Header ── */}
      <header className="relative z-10 border-b border-[var(--border)] bg-[rgba(10,14,26,0.85)] backdrop-blur-md sticky top-0">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 h-14 flex items-center gap-4">
          <Shield size={20} className="text-[var(--accent)]" />
          <span className="font-bold tracking-tight text-gradient">ProbeX</span>

          <span className="text-[var(--border)] select-none">|</span>

          <Link to="/" id="header-new-scan" className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
            New Scan
          </Link>
          <Link to="/history" id="header-history" className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors flex items-center gap-1">
            <History size={12} />
            History
          </Link>

          <div className="ml-auto flex items-center gap-2 text-xs">
            {socket.connected
              ? <span className="flex items-center gap-1 text-[var(--success)]"><Wifi size={12}/> Live</span>
              : <span className="flex items-center gap-1 text-[var(--text-muted)]"><WifiOff size={12}/> Offline</span>
            }
            {socket.reconnectAttempt > 0 && !socket.connected && (
              <span className="text-[var(--warning)]">retry #{socket.reconnectAttempt}</span>
            )}
          </div>
        </div>
      </header>

      <main className="relative z-10 flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 space-y-6">

        {/* ── Backend offline ── */}
        {!restLoading && networkDown && (
          <div className="card p-8 border-[rgba(239,68,68,0.25)] flex flex-col items-center gap-5 text-center max-w-md mx-auto mt-12">
            <div className="w-14 h-14 rounded-2xl bg-[rgba(239,68,68,0.1)] flex items-center justify-center">
              <WifiOff size={28} className="text-[var(--danger)]" />
            </div>
            <div>
              <p className="font-bold text-[var(--text-primary)] text-base mb-1">Backend not reachable</p>
              <p className="text-sm text-[var(--text-muted)] leading-relaxed">
                Start the API server, then reload this page.
              </p>
              <pre className="mt-3 text-left text-xs font-mono bg-[var(--bg-hover)] border border-[var(--border)] rounded-lg p-3 text-[var(--accent-2)]">
{`cd backend\nuvicorn app.main:app --reload`}
              </pre>
            </div>
            <button type="button" onClick={() => navigate(-1)}
              className="text-xs text-[var(--accent)] hover:underline">
              ← Go back
            </button>
          </div>
        )}

        {/* ── Scan not found ── */}
        {!restLoading && restError && !networkDown && (
          <div className="card p-8 flex flex-col items-center gap-4 text-center max-w-md mx-auto mt-12">
            <div className="w-14 h-14 rounded-2xl bg-[rgba(239,68,68,0.1)] flex items-center justify-center">
              <XCircle size={28} className="text-[var(--danger)]" />
            </div>
            <div>
              <p className="font-bold text-[var(--text-primary)] mb-1">Scan not found</p>
              <p className="text-xs text-[var(--text-muted)] font-mono">{scanId}</p>
              <p className="text-sm text-[var(--text-muted)] mt-2">{restError}</p>
            </div>
            <Link to="/history" className="text-xs text-[var(--accent)] hover:underline">
              ← View scan history
            </Link>
          </div>
        )}

        {/* ── Initial skeleton (waiting for first REST response) ── */}
        {restLoading && (
          <div className="space-y-4 animate-pulse">
            <div className="flex gap-3 items-center">
              <div className="h-5 w-16 rounded bg-[var(--bg-hover)]" />
              <div className="h-5 w-48 rounded bg-[var(--bg-hover)]" />
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[0,1,2,3].map(i => (
                <div key={i} className="card p-4 space-y-2">
                  <div className="h-2 w-16 rounded bg-[var(--bg-hover)]" />
                  <div className="h-5 w-12 rounded bg-[var(--bg-hover)]" />
                </div>
              ))}
            </div>
            <div className="card p-5 h-32 flex items-center justify-center">
              <Loader2 size={24} className="text-[var(--accent)] animate-spin" />
            </div>
          </div>
        )}

        {/* ── Main content (shown once REST resolves without error) ── */}
        {!restLoading && !restError && !networkDown && (<>

        {/* ── Scan identity ── */}
        <div className="flex flex-wrap items-start gap-4 justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <StatusBadge status={effectiveStatus} />
              {(restScan?.is_example || false) && (
                <span className="text-[10px] px-2 py-0.5 rounded-full border border-[rgba(0,212,255,0.4)] text-[var(--accent)] font-semibold uppercase tracking-wider bg-[rgba(0,212,255,0.07)]">
                  Example Report
                </span>
              )}
            </div>
            <h1 className="text-lg font-bold text-[var(--text-primary)] truncate max-w-lg">
              {restScan?.target_url ?? 'Loading…'}
            </h1>
            <p className="text-xs text-[var(--text-muted)] font-mono mt-0.5">{scanId}</p>
          </div>

          {/* Export buttons — shown once terminal */}
          {isTerminal && (
            <div className="flex gap-2 flex-shrink-0">
              <button
                id="export-json-btn"
                type="button"
                onClick={() => triggerDownload(scanId, 'json')}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--border)] text-xs text-[var(--text-muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all duration-150"
              >
                <FileJson size={13} /> JSON
              </button>
              <button
                id="export-html-btn"
                type="button"
                onClick={() => triggerDownload(scanId, 'html')}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[var(--border)] text-xs text-[var(--text-muted)] hover:border-[var(--accent-2)] hover:text-[var(--accent-2)] transition-all duration-150"
              >
                <FileText size={13} /> HTML
              </button>
            </div>
          )}
        </div>

        {/* ── Stats row ── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            {
              label: 'Status',
              value: <StatusBadge status={effectiveStatus} />,
              id: 'stat-status',
            },
            {
              label: 'Endpoints found',
              value: restScan?.endpoints_found ?? 0,
              id: 'stat-endpoints',
            },
            {
              label: 'Findings',
              value: allFindings.length,
              id: 'stat-findings',
            },
            {
              label: 'Elapsed',
              value: isTerminal && restScan?.finished_at && restScan.started_at
                ? formatElapsed(new Date(restScan.finished_at).getTime() - new Date(restScan.started_at).getTime())
                : formatElapsed(elapsed),
              id: 'stat-elapsed',
            },
          ].map(s => (
            <div key={s.id} id={s.id} className="card p-4">
              <p className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] font-semibold mb-1">
                {s.label}
              </p>
              <div className="text-base font-bold text-[var(--text-primary)]">{s.value}</div>
            </div>
          ))}
        </div>

        {/* ── Progress bar (while scanning) ── */}
        {!isTerminal && (
          <div className="card p-4">
            <div className="flex items-center justify-between mb-2 text-xs text-[var(--text-muted)]">
              <span className="capitalize font-medium">{socket.phase}</span>
              <span className="tabular-nums font-mono">{Math.round(socket.progress)}%</span>
            </div>
            <div className="h-1.5 bg-[var(--bg-hover)] rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${socket.progress}%`,
                  background: 'linear-gradient(90deg, var(--accent), var(--accent-2))',
                  boxShadow: '0 0 8px rgba(0,212,255,0.5)',
                }}
              />
            </div>
          </div>
        )}

        {/* ── Risk score (terminal) ── */}
        {isTerminal && restScan && (
          <div className="card p-4 flex flex-wrap items-center gap-4">
            <div>
              <p className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] font-semibold mb-0.5">Risk Score</p>
              <p className={`text-3xl font-extrabold tabular-nums ${
                restScan.risk_score >= 70 ? 'text-[var(--critical)]'
                : restScan.risk_score >= 40 ? 'text-[var(--warning)]'
                : 'text-[var(--success)]'
              }`}>
                {restScan.risk_score.toFixed(1)}<span className="text-base font-normal text-[var(--text-muted)]">/100</span>
              </p>
            </div>

            {/* Severity count pills */}
            <div className="flex flex-wrap gap-2 ml-auto">
              {SEVERITY_ORDER.map(sev => {
                const count = allFindings.filter(f => f.severity === sev).length;
                if (!count) return null;
                return (
                  <span key={sev} className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border text-xs font-semibold ${SEV_LABEL_CLASS[sev]}`}>
                    {count} {sev}
                  </span>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Two-column layout (chart + logs / findings) ── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

          {/* Left — Donut chart */}
          <div className="card p-5 flex flex-col">
            <p className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest mb-3">
              Severity Distribution
            </p>
            <div className="flex-1">
              <SeverityDonut findings={allFindings} />
            </div>
          </div>

          {/* Right — Live log panel */}
          <div className="lg:col-span-2 card p-5 flex flex-col" style={{ maxHeight: 280 }}>
            <p className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest mb-3 flex-shrink-0">
              Scanner Log
            </p>
            <div
              ref={logRef}
              className="flex-1 overflow-y-auto font-mono text-xs leading-relaxed space-y-0.5"
              style={{ scrollBehavior: 'smooth' }}
            >
              {socket.logs.length === 0 ? (
                <p className="text-[var(--text-muted)] italic">Waiting for scanner…</p>
              ) : (
                socket.logs.map((line, i) => (
                  <p
                    key={i}
                    className="text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                    style={{ animationDelay: `${Math.min(i * 20, 200)}ms` }}
                  >
                    <span className="text-[var(--accent)] select-none mr-2">&gt;</span>
                    {/* Plain text — never dangerouslySetInnerHTML */}
                    {line}
                  </p>
                ))
              )}
            </div>
          </div>
        </div>

        {/* ── Live findings feed (while scanning) ── */}
        {!isTerminal && socket.findings.length > 0 && (
          <div className="card p-5 space-y-3">
            <p className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest">
              Live Findings ({socket.findings.length})
            </p>
            <div className="space-y-2">
              {socket.findings.map((f, i) => (
                <div
                  key={f.id}
                  id={`live-finding-${f.id}`}
                  className="flex items-center gap-3 p-3 rounded-lg bg-[var(--bg-hover)] border border-[var(--border)]"
                  style={{
                    animation: 'slideIn 0.3s ease both',
                    animationDelay: `${i * 30}ms`,
                  }}
                >
                  <SeverityBadge sev={f.severity} />
                  <span className="text-sm text-[var(--text-primary)] flex-1 font-medium">{f.title}</span>
                  <span className="text-xs text-[var(--text-muted)] font-mono hidden sm:block">{truncate(f.url, 40)}</span>
                  <span className="text-xs font-semibold tabular-nums text-[var(--text-muted)]">
                    CVSS&nbsp;{f.cvss_score.toFixed(1)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Findings Explorer (terminal) ── */}
        {isTerminal && (
          <div className="card p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-xs font-semibold text-[var(--text-muted)] uppercase tracking-widest">
                Findings Explorer ({filteredFindings.length} of {allFindings.length})
              </p>

              {/* Controls */}
              <div className="flex flex-wrap gap-2">
                {/* Search */}
                <div className="relative">
                  <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
                  <input
                    id="findings-search"
                    type="search"
                    placeholder="Search…"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="pl-8 pr-3 py-1.5 text-xs rounded-lg bg-[var(--bg-hover)] border border-[var(--border)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] w-36"
                  />
                </div>

                {/* Severity filter pills */}
                <div className="flex gap-1">
                  {(['all', ...SEVERITY_ORDER] as const).map(sev => (
                    <button
                      key={sev}
                      id={`filter-${sev}`}
                      type="button"
                      onClick={() => setFilterSev(sev)}
                      className={[
                        'text-[10px] px-2 py-1 rounded-md border font-semibold uppercase transition-all duration-150',
                        filterSev === sev
                          ? sev === 'all'
                            ? 'bg-[rgba(0,212,255,0.15)] border-[var(--accent)] text-[var(--accent)]'
                            : `${SEV_LABEL_CLASS[sev]} opacity-100`
                          : 'border-[var(--border)] text-[var(--text-muted)] hover:border-[rgba(255,255,255,0.2)]',
                      ].join(' ')}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Findings list */}
            {filteredFindings.length === 0 ? (
              <div className="py-12 text-center text-[var(--text-muted)] text-sm">
                {allFindings.length === 0
                  ? isDone ? 'No vulnerabilities detected. Clean scan.' : 'No findings yet.'
                  : 'No findings match the current filter.'}
              </div>
            ) : (
              <div className="space-y-2">
                {filteredFindings
                  .sort((a, b) =>
                    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
                  )
                  .map(f => <FindingRow key={f.id} finding={f} />)
                }
              </div>
            )}
          </div>
        )}

        {/* ── Empty state while scanning ── */}
        {!isTerminal && socket.findings.length === 0 && (
          <div className="card p-10 flex flex-col items-center gap-3 text-center">
            <Loader2 size={32} className="text-[var(--accent)] animate-spin" />
            <p className="text-[var(--text-muted)] text-sm">
              Scanner is running — findings will appear here as they are discovered.
            </p>
          </div>
        )}

        {/* ── Failed / blocked state ── */}
        {(socket.status === 'failed' || socket.status === 'blocked') && (
          <div className="card p-5 border-[rgba(239,68,68,0.3)] flex items-start gap-3">
            <TriangleAlert size={18} className="text-[var(--danger)] flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold text-[var(--danger)] text-sm">
                Scan {socket.status === 'failed' ? 'Failed' : 'Blocked'}
              </p>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                {socket.status === 'blocked'
                  ? 'The target returned too many 4xx / WAF responses. Check the log for details.'
                  : 'An unrecoverable error occurred. Check the log panel for details.'}
              </p>
            </div>
          </div>
        )}

        </>)}

      </main>

      {/* Slide-in keyframe for live findings */}
      <style>{`
        @keyframes slideIn {
          from { opacity: 0; transform: translateY(-8px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
