/**
 * ProbeX – Scan History page.
 *
 * Rendered at /history.
 * Fetches GET /api/scans (newest first) and renders a card for each scan.
 *
 * Loading states
 * --------------
 * - **Skeleton** cards pulse while the first fetch is in flight.
 * - **Backend offline** error card shows a clear "Start the backend" message
 *   when fetch() rejects with a network error (backend not running).
 * - **API error** card for any non-network failure.
 *
 * Example badge
 * -------------
 * Scans with is_example=true receive "Example Report — full coverage preview"
 * so they are never confused with real live runs.
 */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Clock, Globe, ChevronRight,
  AlertTriangle, CheckCircle2, XCircle, Loader2,
  Microscope, BarChart3, History, RefreshCw, ServerCrash,
} from 'lucide-react';

import { listScans } from '../api/client';
import type { ScanStatus, ScanSummary, Severity } from '../types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_LABEL_CLASS: Record<Severity, string> = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  info:     'badge-info',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function statusIcon(status: ScanStatus) {
  switch (status) {
    case 'done':    return <CheckCircle2 size={14} className="text-[var(--success)]" />;
    case 'failed':  return <XCircle size={14} className="text-[var(--danger)]" />;
    case 'blocked': return <AlertTriangle size={14} className="text-[var(--warning)]" />;
    default:        return <Loader2 size={14} className="text-[var(--accent)] animate-spin" />;
  }
}

function statusColor(status: ScanStatus): string {
  switch (status) {
    case 'done':    return 'text-[var(--success)]';
    case 'failed':  return 'text-[var(--danger)]';
    case 'blocked': return 'text-[var(--warning)]';
    default:        return 'text-[var(--accent)]';
  }
}

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60)  return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60)  return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24)  return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

function riskColor(score: number): string {
  if (score >= 70) return 'text-[var(--critical)]';
  if (score >= 40) return 'text-[var(--warning)]';
  return 'text-[var(--success)]';
}

/** True when the error looks like a network-level failure (backend down). */
function isNetworkError(msg: string): boolean {
  return (
    msg.toLowerCase().includes('failed to fetch') ||
    msg.toLowerCase().includes('networkerror') ||
    msg.toLowerCase().includes('net::err') ||
    msg.toLowerCase().includes('load failed')
  );
}

// ---------------------------------------------------------------------------
// Skeleton card (shown while loading)
// ---------------------------------------------------------------------------

function SkeletonCard() {
  return (
    <div className="card p-5 animate-pulse space-y-3">
      <div className="flex items-center gap-2">
        <div className="h-3 w-3 rounded bg-[var(--bg-hover)]" />
        <div className="h-3 w-48 rounded bg-[var(--bg-hover)]" />
        <div className="h-4 w-20 rounded-full bg-[var(--bg-hover)] ml-2" />
      </div>
      <div className="flex gap-4">
        <div className="h-2.5 w-12 rounded bg-[var(--bg-hover)]" />
        <div className="h-2.5 w-16 rounded bg-[var(--bg-hover)]" />
        <div className="h-2.5 w-20 rounded bg-[var(--bg-hover)]" />
      </div>
      <div className="flex gap-2">
        <div className="h-5 w-16 rounded-md bg-[var(--bg-hover)]" />
        <div className="h-5 w-14 rounded-md bg-[var(--bg-hover)]" />
      </div>
      <div className="pt-2 border-t border-[var(--border)]">
        <div className="h-2 w-56 rounded bg-[var(--bg-hover)]" />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Backend offline error card
// ---------------------------------------------------------------------------

function BackendOfflineCard({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="card p-8 border-[rgba(239,68,68,0.25)] flex flex-col items-center gap-5 text-center max-w-md mx-auto">
      <div className="w-14 h-14 rounded-2xl bg-[rgba(239,68,68,0.1)] flex items-center justify-center">
        <ServerCrash size={28} className="text-[var(--danger)]" />
      </div>
      <div>
        <p className="font-bold text-[var(--text-primary)] text-base mb-1">Backend not running</p>
        <p className="text-sm text-[var(--text-muted)] leading-relaxed">
          The ProbeX API server is not reachable at{' '}
          <code className="text-[var(--accent)] font-mono text-xs bg-[var(--bg-hover)] px-1.5 py-0.5 rounded">
            localhost:8000
          </code>
          . Start it with:
        </p>
        <pre className="mt-3 text-left text-xs font-mono bg-[var(--bg-hover)] border border-[var(--border)] rounded-lg p-3 text-[var(--accent-2)]">
{`cd backend
uvicorn app.main:app --reload`}
        </pre>
      </div>
      <button
        id="retry-backend-btn"
        type="button"
        onClick={onRetry}
        className="flex items-center gap-2 px-4 py-2 rounded-xl border border-[var(--border)] text-sm text-[var(--text-muted)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-all duration-200"
      >
        <RefreshCw size={13} /> Try again
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scan card
// ---------------------------------------------------------------------------

function ScanCard({ scan }: { scan: ScanSummary }) {
  const totalFindings = Object.values(scan.findings_by_severity).reduce((a, b) => a + b, 0);

  return (
    <Link
      to={`/scans/${scan.scan_id}`}
      id={`scan-card-${scan.scan_id}`}
      className="block card p-5 hover:border-[rgba(0,212,255,0.3)] hover:bg-[rgba(0,212,255,0.02)] transition-all duration-200 group"
    >
      <div className="flex items-start justify-between gap-4">
        {/* Left: info */}
        <div className="flex-1 min-w-0 space-y-3">

          {/* Title row */}
          <div className="flex flex-wrap items-center gap-2">
            <Globe size={14} className="text-[var(--text-muted)] flex-shrink-0" />
            <span className="text-sm font-semibold text-[var(--text-primary)] truncate max-w-sm">
              {scan.target_url}
            </span>

            {/* Example badge */}
            {scan.is_example && (
              <span
                id={`example-badge-${scan.scan_id}`}
                className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border border-[rgba(0,212,255,0.4)] text-[var(--accent)] font-semibold uppercase tracking-wider bg-[rgba(0,212,255,0.07)] flex-shrink-0"
              >
                <Microscope size={10} />
                Example Report — full coverage preview
              </span>
            )}
          </div>

          {/* Meta row */}
          <div className="flex flex-wrap items-center gap-4 text-xs text-[var(--text-muted)]">
            <span className={`flex items-center gap-1 font-semibold ${statusColor(scan.status)}`}>
              {statusIcon(scan.status)}
              {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
            </span>
            <span className="flex items-center gap-1">
              <Clock size={11} />
              {relativeTime(scan.started_at)}
            </span>
            <span>{scan.endpoints_found} endpoints</span>
            <span className="font-semibold">
              {totalFindings} finding{totalFindings !== 1 ? 's' : ''}
            </span>
          </div>

          {/* Severity pills */}
          {totalFindings > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {SEVERITY_ORDER.map(sev => {
                const count = scan.findings_by_severity[sev] ?? 0;
                if (!count) return null;
                return (
                  <span
                    key={sev}
                    className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-md border font-semibold ${SEV_LABEL_CLASS[sev]}`}
                  >
                    {count} {sev}
                  </span>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: risk score + arrow */}
        <div className="flex flex-col items-end gap-2 flex-shrink-0">
          {scan.status === 'done' && (
            <div className="text-right">
              <p className="text-[10px] uppercase tracking-widest text-[var(--text-muted)] font-semibold">Risk</p>
              <p className={`text-xl font-extrabold tabular-nums ${riskColor(scan.risk_score)}`}>
                {scan.risk_score.toFixed(0)}
                <span className="text-xs font-normal text-[var(--text-muted)]">/100</span>
              </p>
            </div>
          )}
          <ChevronRight
            size={18}
            className="text-[var(--text-muted)] group-hover:text-[var(--accent)] transition-colors duration-150"
          />
        </div>
      </div>

      {/* Scan ID */}
      <p className="mt-3 pt-3 border-t border-[var(--border)] text-[10px] font-mono text-[var(--text-muted)]">
        {scan.scan_id}
      </p>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ScanHistory() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [networkError, setNetworkError] = useState(false);

  async function fetchScans() {
    setLoading(true);
    setError(null);
    setNetworkError(false);
    try {
      const data = await listScans();
      setScans([...data].sort(
        (a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime(),
      ));
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to load scans.';
      if (isNetworkError(msg)) {
        setNetworkError(true);
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void fetchScans(); }, []);

  const realScans    = scans.filter(s => !s.is_example);
  const exampleScans = scans.filter(s => s.is_example);

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-[var(--bg-deep)] flex flex-col">

      {/* Ambient glow */}
      <div aria-hidden="true" className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-64 -right-64 w-[500px] h-[500px] rounded-full bg-[var(--accent-2)] opacity-[0.03] blur-[120px]" />
      </div>

      {/* ── Header ── */}
      <header className="relative z-10 border-b border-[var(--border)] bg-[rgba(10,14,26,0.85)] backdrop-blur-md sticky top-0">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center gap-4">
          <Shield size={20} className="text-[var(--accent)]" />
          <span className="font-bold tracking-tight text-gradient">ProbeX</span>

          <span className="text-[var(--border)] select-none">|</span>

          <Link to="/" id="header-new-scan" className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors">
            New Scan
          </Link>
          <span className="text-xs text-[var(--text-primary)] font-semibold flex items-center gap-1">
            <History size={12} /> History
          </span>

          <button
            id="refresh-history-btn"
            type="button"
            onClick={() => void fetchScans()}
            disabled={loading}
            className="ml-auto flex items-center gap-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--accent)] transition-colors disabled:opacity-50"
          >
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </header>

      <main className="relative z-10 flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-10 space-y-8">

        {/* Page heading */}
        <div className="flex items-center gap-3">
          <BarChart3 size={22} className="text-[var(--accent)]" />
          <div>
            <h1 className="text-2xl font-extrabold text-[var(--text-primary)]">Scan History</h1>
            <p className="text-sm text-[var(--text-muted)]">
              {loading ? 'Loading…' : `${scans.length} scan${scans.length !== 1 ? 's' : ''} on record`}
            </p>
          </div>
        </div>

        {/* ── Skeleton loading ── */}
        {loading && (
          <div className="space-y-3" aria-label="Loading scans" aria-busy="true">
            <div className="h-3 w-16 rounded bg-[var(--bg-hover)] animate-pulse mb-4" />
            <SkeletonCard />
            <SkeletonCard />
            <SkeletonCard />
          </div>
        )}

        {/* ── Backend offline ── */}
        {!loading && networkError && (
          <BackendOfflineCard onRetry={() => void fetchScans()} />
        )}

        {/* ── Generic API error ── */}
        {!loading && error && !networkError && (
          <div className="card p-5 border-[rgba(239,68,68,0.3)] flex items-start gap-3">
            <AlertTriangle size={16} className="text-[var(--danger)] flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-semibold text-[var(--danger)]">Could not load scans</p>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">{error}</p>
              <button
                type="button"
                onClick={() => void fetchScans()}
                className="mt-3 text-xs text-[var(--accent)] hover:underline"
              >
                Try again
              </button>
            </div>
          </div>
        )}

        {/* ── Real scans ── */}
        {!loading && !error && !networkError && (
          <>
            {realScans.length > 0 ? (
              <section className="space-y-3" aria-label="Your scans">
                <h2 className="text-xs uppercase tracking-widest text-[var(--text-muted)] font-semibold px-1">
                  Your Scans
                </h2>
                <div className="space-y-3">
                  {realScans.map(s => <ScanCard key={s.scan_id} scan={s} />)}
                </div>
              </section>
            ) : (
              <div className="card p-12 text-center space-y-4">
                <div className="w-14 h-14 rounded-2xl bg-[rgba(0,212,255,0.08)] flex items-center justify-center mx-auto">
                  <Shield size={26} className="text-[var(--accent)]" />
                </div>
                <div>
                  <p className="font-semibold text-[var(--text-primary)]">No scans yet</p>
                  <p className="text-sm text-[var(--text-muted)] mt-1">
                    Start your first scan to see results here.
                  </p>
                </div>
                <Link
                  to="/"
                  id="history-new-scan-cta"
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-[var(--accent)] to-[var(--accent-2)] text-[var(--bg-deep)] text-sm font-semibold hover:opacity-90 transition-opacity"
                >
                  <Shield size={14} /> New Scan
                </Link>
              </div>
            )}

            {/* ── Example scans (always at bottom) ── */}
            {exampleScans.length > 0 && (
              <section className="space-y-3" aria-label="Example scans">
                <h2 className="text-xs uppercase tracking-widest text-[var(--text-muted)] font-semibold px-1 flex items-center gap-2">
                  <Microscope size={12} />
                  Example Scans
                  <span className="normal-case font-normal text-[var(--text-muted)]">
                    — pre-seeded demo data, not from a live run
                  </span>
                </h2>
                <div className="space-y-3">
                  {exampleScans.map(s => <ScanCard key={s.scan_id} scan={s} />)}
                </div>
              </section>
            )}
          </>
        )}
      </main>
    </div>
  );
}
