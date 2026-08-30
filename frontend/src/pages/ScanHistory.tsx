import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe, Clock, ChevronRight, AlertTriangle, CheckCircle2,
  XCircle, Loader2, RefreshCw, ServerCrash, Microscope,
  Trash2, ShieldAlert,
} from 'lucide-react';
import { listScans, deleteScan, clearHistory } from '../api/client';
import type { ScanStatus, ScanSummary, Severity } from '../types';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_CLASS: Record<Severity, string> = {
  critical: 'badge-critical', high: 'badge-high',
  medium: 'badge-medium', low: 'badge-low', info: 'badge-info',
};

const SEV_DOT: Record<Severity, string> = {
  critical: 'var(--sev-critical)', high: 'var(--sev-high)',
  medium: 'var(--sev-medium)', low: 'var(--sev-low)', info: 'var(--sev-info)',
};

function relativeTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h ago` : `${Math.floor(h / 24)}d ago`;
}

function riskColor(score: number) {
  if (score >= 70) return 'var(--danger)';
  if (score >= 40) return 'var(--warning)';
  return 'var(--success)';
}

function StatusPill({ status }: { status: ScanStatus }) {
  const map: Record<ScanStatus, { label: string; cls: string; icon: React.ReactNode }> = {
    done:      { label: 'Complete',  cls: 'status-done',    icon: <CheckCircle2 size={11} /> },
    failed:    { label: 'Failed',    cls: 'status-failed',  icon: <XCircle size={11} /> },
    blocked:   { label: 'Blocked',   cls: 'status-failed',  icon: <AlertTriangle size={11} /> },
    queued:    { label: 'Queued',    cls: 'status-queued',  icon: <Clock size={11} /> },
    crawling:  { label: 'Crawling',  cls: 'status-running', icon: <Loader2 size={11} className="animate-spin" /> },
    fuzzing:   { label: 'Fuzzing',   cls: 'status-running', icon: <Loader2 size={11} className="animate-spin" /> },
    analyzing: { label: 'Analyzing', cls: 'status-running', icon: <Loader2 size={11} className="animate-spin" /> },
  };
  const s = map[status] ?? map.queued;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold ${s.cls}`}>
      {s.icon} {s.label}
    </span>
  );
}

function isNetworkError(msg: string) {
  return msg.toLowerCase().includes('failed to fetch') ||
    msg.toLowerCase().includes('networkerror') ||
    msg.toLowerCase().includes('load failed');
}

function SkeletonRow() {
  return (
    <tr style={{ borderBottom: '1px solid var(--border)' }}>
      {[48, 20, 24, 16, 32, 16, 10].map((w, i) => (
        <td key={i} className="px-5 py-4">
          <div className="skeleton h-4 rounded" style={{ width: `${w * 4}px` }} />
        </td>
      ))}
    </tr>
  );
}

function ScanRow({
  scan, onDelete,
}: { scan: ScanSummary; onDelete: (id: string) => void }) {
  const [deleting, setDeleting] = useState(false);
  const total = Object.values(scan.findings_by_severity).reduce((a, b) => a + b, 0);

  async function handleDelete(e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    if (!confirm('Delete this scan and all associated findings?')) return;
    setDeleting(true);
    try {
      await deleteScan(scan.scan_id);
      onDelete(scan.scan_id);
    } catch {
      setDeleting(false);
    }
  }

  return (
    <tr
      id={`scan-row-${scan.scan_id}`}
      className="group transition-colors"
      style={{ borderBottom: '1px solid var(--border)' }}
      onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-hover)')}
      onMouseLeave={e => (e.currentTarget.style.background = '')}
    >
      {/* Target */}
      <td className="px-5 py-4">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: 'var(--accent-dim)' }}>
            <Globe size={14} style={{ color: 'var(--accent)' }} />
          </div>
          <div className="min-w-0">
            <Link
              to={`/scans/${scan.scan_id}`}
              className="text-sm font-bold truncate block max-w-xs hover:underline"
              style={{ color: 'var(--text-primary)' }}
            >
              {scan.target_url}
            </Link>
            <p className="text-[11px] font-mono mt-0.5 truncate" style={{ color: 'var(--text-muted)' }}>
              {scan.scan_id}
            </p>
          </div>
          {scan.is_example && (
            <span
              className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border font-semibold uppercase tracking-wider flex-shrink-0"
              style={{ background: 'var(--bg-subtle)', borderColor: 'var(--border)', color: 'var(--text-muted)' }}
            >
              <Microscope size={10} /> Demo Data
            </span>
          )}
        </div>
      </td>

      {/* Status */}
      <td className="px-4 py-4"><StatusPill status={scan.status} /></td>

      {/* Time */}
      <td className="px-4 py-4 text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>
        <span className="flex items-center gap-1.5">
          <Clock size={12} style={{ color: 'var(--text-muted)' }} />
          {relativeTime(scan.started_at)}
        </span>
      </td>

      {/* Endpoints */}
      <td className="px-4 py-4 text-xs font-mono font-semibold tabular-nums" style={{ color: 'var(--text-primary)' }}>
        {scan.endpoints_found}
      </td>

      {/* Findings */}
      <td className="px-4 py-4">
        {total > 0 ? (
          <div className="flex gap-1.5 flex-wrap">
            {SEV_ORDER.map(sev => {
              const count = scan.findings_by_severity[sev] ?? 0;
              if (!count) return null;
              return (
                <span key={sev}
                  className={`inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded border font-bold ${SEV_CLASS[sev]}`}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEV_DOT[sev] }} />
                  {count}
                </span>
              );
            })}
          </div>
        ) : (
          <span className="text-xs font-medium" style={{ color: 'var(--text-faint)' }}>Clean</span>
        )}
      </td>

      {/* Risk */}
      <td className="px-4 py-4">
        {scan.status === 'done' && (
          <span className="text-sm font-extrabold tabular-nums" style={{ color: riskColor(scan.risk_score) }}>
            {scan.risk_score.toFixed(0)}
            <span className="text-xs font-normal" style={{ color: 'var(--text-muted)' }}>/100</span>
          </span>
        )}
      </td>

      {/* Actions */}
      <td className="px-4 py-4">
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <Link to={`/scans/${scan.scan_id}`} className="p-1 rounded hover:bg-black/10 transition-colors">
            <ChevronRight size={16} style={{ color: 'var(--text-secondary)' }} />
          </Link>
          {!scan.is_example && (
            <button
              type="button"
              onClick={handleDelete}
              disabled={deleting}
              className="p-1 rounded hover:bg-rose-500/10 transition-colors"
              title="Delete scan"
            >
              {deleting
                ? <Loader2 size={14} className="animate-spin text-rose-500" />
                : <Trash2 size={14} className="text-rose-500" />}
            </button>
          )}
        </div>
      </td>
    </tr>
  );
}

export default function ScanHistory() {
  const [scans, setScans]       = useState<ScanSummary[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [netDown, setNetDown]   = useState(false);
  const [clearing, setClearing] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);

  async function fetchScans() {
    setLoading(true); setError(null); setNetDown(false);
    try {
      const data = await listScans();
      setScans([...data].sort((a, b) =>
        new Date(b.started_at).getTime() - new Date(a.started_at).getTime()));
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Error';
      setNetDown(isNetworkError(msg));
      setError(msg);
    } finally { setLoading(false); }
  }

  async function handleClearHistory() {
    setClearing(true); setShowConfirm(false);
    try {
      await clearHistory(true);
      await fetchScans();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to clear history');
    } finally { setClearing(false); }
  }

  function removeFromList(id: string) {
    setScans(prev => prev.filter(s => s.scan_id !== id));
  }

  useEffect(() => { void fetchScans(); }, []);

  const realScans    = scans.filter(s => !s.is_example);
  const exampleScans = scans.filter(s => s.is_example);
  const doneScans    = scans.filter(s => s.status === 'done');
  const totalFindings = scans.reduce(
    (acc, s) => acc + Object.values(s.findings_by_severity).reduce((a, b) => a + b, 0), 0);

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-deep)' }}>

      {/* Header */}
      <div className="page-header justify-between">
        <div className="flex items-center gap-2">
          <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>Scan History & Audit Log</p>
          <span className="text-[11px] font-bold px-2 py-0.5 rounded-full"
            style={{ background: 'var(--accent-dim)', color: 'var(--accent)' }}>
            {scans.length} Scans Total
          </span>
        </div>
        <div className="flex items-center gap-2">
          {realScans.length > 0 && (
            <button
              id="clear-history-btn"
              type="button"
              onClick={() => setShowConfirm(true)}
              disabled={clearing}
              className="btn btn-sm btn-danger"
            >
              {clearing
                ? <Loader2 size={13} className="animate-spin" />
                : <Trash2 size={13} />}
              Clear History
            </button>
          )}
          <button
            id="refresh-history-btn"
            type="button"
            onClick={() => void fetchScans()}
            disabled={loading}
            className="btn btn-sm btn-ghost"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* Confirm modal */}
      {showConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)' }}>
          <div className="card p-6 max-w-md w-full space-y-4 shadow-xl">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
                style={{ background: 'var(--sev-critical-bg)', color: 'var(--sev-critical)' }}>
                <Trash2 size={20} />
              </div>
              <div>
                <p className="text-base font-bold" style={{ color: 'var(--text-primary)' }}>
                  Clear Scan History?
                </p>
                <p className="text-xs mt-0.5 leading-relaxed" style={{ color: 'var(--text-muted)' }}>
                  This will permanently delete {realScans.length} user-initiated scan{realScans.length !== 1 ? 's' : ''} and all associated findings. Pre-seeded demo records will be preserved.
                </p>
              </div>
            </div>
            <div className="flex gap-2 justify-end pt-2">
              <button type="button" onClick={() => setShowConfirm(false)} className="btn btn-sm btn-ghost">
                Cancel
              </button>
              <button type="button" onClick={() => void handleClearHistory()} className="btn btn-sm btn-danger">
                Delete Scans
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="page-content space-y-6">

        {/* Dynamic Multi-Color Summary Cards */}
        {!loading && !netDown && !error && scans.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: 'Total Executions', value: scans.length, cls: 'stat-card stat-card-indigo' },
              { label: 'Successful Scans', value: doneScans.length, cls: 'stat-card stat-card-green' },
              { label: 'Discovered Findings', value: totalFindings, cls: 'stat-card stat-card-amber' },
              {
                label: 'Average Risk',
                value: doneScans.length
                  ? `${(doneScans.reduce((a, b) => a + b.risk_score, 0) / doneScans.length).toFixed(0)}/100`
                  : '—',
                cls: 'stat-card stat-card-red',
              },
            ].map(s => (
              <div key={s.label} className={s.cls}>
                <p className="label-xs mb-2" style={{ color: 'var(--text-muted)' }}>{s.label}</p>
                <p className="text-2xl font-black tabular-nums" style={{ color: 'var(--text-primary)' }}>
                  {s.value}
                </p>
              </div>
            ))}
          </div>
        )}

        {/* Backend Offline Banner */}
        {!loading && netDown && (
          <div className="card p-8 max-w-md flex flex-col items-center gap-5 text-center mx-auto mt-8">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center"
              style={{ background: 'var(--sev-critical-bg)', color: 'var(--sev-critical)' }}>
              <ServerCrash size={24} />
            </div>
            <div>
              <p className="font-bold text-base mb-1" style={{ color: 'var(--text-primary)' }}>Backend API Offline</p>
              <p className="text-xs mb-4" style={{ color: 'var(--text-muted)' }}>
                Please start the FastAPI server to access scan logs.
              </p>
              <pre className="text-xs text-left rounded-lg p-3"
                style={{ background: 'var(--log-bg)', border: '1px solid var(--border)', color: '#34d399', fontFamily: "'JetBrains Mono', monospace" }}>
{`cd backend
uvicorn app.main:app --reload`}
              </pre>
            </div>
            <button type="button" onClick={() => void fetchScans()} className="btn btn-ghost btn-sm">
              <RefreshCw size={13} /> Reconnect
            </button>
          </div>
        )}

        {/* Error Alert */}
        {!loading && error && !netDown && (
          <div className="p-4 rounded-xl flex items-center gap-3 text-sm font-medium"
            style={{ background: 'var(--sev-critical-bg)', border: '1px solid var(--sev-critical-bd)', color: 'var(--sev-critical)' }}>
            <AlertTriangle size={16} className="flex-shrink-0" />
            <span>{error}</span>
            <button onClick={() => void fetchScans()} className="ml-auto text-xs hover:underline">Retry</button>
          </div>
        )}

        {/* Scans Table */}
        {!netDown && !error && (
          <div className="card overflow-hidden">
            <table className="w-full">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-subtle)' }}>
                  {['Target Application', 'Status', 'Started', 'Endpoints', 'Findings Summary', 'Risk Score', ''].map(h => (
                    <th key={h} className="px-5 py-3 text-left">
                      <span className="label-xs" style={{ color: 'var(--text-muted)' }}>{h}</span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  [0, 1, 2, 3].map(i => <SkeletonRow key={i} />)
                ) : scans.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-16 text-center">
                      <div className="flex flex-col items-center gap-3">
                        <ShieldAlert size={32} style={{ color: 'var(--text-faint)' }} />
                        <p className="text-sm font-bold" style={{ color: 'var(--text-primary)' }}>No security scans executed yet</p>
                        <p className="text-xs max-w-sm mb-2" style={{ color: 'var(--text-muted)' }}>
                          Launch your first DAST security scan to identify potential vulnerabilities.
                        </p>
                        <Link to="/" className="btn btn-primary btn-sm">
                          Launch First Scan
                        </Link>
                      </div>
                    </td>
                  </tr>
                ) : (
                  <>
                    {realScans.map(s => (
                      <ScanRow key={s.scan_id} scan={s} onDelete={removeFromList} />
                    ))}
                    {exampleScans.length > 0 && (
                      <>
                        {realScans.length > 0 && (
                          <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-subtle)' }}>
                            <td colSpan={7} className="px-5 py-2">
                              <span className="label-xs flex items-center gap-1.5"
                                style={{ color: 'var(--text-muted)' }}>
                                <Microscope size={12} /> Pre-seeded Demo Data
                              </span>
                            </td>
                          </tr>
                        )}
                        {exampleScans.map(s => (
                          <ScanRow key={s.scan_id} scan={s} onDelete={removeFromList} />
                        ))}
                      </>
                    )}
                  </>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
