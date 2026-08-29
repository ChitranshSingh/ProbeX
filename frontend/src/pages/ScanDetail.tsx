/**
 * ProbeX – stub ScanDetail page (Task S6 will replace this with the full dashboard).
 * Shown at /scans/:id after a scan is created.
 */
import { useParams, Link } from 'react-router-dom';
import { Shield, ArrowLeft, Clock } from 'lucide-react';

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();

  return (
    <div className="min-h-screen bg-[var(--bg-deep)] flex flex-col">
      {/* Header */}
      <header className="border-b border-[var(--border)] bg-[rgba(10,14,26,0.8)] backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center gap-3">
          <Shield size={22} className="text-[var(--accent)]" />
          <span className="font-bold text-lg tracking-tight text-gradient">ProbeX</span>
        </div>
      </header>

      <main className="flex-1 flex items-center justify-center px-4 py-24">
        <div className="card p-12 max-w-lg w-full text-center space-y-6">
          <div className="w-16 h-16 rounded-2xl bg-[rgba(0,212,255,0.1)] flex items-center justify-center mx-auto">
            <Clock size={32} className="text-[var(--accent)] animate-pulse" />
          </div>

          <div>
            <h1 className="text-2xl font-bold text-[var(--text-primary)] mb-2">
              Scan in progress
            </h1>
            <p className="text-[var(--text-muted)] text-sm leading-relaxed">
              Scan <code className="text-[var(--accent)] font-mono text-xs bg-[var(--bg-hover)] px-2 py-0.5 rounded">{id}</code>{' '}
              has been queued. The real-time dashboard (Task S6) will show live findings here.
            </p>
          </div>

          <div className="flex flex-col sm:flex-row gap-3 justify-center pt-2">
            <Link
              to="/"
              id="back-to-new-scan"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl border border-[var(--border)] text-[var(--text-muted)] text-sm hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors duration-200"
            >
              <ArrowLeft size={15} />
              New Scan
            </Link>
          </div>
        </div>
      </main>
    </div>
  );
}
