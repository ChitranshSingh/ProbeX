import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  AlertTriangle,
  Zap,
  Globe,
  Lock,
  ChevronRight,
  Loader2,
  CheckCircle2,
} from 'lucide-react';
import { createScan } from '../api/client';
import type { ScanProfile } from '../types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PRACTICE_TARGET = 'http://testphp.vulnweb.com';

const CONSENT_TEXT =
  'I confirm I have explicit permission to test this target. Unauthorized scanning may be illegal.';

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function ProfileCard({
  value,
  selected,
  onSelect,
  icon,
  label,
  subtitle,
  time,
}: {
  value: ScanProfile;
  selected: boolean;
  onSelect: (v: ScanProfile) => void;
  icon: React.ReactNode;
  label: string;
  subtitle: string;
  time: string;
}) {
  return (
    <button
      type="button"
      id={`profile-${value}`}
      onClick={() => onSelect(value)}
      className={[
        'relative flex flex-col gap-2 p-4 rounded-xl border text-left transition-all duration-200 cursor-pointer',
        selected
          ? 'border-[var(--accent)] bg-[rgba(0,212,255,0.07)] shadow-[0_0_0_1px_var(--accent)]'
          : 'border-[var(--border)] bg-[var(--bg-hover)] hover:border-[rgba(0,212,255,0.4)] hover:bg-[rgba(0,212,255,0.04)]',
      ].join(' ')}
    >
      {/* Selected indicator */}
      {selected && (
        <span className="absolute top-3 right-3 text-[var(--accent)]">
          <CheckCircle2 size={16} />
        </span>
      )}

      <span
        className={`w-8 h-8 rounded-lg flex items-center justify-center ${
          selected ? 'bg-[rgba(0,212,255,0.15)] text-[var(--accent)]' : 'bg-[var(--bg-card)] text-[var(--text-muted)]'
        }`}
      >
        {icon}
      </span>

      <div>
        <p className={`font-semibold text-sm ${selected ? 'text-[var(--accent)]' : 'text-[var(--text-primary)]'}`}>
          {label}
        </p>
        <p className="text-xs text-[var(--text-muted)] mt-0.5">{subtitle}</p>
      </div>

      <span className="text-xs font-mono text-[var(--text-muted)] mt-auto pt-1 border-t border-[var(--border)]">
        ~{time}
      </span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function NewScan() {
  const navigate = useNavigate();

  const [targetUrl, setTargetUrl] = useState('');
  const [profile, setProfile] = useState<ScanProfile>('quick');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);

  // ---- URL validation ----
  function validateUrl(raw: string): string | null {
    if (!raw.trim()) return 'Target URL is required.';
    try {
      const u = new URL(raw.trim());
      if (!['http:', 'https:'].includes(u.protocol))
        return 'URL must start with http:// or https://';
      return null;
    } catch {
      return 'Please enter a valid URL (e.g. https://example.com).';
    }
  }

  function handleUrlChange(e: React.ChangeEvent<HTMLInputElement>) {
    setTargetUrl(e.target.value);
    if (urlError) setUrlError(validateUrl(e.target.value));
  }

  function fillPracticeTarget() {
    setTargetUrl(PRACTICE_TARGET);
    setUrlError(null);
  }

  // ---- Submit ----
  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const urlErr = validateUrl(targetUrl);
    if (urlErr) { setUrlError(urlErr); return; }

    if (!consent) { setError('You must accept the consent statement before scanning.'); return; }

    setLoading(true);
    try {
      const { scan_id } = await createScan({
        target_url: targetUrl.trim(),
        profile,
        consent_confirmed: consent,
      });
      navigate(`/scans/${scan_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan. Is the backend running?');
    } finally {
      setLoading(false);
    }
  }

  const canSubmit = consent && !loading && !!targetUrl.trim() && !urlError;

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------
  return (
    <div className="min-h-screen bg-[var(--bg-deep)] flex flex-col">

      {/* ── Background ambient glow ── */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-0 overflow-hidden"
      >
        <div className="absolute -top-64 -left-64 w-[600px] h-[600px] rounded-full bg-[var(--accent)] opacity-[0.04] blur-[120px]" />
        <div className="absolute -bottom-64 -right-32 w-[500px] h-[500px] rounded-full bg-[var(--accent-2)] opacity-[0.04] blur-[120px]" />
      </div>

      {/* ── Header / nav ── */}
      <header className="relative z-10 border-b border-[var(--border)] bg-[rgba(10,14,26,0.8)] backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center gap-3">
          <Shield size={22} className="text-[var(--accent)]" />
          <span className="font-bold text-lg tracking-tight text-gradient">ProbeX</span>
          <span className="ml-2 text-[var(--text-muted)] text-sm hidden sm:block">
            Dynamic Application Security Testing
          </span>
        </div>
      </header>

      {/* ── Page content ── */}
      <main className="relative z-10 flex-1 flex items-start justify-center px-4 py-16 sm:py-24">
        <div className="w-full max-w-2xl">

          {/* ── Hero heading ── */}
          <div className="text-center mb-12">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-[rgba(0,212,255,0.3)] bg-[rgba(0,212,255,0.07)] text-[var(--accent)] text-xs font-medium mb-5">
              <Zap size={12} />
              Automated Vulnerability Scanner
            </div>
            <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight leading-tight mb-4">
              <span className="text-[var(--text-primary)]">Find security flaws</span>
              <br />
              <span className="text-gradient">before attackers do</span>
            </h1>
            <p className="text-[var(--text-muted)] text-base sm:text-lg max-w-lg mx-auto leading-relaxed">
              ProbeX crawls your app, fuzzes every parameter, and surfaces
              real vulnerabilities — not just header misconfigurations.
            </p>
          </div>

          {/* ── Scan form card ── */}
          <form
            id="new-scan-form"
            onSubmit={handleSubmit}
            noValidate
            className="card p-8 space-y-7 shadow-glow"
          >

            {/* ---- Target URL ---- */}
            <div className="space-y-2">
              <label
                htmlFor="target-url"
                className="block text-sm font-semibold text-[var(--text-primary)]"
              >
                Target URL
                <span className="text-[var(--danger)] ml-1">*</span>
              </label>

              <div className="relative">
                <Globe
                  size={16}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] pointer-events-none"
                />
                <input
                  id="target-url"
                  type="url"
                  name="target_url"
                  placeholder="https://your-app.example.com"
                  value={targetUrl}
                  onChange={handleUrlChange}
                  onBlur={() => setUrlError(validateUrl(targetUrl))}
                  autoComplete="url"
                  spellCheck={false}
                  aria-describedby={urlError ? 'url-error' : undefined}
                  aria-invalid={!!urlError}
                  className={[
                    'w-full bg-[var(--bg-hover)] text-[var(--text-primary)] placeholder-[var(--text-muted)]',
                    'pl-9 pr-4 py-3 rounded-xl border text-sm font-mono transition-all duration-200',
                    'focus:outline-none focus:ring-2 focus:ring-[var(--accent)] focus:border-transparent',
                    urlError
                      ? 'border-[var(--danger)]'
                      : 'border-[var(--border)] hover:border-[rgba(0,212,255,0.3)]',
                  ].join(' ')}
                />
              </div>

              {urlError && (
                <p id="url-error" className="flex items-center gap-1.5 text-xs text-[var(--danger)]" role="alert">
                  <AlertTriangle size={12} />
                  {urlError}
                </p>
              )}

              {/* Practice target hint */}
              <div className="flex items-center gap-2 pt-1">
                <span className="text-xs text-[var(--text-muted)]">Don't have a target?</span>
                <button
                  type="button"
                  id="fill-practice-target"
                  onClick={fillPracticeTarget}
                  className="text-xs text-[var(--accent)] hover:text-[var(--accent-2)] underline underline-offset-2 transition-colors duration-150 font-medium"
                >
                  Try a safe practice target ↗
                </button>
              </div>
            </div>

            {/* ---- Scan profile ---- */}
            <div className="space-y-3">
              <p className="text-sm font-semibold text-[var(--text-primary)]">
                Scan Profile
              </p>
              <div className="grid grid-cols-2 gap-3">
                <ProfileCard
                  value="quick"
                  selected={profile === 'quick'}
                  onSelect={setProfile}
                  icon={<Zap size={16} />}
                  label="Quick"
                  subtitle="Depth 1 crawl, reduced payload set"
                  time="30 s"
                />
                <ProfileCard
                  value="standard"
                  selected={profile === 'standard'}
                  onSelect={setProfile}
                  icon={<Shield size={16} />}
                  label="Standard"
                  subtitle="Multi-depth crawl, full payload library"
                  time="3 min"
                />
              </div>
            </div>

            {/* ---- Consent ---- */}
            <div
              className={[
                'rounded-xl border p-4 transition-all duration-200',
                consent
                  ? 'border-[var(--success)] bg-[rgba(16,185,129,0.06)]'
                  : 'border-[var(--border)] bg-[var(--bg-hover)]',
              ].join(' ')}
            >
              <label
                htmlFor="consent-checkbox"
                className="flex items-start gap-3 cursor-pointer select-none group"
              >
                {/* Custom checkbox */}
                <div className="relative mt-0.5 flex-shrink-0">
                  <input
                    id="consent-checkbox"
                    type="checkbox"
                    name="consent_confirmed"
                    checked={consent}
                    onChange={e => setConsent(e.target.checked)}
                    className="sr-only peer"
                    required
                    aria-describedby="consent-text"
                  />
                  <div
                    className={[
                      'w-5 h-5 rounded-md border-2 flex items-center justify-center transition-all duration-200',
                      consent
                        ? 'bg-[var(--success)] border-[var(--success)]'
                        : 'bg-transparent border-[var(--border)] group-hover:border-[var(--success)]',
                    ].join(' ')}
                  >
                    {consent && (
                      <svg viewBox="0 0 12 10" className="w-3 h-3 text-white fill-none stroke-current stroke-2">
                        <polyline points="1,5 4,8 11,1" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    )}
                  </div>
                </div>

                <div>
                  <span
                    id="consent-text"
                    className="text-sm text-[var(--text-primary)] leading-snug"
                  >
                    {CONSENT_TEXT}
                  </span>
                  <div className="flex items-center gap-1 mt-1.5">
                    <Lock size={10} className="text-[var(--text-muted)]" />
                    <span className="text-[10px] text-[var(--text-muted)]">
                      Required — POST /api/scans returns HTTP 400 without this confirmation
                    </span>
                  </div>
                </div>
              </label>
            </div>

            {/* ---- Global error ---- */}
            {error && (
              <div
                className="flex items-start gap-2 p-3 rounded-lg bg-[rgba(239,68,68,0.1)] border border-[rgba(239,68,68,0.3)] text-[var(--danger)] text-sm"
                role="alert"
              >
                <AlertTriangle size={15} className="flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            {/* ---- Submit ---- */}
            <button
              id="start-scan-btn"
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              className={[
                'w-full flex items-center justify-center gap-2 py-3.5 px-6 rounded-xl',
                'font-semibold text-sm transition-all duration-200',
                canSubmit
                  ? [
                      'bg-gradient-to-r from-[var(--accent)] to-[var(--accent-2)]',
                      'text-[var(--bg-deep)] shadow-glow cursor-pointer',
                      'hover:shadow-[0_0_40px_rgba(0,212,255,0.3)] hover:scale-[1.01]',
                      'active:scale-[0.99]',
                    ].join(' ')
                  : 'bg-[var(--bg-hover)] text-[var(--text-muted)] border border-[var(--border)] cursor-not-allowed',
              ].join(' ')}
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Starting scan…
                </>
              ) : (
                <>
                  <Shield size={16} />
                  Start Scan
                  <ChevronRight size={16} />
                </>
              )}
            </button>

            {/* Subtle hint when button is locked */}
            {!consent && !loading && (
              <p className="text-center text-xs text-[var(--text-muted)]">
                Accept the consent statement to enable scanning
              </p>
            )}
          </form>

          {/* ── Feature pills ── */}
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            {[
              '✦ XSS & SQL Injection',
              '✦ SSRF & Path Traversal',
              '✦ SSTI Detection',
              '✦ Security Headers',
              '✦ Baseline false-positive defence',
            ].map(f => (
              <span
                key={f}
                className="text-xs px-3 py-1 rounded-full border border-[var(--border)] text-[var(--text-muted)] bg-[var(--bg-card)]"
              >
                {f}
              </span>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
