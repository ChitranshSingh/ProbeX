/**
 * ProbeX – hand-mirrored TypeScript types from backend/app/schemas.py
 *
 * These are intentionally hand-written to avoid the openapi-typescript
 * toolchain dependency at scaffold time (the backend must be running for the
 * generator to work). Once the backend is live:
 *
 *   npx openapi-typescript http://localhost:8000/openapi.json -o src/types.ts
 *
 * …will regenerate this file with full fidelity to the server schema.
 */

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

export type ScanStatus =
  | 'queued'
  | 'crawling'
  | 'fuzzing'
  | 'analyzing'
  | 'done'
  | 'failed'
  | 'blocked';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScanProfile = 'quick' | 'standard';

// ---------------------------------------------------------------------------
// Request models
// ---------------------------------------------------------------------------

/** POST /api/scans body */
export interface ScanRequest {
  /** Fully-qualified URL of the application under test. */
  target_url: string;
  /** 'quick' (~30 s) or 'standard' (~3 min). */
  profile: ScanProfile;
  /**
   * Must be true — the caller confirms they have authorisation to test the
   * target. The backend returns HTTP 400 if this is false.
   */
  consent_confirmed: boolean;
}

/** POST /api/scans response */
export interface ScanCreatedResponse {
  scan_id: string;
  status: 'queued';
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

export interface Finding {
  id: string;
  template_id: string;
  title: string;
  severity: Severity;
  url: string;
  parameter: string | null;
  payload: string | null;
  evidence: string;
  cwe: string;
  owasp: string;
  cvss_score: number;
  confidence: number;
  remediation: string;
  ai_remediation: string | null;
  /** True for seed-script injected demo findings. */
  is_example: boolean;
}

// ---------------------------------------------------------------------------
// ScanSummary
// ---------------------------------------------------------------------------

export interface ScanSummary {
  scan_id: string;
  target_url: string;
  status: ScanStatus;
  /** ISO-8601 UTC string. */
  started_at: string;
  /** ISO-8601 UTC string or null while running. */
  finished_at: string | null;
  endpoints_found: number;
  findings_by_severity: Record<Severity, number>;
  /** Composite risk score [0, 100] — higher is worse. */
  risk_score: number;
  findings: Finding[];
  /** True for scans inserted by the seed script (shown with Demo badge). */
  is_example: boolean;
}

// ---------------------------------------------------------------------------
// WebSocket messages
// ---------------------------------------------------------------------------

export type WSMessageType = 'status' | 'progress' | 'finding' | 'log' | 'error';

export interface WSStatusData   { status: ScanStatus }
export interface WSProgressData { pct: number; phase: string }
export interface WSFindingData  extends Finding {}
export interface WSLogData      { message: string }
export interface WSErrorData    { message: string }

export interface WSMessage {
  type: WSMessageType;
  data: WSStatusData | WSProgressData | WSFindingData | WSLogData | WSErrorData;
}
