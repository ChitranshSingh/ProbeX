/**
 * ProbeX – typed API client
 *
 * Base URL resolves in priority order:
 *   1. VITE_API_URL environment variable (set in .env or CI)
 *   2. Hardcoded fallback http://localhost:8000
 *
 * All public functions throw on non-2xx responses so callers can use
 * try/catch or React error boundaries.
 */

import type {
  Finding,
  ScanCreatedResponse,
  ScanRequest,
  ScanSummary,
} from '../types';

const BASE_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:8000';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function _fetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      /* ignore JSON parse errors on error bodies */
    }
    throw new Error(detail);
  }

  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Scan endpoints
// ---------------------------------------------------------------------------

/**
 * POST /api/scans
 *
 * Starts a new DAST scan. The caller must set consent_confirmed=true or the
 * backend returns HTTP 400 ("You must confirm you have permission to scan
 * this target.").
 *
 * @throws Error with the server's `detail` message on 400/422/5xx.
 */
export async function createScan(req: ScanRequest): Promise<ScanCreatedResponse> {
  return _fetch<ScanCreatedResponse>('/api/scans', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

/**
 * GET /api/scans
 *
 * Returns all scans (newest first), including seeded example scans
 * identified by is_example=true.
 */
export async function listScans(): Promise<ScanSummary[]> {
  return _fetch<ScanSummary[]>('/api/scans');
}

/**
 * GET /api/scans/:id
 *
 * Returns the full ScanSummary with all Finding objects.
 *
 * @throws Error with detail "Scan '...' not found." on 404.
 */
export async function getScan(id: string): Promise<ScanSummary> {
  return _fetch<ScanSummary>(`/api/scans/${id}`);
}

/**
 * GET /api/scans/:id/report?format=json|html
 *
 * Downloads the scan report in the requested format. Returns the raw
 * Response so the caller can stream/blob it.
 */
export async function downloadReport(
  id: string,
  format: 'json' | 'html' = 'json',
): Promise<Response> {
  const res = await fetch(`${BASE_URL}/api/scans/${id}/report?format=${format}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res;
}

// ---------------------------------------------------------------------------
// Re-export Finding for consumers that only import from api/client
// ---------------------------------------------------------------------------
export type { Finding, ScanSummary, ScanRequest };
