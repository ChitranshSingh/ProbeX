/**
 * ProbeX – WebSocket hook for real-time scan progress.
 *
 * useScanSocket(scanId) opens ws(s)://host/ws/scans/{scanId}, parses every
 * WSMessage frame from the server, and exposes a stable reactive state object.
 *
 * Reconnect strategy
 * ------------------
 * On an unexpected close the hook retries with exponential back-off:
 *   attempt 1 → 500 ms
 *   attempt 2 → 1 000 ms
 *   attempt 3 → 2 000 ms
 *   attempt 4 → 4 000 ms
 *   attempt 5+ → 8 000 ms (cap)
 *
 * Reconnects stop once the scan reaches a terminal status
 * (done / failed / blocked) or the component unmounts.
 *
 * WS URL derivation
 * -----------------
 * Derives from VITE_API_URL (default http://localhost:8000) by swapping
 * http → ws and https → wss.
 */

import { useCallback, useEffect, useReducer, useRef } from 'react';
import type {
  Finding,
  ScanStatus,
  WSMessage,
  WSFindingData,
  WSProgressData,
  WSStatusData,
} from '../types';

// ---------------------------------------------------------------------------
// URL helper
// ---------------------------------------------------------------------------

function wsUrl(scanId: string): string {
  const apiUrl: string =
    (import.meta.env.VITE_API_URL as string | undefined) ?? 'http://localhost:8000';
  const base = apiUrl.replace(/^http/, 'ws');
  return `${base}/ws/scans/${scanId}`;
}

// ---------------------------------------------------------------------------
// State shape
// ---------------------------------------------------------------------------

export interface ScanSocketState {
  /** Latest scan lifecycle status received from the server. */
  status: ScanStatus;
  /** Fuzzing/crawl progress 0–100. */
  progress: number;
  /** Phase label from the most recent progress frame. */
  phase: string;
  /** Ordered list of findings received so far. */
  findings: Finding[];
  /** Ordered log lines (most recent last). */
  logs: string[];
  /** Whether the WebSocket is currently connected. */
  connected: boolean;
  /** Number of reconnect attempts since last stable connect. */
  reconnectAttempt: number;
}

const TERMINAL: ReadonlySet<ScanStatus> = new Set(['done', 'failed', 'blocked']);

const initialState: ScanSocketState = {
  status: 'queued',
  progress: 0,
  phase: 'queued',
  findings: [],
  logs: [],
  connected: false,
  reconnectAttempt: 0,
};

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

type Action =
  | { type: 'CONNECTED' }
  | { type: 'DISCONNECTED' }
  | { type: 'STATUS';   payload: WSStatusData }
  | { type: 'PROGRESS'; payload: WSProgressData }
  | { type: 'FINDING';  payload: WSFindingData }
  | { type: 'LOG';      payload: string }
  | { type: 'RECONNECT_ATTEMPT' }
  | { type: 'RESET' };

function reducer(state: ScanSocketState, action: Action): ScanSocketState {
  switch (action.type) {
    case 'CONNECTED':
      return { ...state, connected: true, reconnectAttempt: 0 };
    case 'DISCONNECTED':
      return { ...state, connected: false };
    case 'STATUS':
      return { ...state, status: action.payload.status };
    case 'PROGRESS':
      return { ...state, progress: action.payload.pct, phase: action.payload.phase };
    case 'FINDING':
      // Deduplicate by id in case the server replays events on reconnect.
      if (state.findings.some(f => f.id === action.payload.id)) return state;
      return { ...state, findings: [...state.findings, action.payload as Finding] };
    case 'LOG':
      return { ...state, logs: [...state.logs, action.payload] };
    case 'RECONNECT_ATTEMPT':
      return { ...state, reconnectAttempt: state.reconnectAttempt + 1 };
    case 'RESET':
      return initialState;
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Opens a WebSocket to /ws/scans/{scanId} and streams live events.
 *
 * @param scanId - The scan UUID to subscribe to.
 * @returns Reactive state object with status, findings, logs, and progress.
 */
export function useScanSocket(scanId: string): ScanSocketState {
  const [state, dispatch] = useReducer(reducer, initialState);

  // Keep a ref to the latest status so the reconnect callback can read it
  // without capturing a stale closure over `state`.
  const statusRef = useRef<ScanStatus>('queued');
  statusRef.current = state.status;

  const connect = useCallback(() => {
    if (TERMINAL.has(statusRef.current)) return;

    const url = wsUrl(scanId);
    const ws = new WebSocket(url);

    ws.addEventListener('open', () => {
      dispatch({ type: 'CONNECTED' });
    });

    ws.addEventListener('message', (event: MessageEvent<string>) => {
      let msg: WSMessage;
      try {
        msg = JSON.parse(event.data) as WSMessage;
      } catch {
        return; // ignore unparseable frames
      }

      switch (msg.type) {
        case 'status':
          dispatch({ type: 'STATUS', payload: msg.data as WSStatusData });
          break;
        case 'progress':
          dispatch({ type: 'PROGRESS', payload: msg.data as WSProgressData });
          break;
        case 'finding':
          dispatch({ type: 'FINDING', payload: msg.data as WSFindingData });
          break;
        case 'log':
        case 'error':
          dispatch({ type: 'LOG', payload: (msg.data as { message: string }).message });
          break;
      }
    });

    ws.addEventListener('close', () => {
      dispatch({ type: 'DISCONNECTED' });
    });

    ws.addEventListener('error', () => {
      ws.close();
    });

    return ws;
  }, [scanId]);

  // Manage connection lifecycle + exponential-backoff reconnect.
  useEffect(() => {
    let ws: WebSocket | undefined;
    let retryTimer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let unmounted = false;

    function open() {
      if (unmounted) return;
      ws = connect();

      if (!ws) return; // terminal — don't connect

      ws.addEventListener('close', () => {
        if (unmounted) return;
        if (TERMINAL.has(statusRef.current)) return; // scan is done

        // Exponential back-off: 500 ms, 1s, 2s, 4s, 8s (cap)
        attempt += 1;
        dispatch({ type: 'RECONNECT_ATTEMPT' });
        const delay = Math.min(500 * Math.pow(2, attempt - 1), 8000);
        retryTimer = setTimeout(open, delay);
      });
    }

    open();

    return () => {
      unmounted = true;
      clearTimeout(retryTimer);
      ws?.close();
    };
  }, [connect]);

  return state;
}
