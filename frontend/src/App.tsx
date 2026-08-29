import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import NewScan     from './pages/NewScan';
import ScanDetail  from './pages/ScanDetail';
import ScanHistory from './pages/ScanHistory';

/**
 * ProbeX React application router.
 *
 * Routes:
 *   /             → NewScan      (scan launcher form)
 *   /scans/:id    → ScanDetail   (live WebSocket dashboard + findings explorer)
 *   /history      → ScanHistory  (all past scans including example scan)
 *   *             → redirect to /
 */
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"           element={<NewScan />} />
        <Route path="/scans/:id"  element={<ScanDetail />} />
        <Route path="/history"    element={<ScanHistory />} />
        <Route path="*"           element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
