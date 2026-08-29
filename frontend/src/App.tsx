import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import NewScan from './pages/NewScan';
import ScanDetail from './pages/ScanDetail';

/**
 * ProbeX React application router.
 *
 * Routes:
 *   /             → NewScan  (scan launcher form)
 *   /scans/:id    → ScanDetail (live dashboard — stubbed; completed in Task S6)
 *   *             → redirect to /
 */
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"            element={<NewScan />} />
        <Route path="/scans/:id"   element={<ScanDetail />} />
        <Route path="*"            element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
