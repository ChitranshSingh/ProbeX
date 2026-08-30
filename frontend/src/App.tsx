import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider } from './context/ThemeContext';
import Sidebar     from './components/Sidebar';
import NewScan     from './pages/NewScan';
import ScanDetail  from './pages/ScanDetail';
import ScanHistory from './pages/ScanHistory';

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <div className="app-shell">
          <Sidebar />
          <div className="app-main">
            <Routes>
              <Route path="/"           element={<NewScan />} />
              <Route path="/scans/:id"  element={<ScanDetail />} />
              <Route path="/history"    element={<ScanHistory />} />
              <Route path="*"           element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </div>
      </BrowserRouter>
    </ThemeProvider>
  );
}
