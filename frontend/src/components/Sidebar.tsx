import { NavLink, useLocation } from 'react-router-dom';
import { Shield, Plus, History, ExternalLink, Zap, Sun, Moon } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export default function Sidebar() {
  const loc = useLocation();
  const { theme, toggleTheme } = useTheme();

  const at = (path: string) =>
    path === '/' ? loc.pathname === '/' : loc.pathname.startsWith(path);

  return (
    <aside className="app-sidebar">
      {/* Logo */}
      <div className="px-4 py-4" style={{ borderBottom: '1px solid var(--sidebar-border)' }}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
              style={{
                background: 'var(--accent)',
                boxShadow: '0 2px 8px rgba(0, 0, 0, 0.2)',
              }}
            >
              <Shield size={16} strokeWidth={2.5} style={{ color: '#ffffff' }} />
            </div>
            <div>
              <p className="text-sm font-bold tracking-tight" style={{ color: 'var(--sidebar-text-primary)', lineHeight: 1.1 }}>
                ProbeX
              </p>
              <p className="text-[10px] mt-0.5 font-bold tracking-wider uppercase" style={{ color: 'var(--sidebar-text-muted)', lineHeight: 1 }}>
                DAST Scanner
              </p>
            </div>
          </div>

          {/* Theme Toggle Button */}
          <button
            type="button"
            onClick={toggleTheme}
            className="p-1.5 rounded-lg transition-colors border"
            style={{
              background: 'rgba(255, 255, 255, 0.1)',
              borderColor: 'var(--sidebar-border)',
              color: 'var(--sidebar-text-primary)',
            }}
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} mode`}
          >
            {theme === 'dark' ? <Sun size={15} className="text-amber-400" /> : <Moon size={15} className="text-emerald-200" />}
          </button>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2.5 py-4 space-y-1">
        <p className="label-xs px-2 mb-2" style={{ color: 'var(--sidebar-text-faint)' }}>Navigation</p>

        <NavLink
          to="/"
          end
          className={`sidebar-nav-link ${at('/') ? 'active' : ''}`}
        >
          <Plus size={15} />
          New Scan
        </NavLink>

        <NavLink
          to="/history"
          className={`sidebar-nav-link ${at('/history') ? 'active' : ''}`}
        >
          <History size={15} />
          Scan History
        </NavLink>
      </nav>

      {/* Footer Section */}
      <div className="px-3 py-3" style={{ borderTop: '1px solid var(--sidebar-border)' }}>
        <a
          href="http://localhost:8000/docs"
          target="_blank"
          rel="noopener noreferrer"
          className="sidebar-nav-link"
          style={{ fontSize: '0.75rem' }}
        >
          <ExternalLink size={13} />
          API Reference
        </a>

        {/* Live Backend Indicator */}
        <div
          className="flex items-center gap-2 px-2.5 mt-3 py-2 rounded-lg"
          style={{ background: 'rgba(255, 255, 255, 0.1)', border: '1px solid var(--sidebar-border)' }}
        >
          <span
            className="inline-block w-2 h-2 rounded-full pulse-dot"
            style={{ background: '#10b981' }}
          />
          <span className="text-[11px] font-semibold" style={{ color: 'var(--sidebar-text-primary)' }}>
            Backend Online
          </span>
          <Zap size={11} style={{ color: 'var(--sidebar-text-muted)', marginLeft: 'auto' }} />
        </div>
      </div>
    </aside>
  );
}
