/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        'bg-deep':   '#0a0e1a',
        'bg-card':   '#111827',
        'bg-hover':  '#1e293b',
        border:      '#1e3a5f',
        accent:      '#00d4ff',
        'accent-2':  '#00f5c4',
        success:     '#10b981',
        warning:     '#f59e0b',
        danger:      '#ef4444',
        critical:    '#dc2626',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        glow:  '0 0 32px rgba(0, 212, 255, 0.12)',
        card:  '0 4px 24px rgba(0, 0, 0, 0.4)',
        inner: 'inset 0 1px 0 rgba(255,255,255,0.04)',
      },
    },
  },
  plugins: [],
};
