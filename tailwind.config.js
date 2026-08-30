/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // SOC & Enterprise Palette mapped to semantic CSS tokens
        threat: {
          bg: 'var(--background)',
          card: 'var(--surface)',
          subcard: 'var(--surface-elevated)',
          border: 'var(--border)',
          borderLight: 'var(--border-medium)',
          muted: 'var(--text-muted)',
          secondary: 'var(--text-secondary)',
          text: 'var(--text-primary)',
          accent: 'var(--accent)',
          accentLight: 'var(--accent-light)',
          // Semantic Severity Colors
          critical: 'var(--danger)',
          high: 'var(--warning)',
          medium: 'var(--warning)',
          low: 'var(--success)',
          info: 'var(--info)',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': '0.6875rem', // 11px
        'xs': '0.75rem',    // 12px
        'sm': '0.8125rem',  // 13px
        'base': '0.875rem', // 14px
        'md': '0.9375rem',  // 15px
        'lg': '1rem',       // 16px
        'xl': '1.125rem',   // 18px
      }
    },
  },
  plugins: [],
}
