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
        // SOC Dark Console Palette
        threat: {
          bg: '#0B0F17',         // Deepest background
          card: '#111827',       // Elevated panel / card
          subcard: '#161F30',    // Sub-panel / active row
          border: '#1F2937',     // Base border
          borderLight: '#374151',// Active border
          muted: '#64748B',      // Secondary text
          text: '#E2E8F0',       // Primary text
          white: '#F8FAFC',      // High contrast text
          accent: '#0284C7',     // Tactical Cyan / Blue Accent
          accentLight: '#38BDF8',
          // Semantic Severity Colors
          critical: '#EF4444',   // Red-500
          criticalBg: 'rgba(239, 68, 68, 0.12)',
          high: '#F97316',       // Orange-500
          highBg: 'rgba(249, 115, 22, 0.12)',
          medium: '#F59E0B',     // Amber-500
          mediumBg: 'rgba(245, 158, 11, 0.12)',
          low: '#10B981',        // Emerald-500
          lowBg: 'rgba(16, 185, 129, 0.12)',
          info: '#3B82F6',       // Blue-500
          infoBg: 'rgba(59, 130, 246, 0.12)',
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
