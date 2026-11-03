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
        sentinel: {
          bg: '#0a0f1d',
          card: '#0f172a',
          surface: '#1e293b',
          border: '#334155',
          accent: '#06b6d4',
          'accent-hover': '#0891b2',
          cyan: '#22d3ee',
          safe: '#10b981',
          suspicious: '#f59e0b',
          malicious: '#ef4444',
          muted: '#94a3b8'
        }
      }
    },
  },
  plugins: [],
}

