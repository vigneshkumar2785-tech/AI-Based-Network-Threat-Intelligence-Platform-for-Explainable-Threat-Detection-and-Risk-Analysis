/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0A0E14",
          card: "#0F172A",
          panel: "#1E293B",
          border: "#334155",
          accent: "#00F0FF",
          accentGlow: "rgba(0, 240, 255, 0.15)",
          matrix: "#00FF66",
          text: "#E2E8F0",
          muted: "#94A3B8",
          severity: {
            low: "#00F0FF",
            medium: "#F59E0B",
            high: "#EF4444",
            critical: "#DC2626"
          }
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Space Mono"', 'ui-monospace', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        'grid-pattern': "linear-gradient(to right, rgba(51, 65, 85, 0.15) 1px, transparent 1px), linear-gradient(to bottom, rgba(51, 65, 85, 0.15) 1px, transparent 1px)",
      }
    },
  },
  plugins: [],
}
