/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        mongo: {
          bg: "#F9FBF9",
          header: "#001E2B",
          dark: "#001E2B",
          forest: "#00684A",
          green: "#00ED64",
          leaf: "#13AA52",
          lightGreen: "#E6F4EA",
          border: "#E1E8E5",
          card: "#FFFFFF",
          text: "#1C2D27",
          muted: "#5C6C64",
        },
        cyber: {
          bg: "#F9FBF9",
          card: "#FFFFFF",
          panel: "#F0F4F2",
          border: "#E1E8E5",
          accent: "#00ED64",
          accentGlow: "rgba(0, 237, 100, 0.15)",
          matrix: "#13AA52",
          text: "#1C2D27",
          muted: "#5C6C64",
          severity: {
            low: "#10B981",
            medium: "#D97706",
            high: "#E11D48",
            critical: "#DC2626"
          }
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Space Mono"', 'ui-monospace', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        'grid-pattern': "linear-gradient(to right, rgba(0, 104, 74, 0.05) 1px, transparent 1px), linear-gradient(to bottom, rgba(0, 104, 74, 0.05) 1px, transparent 1px)",
      }
    },
  },
  plugins: [],
}
