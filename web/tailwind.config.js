/** MamorAI theme: `teal` is remapped to the brand 藍 (ai-iro) scale and `slate` to the night-navy scale,
 *  so existing utility classes across all pages pick up the new palette without per-page edits. */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        teal: { 50: "#EEF1FF", 100: "#DCE2FF", 200: "#B9C6FF", 300: "#8EA2FF", 400: "#6B83FA", 500: "#3A56F0", 600: "#2E46CC", 700: "#2538A3", 800: "#1B2A6B", 900: "#141F4F", 950: "#0D1433" },
        slate: { 50: "#F4F6FB", 100: "#E6EAF2", 200: "#D6DDF0", 300: "#B4BED3", 400: "#9AA6BF", 500: "#7F8BA6", 600: "#2A3756", 700: "#1E2942", 800: "#111A2E", 900: "#0E1526", 950: "#0A0F1C" },
        brand: { deep: "#1B2A6B", DEFAULT: "#3A56F0", light: "#8EA2FF", night: "#0A0F1C" },
      },
      fontFamily: {
        sans: ['"IBM Plex Sans JP"', "system-ui", "-apple-system", '"Segoe UI"', "sans-serif"],
        display: ["Sora", '"IBM Plex Sans JP"', "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
