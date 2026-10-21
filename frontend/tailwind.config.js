/** @type {import('tailwindcss').Config} */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        page: v("page"),
        panel: v("panel"),
        raised: v("raised"),
        line: v("line"),
        ink: v("ink"),
        ink2: v("ink2"),
        muted: v("muted"),
        accent: v("accent"),
        good: v("good"),
        warn: v("warn"),
        serious: v("serious"),
        crit: v("crit"),
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', '"Segoe UI"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
};
