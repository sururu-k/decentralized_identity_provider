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
          bg: '#090d16',
          card: '#111827',
          border: '#1f2937',
          accent: '#6366f1',
        }
      }
    },
  },
  plugins: [],
}
