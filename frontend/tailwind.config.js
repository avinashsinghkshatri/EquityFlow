/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Brand palette: deep navy to inky black
        brand: {
          50:  "#eef4ff",
          100: "#d9e4ff",
          200: "#b6c7ff",
          300: "#8aa3ff",
          400: "#5e7eff",
          500: "#355bff",
          600: "#1e42e6",
          700: "#162fb4",
          800: "#112482",
          900: "#0c1a59",
          950: "#081237"   // deep navy
        },
        ink: {
          900: "#0a0a0f",  // near-black
          950: "#06060a"
        }
      },
      backgroundImage: {
        "brand-gradient":
          "radial-gradient(1200px 600px at 10% -10%, rgba(53,91,255,0.20) 0%, transparent 60%), radial-gradient(900px 500px at 90% 10%, rgba(12,26,89,0.45) 0%, transparent 70%), linear-gradient(180deg, #0c1a59 0%, #06060a 80%)"
      },
      boxShadow: {
        "soft": "0 6px 24px rgba(0,0,0,0.3)",
        "ring": "0 0 0 1px rgba(255,255,255,0.06) inset, 0 8px 30px rgba(0,0,0,0.35)"
      },
      borderRadius: {
        "2xl": "1.25rem",
        "3xl": "1.5rem"
      },
      backdropBlur: {
        xs: "2px"
      }
    }
  },
  plugins: []
}
