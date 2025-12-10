module.exports = {
  content: ["./templates/**/*.html", "./static/js/**/*.js"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "sans-serif"],
        display: ["IM Fell English SC", "serif"],
      },
      colors: {
        slate: {
          950: "#020617",
        },
      },
      boxShadow: {
        "indigo-veil": "0 35px 60px -20px rgba(31, 41, 96, 0.3)",
      },
    },
  },
  plugins: [],
};
