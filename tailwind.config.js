/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./app.js",
    "./**/*.{html,js}"
  ],
  theme: {
    extend: {
      colors: {
        accent: {
          50: 'rgb(239, 246, 255)',
          100: 'rgb(219, 234, 254)',
          300: 'rgb(147, 197, 253)',
          400: 'rgb(96, 165, 250)',
          500: 'rgb(59, 130, 246)',
          600: 'rgb(37, 99, 235)',
          700: 'rgb(29, 78, 216)',
        }
      },
      animation: {
        'logo': 'logoSlideIn 0.2s ease-out forwards',
      },
      keyframes: {
        logoSlideIn: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' }
        }
      }
    },
  },
  plugins: [],
}

