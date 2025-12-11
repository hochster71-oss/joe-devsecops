/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}'
  ],
  theme: {
    extend: {
      colors: {
        // Dark Wolf Solutions Brand Colors
        'dws': {
          'dark': '#1E1E1E',
          'darker': '#141414',
          'card': '#343434',
          'elevated': '#3A3A3A',
          'border': '#4A4A4A',
          'green': '#87C549',
          'green-dark': '#6BA33A'
        },
        // J.O.E. Blue Accent
        'joe': {
          'blue': '#00A8E8',
          'blue-light': '#33BFFF',
          'blue-dark': '#0088C2',
          'blue-glow': 'rgba(0, 168, 232, 0.3)'
        },
        // Alert Colors
        'alert': {
          'critical': '#FF3366',
          'critical-dark': '#CC2952',
          'high': '#FF6B35',
          'warning': '#FFB000',
          'success': '#87C549',
          'info': '#00A8E8'
        },
        // Severity Colors
        'severity': {
          'critical': '#FF3366',
          'high': '#FF6B35',
          'medium': '#FFB000',
          'low': '#87C549',
          'info': '#6B7280'
        }
      },
      fontFamily: {
        'heading': ['Josefin Sans', 'sans-serif'],
        'body': ['Nunito Sans', 'sans-serif'],
        'mono': ['JetBrains Mono', 'Consolas', 'monospace']
      },
      boxShadow: {
        'glow-blue': '0 0 20px rgba(0, 168, 232, 0.4)',
        'glow-green': '0 0 20px rgba(135, 197, 73, 0.4)',
        'glow-critical': '0 0 20px rgba(255, 51, 102, 0.4)',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.37)'
      },
      backgroundImage: {
        'glass-gradient': 'linear-gradient(135deg, rgba(52, 52, 52, 0.4), rgba(52, 52, 52, 0.1))',
        'dark-gradient': 'linear-gradient(180deg, #1E1E1E 0%, #141414 100%)',
        'blue-gradient': 'linear-gradient(135deg, #00A8E8 0%, #0088C2 100%)',
        'green-gradient': 'linear-gradient(135deg, #87C549 0%, #6BA33A 100%)'
      },
      backdropBlur: {
        'glass': '10px'
      },
      animation: {
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'slide-in': 'slide-in 0.3s ease-out',
        'fade-in': 'fade-in 0.3s ease-out',
        'spin-slow': 'spin 3s linear infinite'
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(0, 168, 232, 0.4)' },
          '50%': { boxShadow: '0 0 40px rgba(0, 168, 232, 0.6)' }
        },
        'slide-in': {
          '0%': { transform: 'translateX(-100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' }
        },
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' }
        }
      }
    }
  },
  plugins: []
};
