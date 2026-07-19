/**
 *-------------------------------------------------------------------------------
 * Name: Gnoppix Linux - Services
 * Architecture: all
 * Date: 2002-2026 by Gnoppix Linux
 * Author: Andreas Mueller
 * Website: https://www.gnoppix.com
 * Licence: Business Source License (BSL / BUSL)
 * You can use the code for free if your company or organisation doesn't have more than 2 people.
 *-------------------------------------------------------------------------------
 */

/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Signal-inspired color palette
        primary: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          200: '#bae6fd',
          300: '#7dd3fc',
          400: '#38bdf8',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
          800: '#075985',
          900: '#0c4a6e',
        },
        // Light theme
        light: {
          background: '#F2F2F7',
          sidebar: '#FFFFFF',
          bubbleSent: '#007AFF',
          bubbleReceived: '#E9E9EB',
          text: '#000000',
          textSecondary: '#3C3C43',
        },
        // Dark theme
        dark: {
          background: '#121212',
          sidebar: '#1E1E1E',
          bubbleSent: '#0A84FF',
          bubbleReceived: '#2C2C2E',
          text: '#FFFFFF',
          textSecondary: '#9D9DA3',
        },
        signal: {
          teal: '#05a3a3',
          blue: '#007AFF',
          gray: '#8E8E93',
          background: '#F2F2F7',
        },
      },
      spacing: {
        sidebar: '30%',
        chat: '70%',
      },
    },
  },
  plugins: [],
}