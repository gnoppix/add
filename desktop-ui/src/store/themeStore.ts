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

import { create } from 'zustand'
import { persist } from 'zustand/middleware'

type Theme = 'light' | 'dark' | 'system'

interface ThemeColors {
  primary: string
  secondary: string
  background: string
  sidebar: string
  bubbleSent: string
  bubbleReceived: string
  text: string
  textSecondary: string
}

interface ThemeState {
  theme: Theme
  systemPrefersDark: boolean
  customColors?: Partial<ThemeColors>
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
  setSystemPrefersDark: (value: boolean) => void
  setCustomColors: (colors: Partial<ThemeColors>) => void
  resetCustomColors: () => void
}

const lightColors: ThemeColors = {
  primary: '#007AFF',
  secondary: '#8E8E93',
  background: '#F2F2F7',
  sidebar: '#FFFFFF',
  bubbleSent: '#007AFF',
  bubbleReceived: '#E9E9EB',
  text: '#000000',
  textSecondary: '#6D6D70',
}

const darkColors: ThemeColors = {
  primary: '#0A84FF',
  secondary: '#8E8E93',
  background: '#121212',
  sidebar: '#1E1E1E',
  bubbleSent: '#0A84FF',
  bubbleReceived: '#2C2C2E',
  text: '#FFFFFF',
  textSecondary: '#AEAEB2',
}

function applyCustomProperties(colors: ThemeColors) {
  const root = document.documentElement.style
  Object.entries(colors).forEach(([key, value]) => {
    root.setProperty(`--color-${key}`, value)
  })
}

function getActiveColors(theme: Theme, systemPrefersDark: boolean, customColors?: Partial<ThemeColors>): ThemeColors {
  const isDark = theme === 'dark' || (theme === 'system' && systemPrefersDark)
  const baseColors = isDark ? darkColors : lightColors
  return { ...baseColors, ...customColors }
}

function applyTheme(theme: Theme, systemPrefersDark: boolean, customColors?: Partial<ThemeColors>) {
  const isDark = theme === 'dark' || (theme === 'system' && systemPrefersDark)
  
  if (isDark) {
    document.documentElement.classList.add('dark')
    document.documentElement.setAttribute('data-theme', 'dark')
  } else {
    document.documentElement.classList.remove('dark')
    document.documentElement.setAttribute('data-theme', 'light')
  }
  
  const activeColors = getActiveColors(theme, systemPrefersDark, customColors)
  applyCustomProperties(activeColors)
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => ({
      theme: 'system',
      systemPrefersDark: false,
      customColors: undefined,
      setTheme: (theme: Theme) => {
        set({ theme })
        applyTheme(theme, get().systemPrefersDark, get().customColors)
      },
      toggleTheme: () => {
        const current = get().theme
        const next: Theme = current === 'system' ? 'light' : current === 'light' ? 'dark' : 'system'
        get().setTheme(next)
      },
      setSystemPrefersDark: (value: boolean) => {
        set({ systemPrefersDark: value })
        if (get().theme === 'system') {
          applyTheme('system', value, get().customColors)
        }
      },
      setCustomColors: (colors: Partial<ThemeColors>) => {
        set({ customColors: colors })
        applyTheme(get().theme, get().systemPrefersDark, colors)
      },
      resetCustomColors: () => {
        set({ customColors: undefined })
        applyTheme(get().theme, get().systemPrefersDark)
      },
    }),
    {
      name: 'theme-storage',
      partialize: (state) => ({
        theme: state.theme,
        customColors: state.customColors,
      }),
    }
  )
)

// Initialize system preference detection and apply saved theme
if (typeof window !== 'undefined') {
  const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
  const store = useThemeStore.getState()
  store.setSystemPrefersDark(mediaQuery.matches)
  applyTheme(store.theme, store.systemPrefersDark, store.customColors)
  mediaQuery.addEventListener('change', (e) => {
    store.setSystemPrefersDark(e.matches)
  })
}