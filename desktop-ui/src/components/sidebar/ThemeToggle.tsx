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

import { useThemeStore } from '../../store/themeStore'

export default function ThemeToggle() {
  const { theme, toggleTheme } = useThemeStore()

  // Determine effective theme and next action
  const effectiveTheme = theme === 'system' ? (useThemeStore.getState().systemPrefersDark ? 'dark' : 'light') : theme
  const isDark = effectiveTheme === 'dark'

  const getLabel = () => {
    if (theme === 'system') {
      return `Using ${isDark ? 'dark' : 'light'} mode (system). Click for ${isDark ? 'light' : 'dark'}.`
    }
    return `Switch to ${isDark ? 'light' : 'dark'} mode`
  }

  return (
    <button
      onClick={toggleTheme}
      className="flex h-8 w-8 items-center justify-center rounded-full text-gray-600 transition-colors hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-700"
      aria-label={getLabel()}
    >
      {isDark ? (
        // Moon icon (currently dark, click for light)
        <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
      ) : (
        // Sun icon (currently light, click for dark)
        <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m8.66-11.66l-.71.71M5.04 19.96l-.71-.71M21 12h-1M4 12H3m16.66 11.66l-.71-.71M5.75 5.75l-.71.71M12 7a5 5 0 100 10 5 5 0 000-10z" />
        </svg>
      )}
    </button>
  )
}