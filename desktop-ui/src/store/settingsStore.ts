/**
 *-------------------------------------------------------------------------------
 * Name: Gnoppix Linux - Services
 * Architecture: all
 * Date: 2002-2026 by Gnoppix Linux
 * Author: Andreas Mueller
 * Website: https://www.gnoppix.com
 * Licence: Business Source License (BSL / BUSL)
 *-------------------------------------------------------------------------------
 */

import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface SecuritySettings {
  selfDestructEnabled: boolean
  selfDestructThreshold: number // 3-20 attempts
}

interface UISettings {
  autoStartListener: boolean // Auto-start P2P listener on unlock
}

interface SettingsStore {
  security: SecuritySettings
  ui: UISettings
  setSelfDestructEnabled: (enabled: boolean) => void
  setSelfDestructThreshold: (threshold: number) => void
  setAutoStartListener: (enabled: boolean) => void
}

export const useSettingsStore = create<SettingsStore>()(
  persist(
    (set) => ({
      security: {
        selfDestructEnabled: true, // Enabled by default
        selfDestructThreshold: 10,
      },
      ui: {
        autoStartListener: false, // Disabled by default - opt-in
      },
      setSelfDestructEnabled: (enabled) =>
        set((state) => ({
          security: { ...state.security, selfDestructEnabled: enabled },
        })),
      setSelfDestructThreshold: (threshold) =>
        set((state) => ({
          security: { ...state.security, selfDestructThreshold: threshold },
        })),
      setAutoStartListener: (enabled) =>
        set((state) => ({
          ui: { ...state.ui, autoStartListener: enabled },
        })),
    }),
    {
      name: 'add-settings', // localStorage key
    }
  )
)