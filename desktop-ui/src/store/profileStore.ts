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

interface ProfileState {
  avatarUrl?: string
  setAvatar: (url: string) => void
  removeAvatar: () => void
}

export const useProfileStore = create<ProfileState>()(
  persist(
    (set) => ({
      avatarUrl: undefined,
      setAvatar: (url: string) => {
        set({ avatarUrl: url })
      },
      removeAvatar: () => {
        set({ avatarUrl: undefined })
      },
    }),
    {
      name: 'profile-storage',
    }
  )
)