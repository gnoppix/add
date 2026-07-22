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

// Type definitions for Electron API (window.addAPI)
declare global {
  interface Window {
    addAPI?: {
      // App info
      isPackaged: boolean
      resourcesPath: string
      getVersion: () => Promise<string>
      // Read a bundled asset (e.g. a sticker image) as a base64 data URL.
      // relPath is relative to the app's dist/ dir (e.g. "emoji/gif/AgAD.webp").
      readAsset?: (relPath: string) => string | null
      // Identity
      init: (opts?: { pin?: string; password?: string }) => Promise<{ id: string; fingerprint: string }>
      publishCert: () => Promise<unknown>
      getMyId: () => Promise<{ id: string; fingerprint: string }>
      register: () => Promise<unknown>
      registerAllBootstraps: () => Promise<unknown>
      checkRegister: () => Promise<unknown>
      checkContactStatus: () => Promise<Array<{ nullId: string; isOnline: boolean }>>
      // Contacts
      addContact: (nullId: string, fingerprint: string) => Promise<unknown>
      contacts: () => Promise<Array<{ nullId: string; fingerprint: string }>>
      alias: (name: string, nullId: string) => Promise<unknown>
      aliases: () => Promise<Array<{ alias: string; nullId: string }>>
      // Messaging
      send: (nullId: string, message: string, ttl?: string) => Promise<unknown>
      read: (json: boolean) => Promise<unknown>
      delete: (id: string) => Promise<unknown>
      // Verification
      verify: (nullId: string) => Promise<unknown>
      safetyNumber: (nullId: string) => Promise<unknown>
      status: () => Promise<unknown>
      // P2P Listen
      listen: () => Promise<unknown>
      startListen: () => Promise<unknown>
      stopListen: () => Promise<unknown>
      restartListen: () => Promise<unknown>
      listenStatus: () => Promise<{ running: boolean; pid: number | null }>
      // Passphrase management (stored in memory, never persisted to disk)
      setPassphrase: (passphrase: string) => Promise<{ success: boolean }>
      clearPassphrase: () => Promise<{ success: boolean }>
      // Security
      passwd: (current: string, newPass: string) => Promise<unknown>
      unlock: (opts?: { pin?: string; password?: string }) => Promise<unknown>
      selfDestruct: (homeDir: string) => Promise<unknown>
      // About
      openExternal: (url: string) => Promise<unknown>
      // Subscribe to main-process push events
      on: (channel: string, callback: (...args: unknown[]) => void) => () => void
    }
  }
}

export {}
