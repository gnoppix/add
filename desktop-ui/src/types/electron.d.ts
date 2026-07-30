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
      init: (opts?: {
        pin?: string
        password?: string
      }) => Promise<{ id: string; fingerprint: string }>
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
      // Verification (G6)
      verify: (nullId: string) => Promise<unknown>
      safetyNumber: (nullId: string) => Promise<unknown>
      status: () => Promise<unknown>
      // P2P Listen (background process)
      listen: () => Promise<unknown>
      startListen: () => Promise<unknown>
      stopListen: () => Promise<unknown>
      restartListen: () => Promise<unknown>
      listenStatus: () => Promise<{ running: boolean; pid: number | null }>
      // Passphrase management (stored in memory, never persisted to disk)
      setPassphrase: (passphrase: string) => Promise<{ success: boolean }>
      clearPassphrase: () => Promise<{ success: boolean }>
      submitPassphrase: (passphrase: string) => Promise<{ success: boolean; error?: string }>
      // Security - Change GPG key passphrase
      passwd: (current: string, newPass: string) => Promise<unknown>
      unlock: (opts?: { pin?: string; password?: string }) => Promise<unknown>
      selfDestruct: (homeDir: string) => Promise<unknown>
      // Backup/Restore
      backup: () => Promise<{
        success: boolean
        backupName?: string
        backupPath?: string
        size?: number
        timestamp?: string
        error?: string
      }>
      listBackups: () => Promise<{
        success: boolean
        backups: Array<{ name: string; path: string; size: number; mtime: string }>
        error?: string
      }>
      restore: (
        backupName: string
      ) => Promise<{ success: boolean; message?: string; error?: string }>
      deleteBackup: (
        backupName: string
      ) => Promise<{ success: boolean; message?: string; error?: string }>
      // For About window
      openExternal: (url: string) => Promise<unknown>
      getVersion: () => Promise<unknown>

      // Version Check
      checkVersion: () => Promise<{
        status: string
        local_version: string
        latest_version: string
        release_url: string
        checked_at: string
      }>

      // Subscribe to main-process push events (e.g. live P2P inbound messages
      // from the background listener). Returns an unsubscribe function.
      on: (channel: string, callback: (...args: unknown[]) => void) => () => void
    }
  }
}

export {}
