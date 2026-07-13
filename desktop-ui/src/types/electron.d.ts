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

// Type definitions for Electron API (window.addAPI)
declare global {
  interface Window {
    addAPI: {
      // Identity
      init: () => Promise<{ id: string; fingerprint: string }>
      getMyId: () => Promise<{ id: string; fingerprint: string }>
      register: () => Promise<void>
      registerAllBootstraps: () => Promise<void>
      checkRegister: () => Promise<void>
      status: () => Promise<string>
      checkContactStatus: () => Promise<Array<{ nullId: string; isOnline: boolean }>>

      // Contacts
      addContact: (nullId: string, fingerprint: string) => Promise<void>
      contacts: () => Promise<Array<{ nullId: string; fingerprint: string; alias?: string }>>
      alias: (name: string, nullId: string) => Promise<void>
      aliases: () => Promise<Array<{ alias: string; nullId: string }>>

      // Messaging
      send: (nullId: string, message: string, ttl?: string) => Promise<void>
      read: (json?: boolean) => Promise<Array<{ from: string; text: string }> | string>
      delete: (id: number) => Promise<string>

      // Verification (G6)
      verify: (nullId: string) => Promise<string>
      safetyNumber: (nullId: string) => Promise<string>

      // P2P Listen (background process)
      listen: () => Promise<string>
      startListen: () => Promise<{ success: boolean; message: string }>
      stopListen: () => Promise<{ success: boolean; message: string }>
      restartListen: () => Promise<{ success: boolean; message: string }>
      listenStatus: () => Promise<{ running: boolean; pid: number | null }>

      // Security - Change GPG key passphrase
      passwd: () => Promise<string>
    }
  }
}

export {}