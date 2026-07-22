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

// Preload runs in a SANDBOXED renderer context in the packaged app, where
// Node built-ins (fs/path) AND `__dirname` are NOT available. Keep this file
// free of `require` except `electron` (contextBridge/ipcRenderer). All file
// I/O is delegated to the main process via IPC (`add-read-asset`).
const { contextBridge, ipcRenderer } = require('electron')

// Resolve the app "resources" directory WITHOUT fs/path/__dirname (none are
// available here). Prefer process.resourcesPath; fall back to deriving it from
// the executable path: <app>/add-desktop -> <app>/resources.
function resourcesDir() {
  if (typeof process !== 'undefined' && process.resourcesPath) return process.resourcesPath
  if (typeof process !== 'undefined' && process.execPath) {
    const parts = process.execPath.split('/')
    parts.pop() // drop the executable name
    return parts.join('/') + '/resources'
  }
  return ''
}
const RESOURCES_PATH = resourcesDir()
const IS_PACKAGED =
  (typeof process !== 'undefined' && !!process.resourcesPath) ||
  (typeof process !== 'undefined' && /add-desktop/.test(process.execPath || ''))

contextBridge.exposeInMainWorld('addAPI', {
  // App info
  isPackaged: IS_PACKAGED,
  resourcesPath: RESOURCES_PATH,
  getVersion: () => ipcRenderer.invoke('add-get-version'),

  // Identity
  init: (opts) => ipcRenderer.invoke('add-init', opts),
  publishCert: () => ipcRenderer.invoke('add-publish-cert'),
  getMyId: () => ipcRenderer.invoke('add-id'),
  register: () => ipcRenderer.invoke('add-register'),
  registerAllBootstraps: () => ipcRenderer.invoke('add-register-all-bootstraps'),
  checkRegister: () => ipcRenderer.invoke('add-check-register'),
  checkContactStatus: () => ipcRenderer.invoke('add-check-contact-status'),

  // Contacts
  addContact: (nullId, fingerprint) =>
    ipcRenderer.invoke('add-add-contact', nullId, fingerprint),
  contacts: () => ipcRenderer.invoke('add-contacts'),
  alias: (name, nullId) => ipcRenderer.invoke('add-alias', name, nullId),
  aliases: () => ipcRenderer.invoke('add-aliases'),

  // Messaging
  send: (nullId, message, ttl) => ipcRenderer.invoke('add-send', nullId, message, ttl),
  read: (json) => ipcRenderer.invoke('add-read', json),
  delete: (id) => ipcRenderer.invoke('add-delete', id),

  // Verification (G6)
  verify: (nullId) => ipcRenderer.invoke('add-verify', nullId),
  safetyNumber: (nullId) => ipcRenderer.invoke('add-safety-number', nullId),
  status: () => ipcRenderer.invoke('add-status'),

  // P2P Listen (background process)
  listen: () => ipcRenderer.invoke('add-listen'),
  startListen: () => ipcRenderer.invoke('add-start-listen'),
  stopListen: () => ipcRenderer.invoke('add-stop-listen'),
  restartListen: () => ipcRenderer.invoke('add-restart-listen'),
  listenStatus: () => ipcRenderer.invoke('add-listen-status'),

  // Passphrase management (stored in memory, never persisted to disk)
  setPassphrase: (passphrase) => ipcRenderer.invoke('add-set-passphrase', passphrase),
  clearPassphrase: () => ipcRenderer.invoke('add-clear-passphrase'),
  submitPassphrase: (passphrase) => ipcRenderer.invoke('add-submit-passphrase', passphrase),

  // Security - Change GPG key passphrase
  passwd: (current, newPass) => ipcRenderer.invoke('add-passwd', current, newPass),

  // Vault unlock (TPM PIN or passphrase)
  unlock: (opts) => ipcRenderer.invoke('add-unlock', opts),

  // Self-destruct: wipe all identity data (messages, keys, vault)
  selfDestruct: (homeDir) => ipcRenderer.invoke('add-self-destruct', homeDir),

  // Read a bundled sticker asset as a base64 data URL. Delegated to the main
  // process (which has fs) so the sandboxed preload stays Node-free.
  readAsset: (relPath) => ipcRenderer.invoke('add-read-asset', relPath),

  // For About window
  openExternal: (url) => ipcRenderer.invoke('add-open-external', url),
  getVersion: () => ipcRenderer.invoke('add-get-version'),

  // Subscribe to main-process push events (e.g. live P2P inbound messages
  // from the background listener). Returns an unsubscribe function.
  on: (channel, callback) => {
    const listener = (_event, ...args) => callback(...args)
    ipcRenderer.on(channel, listener)
    return () => ipcRenderer.removeListener(channel, listener)
  },
})
