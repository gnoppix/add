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

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('addAPI', {
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

  // Security - Change GPG key passphrase
  passwd: (current, newPass) => ipcRenderer.invoke('add-passwd', current, newPass),

  // Vault unlock (TPM PIN or passphrase)
  unlock: (opts) => ipcRenderer.invoke('add-unlock', opts),

  // Self-destruct: wipe all identity data (messages, keys, vault)
  selfDestruct: (homeDir) => ipcRenderer.invoke('add-self-destruct', homeDir),

  // Subscribe to main-process push events (e.g. live P2P inbound messages
  // from the background listener). Returns an unsubscribe function.
  on: (channel, callback) => {
    const listener = (_event, ...args) => callback(...args)
    ipcRenderer.on(channel, listener)
    return () => ipcRenderer.removeListener(channel, listener)
  },
})