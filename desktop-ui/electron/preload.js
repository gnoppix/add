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
  init: () => ipcRenderer.invoke('add-init'),
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
  read: () => ipcRenderer.invoke('add-read'),
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
})