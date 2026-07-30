/**
 * Version Check Integration for Electron Main Process
 * Integrates the add-version-check-agent into the Electron app
 */

const { checkVersion } = require('./version-check.js');
const { Notification } = require('electron');

/**
 * Initialize version check at app startup (non-blocking)
 * Call this in app.whenReady() after window creation
 *
 * @param {BrowserWindow} mainWindow - The main Electron window
 * @param {Object} options - Optional configuration
 * @param {number} options.initialDelay - Delay before first check (ms, default: 5000)
 * @param {number} options.interval - Periodic check interval (ms, default: 12 hours)
 * @param {boolean} options.showNotification - Show system notification on update (default: true)
 */
function initializeVersionCheck(mainWindow, options = {}) {
  const {
    initialDelay = 5000,
    interval = 12 * 60 * 60 * 1000, // 12 hours
    showNotification = true
  } = options;

  // Initial check
  setTimeout(async () => {
    await runVersionCheck(mainWindow, showNotification);
  }, initialDelay);

  // Periodic checks
  if (interval > 0) {
    setInterval(async () => {
      await runVersionCheck(mainWindow, showNotification);
    }, interval);
  }
}

/**
 * Run a single version check and notify if update available
 */
async function runVersionCheck(mainWindow, showNotification = true) {
  try {
    const result = await checkVersion();
    console.log('[Version Check] Result:', result);

    if (result.status === 'UPDATE_AVAILABLE' && mainWindow && !mainWindow.isDestroyed()) {
      // Notify renderer process
      mainWindow.webContents.send('add-update-available', result);

      // Show system notification
      if (showNotification && Notification.isSupported()) {
        new Notification({
          title: 'Add Messenger Update Available',
          body: `Version ${result.latest_version} is available. You have ${result.local_version}.`,
          silent: false
        }).show();
      }
    }
  } catch (err) {
    // Fail silently - never block app
    console.warn('[Version Check] Failed:', err.message);
  }
}

/**
 * Manual version check (exposed via IPC)
 * Call from renderer: const result = await window.addAPI.checkVersion()
 */
function setupVersionCheckIPC() {
  const { ipcMain } = require('electron');

  ipcMain.handle('add-check-version', async () => {
    try {
      return await checkVersion();
    } catch (err) {
      return {
        status: 'UNKNOWN',
        local_version: 'UNAVAILABLE',
        latest_version: 'UNKNOWN',
        release_url: 'https://github.com/gnoppix/add/releases',
        checked_at: new Date().toISOString()
      };
    }
  });
}

module.exports = {
  initializeVersionCheck,
  runVersionCheck,
  setupVersionCheckIPC
};