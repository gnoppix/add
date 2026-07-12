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

const { app, BrowserWindow, ipcMain } = require('electron')
const { spawn } = require('child_process')
const path = require('path')
const fs = require('fs')
const os = require('os')

// Resolve add CLI path for dev and packaged modes
function getAddCliPath() {
  // 1. Environment variable override
  if (process.env.ADD_CLI_PATH) {
    return process.env.ADD_CLI_PATH
  }

  // 2. Packaged mode: resources/extra/add
  if (app.isPackaged) {
    const packagedPath = path.join(process.resourcesPath, 'add')
    if (fs.existsSync(packagedPath)) {
      return packagedPath
    }
  }

  // 3. Development mode: relative to project
  const devPath = path.join(__dirname, '../../target/release/add')
  if (fs.existsSync(devPath)) {
    return devPath
  }

  // 4. Fallback to current directory
  return './add'
}

const ADD_CLI = getAddCliPath()

// PID file paths
const PID_DIR = path.join(os.homedir(), '.add')
const LISTEN_PID_FILE = path.join(PID_DIR, 'add_listen.pid')
const APP_PID_FILE = path.join(PID_DIR, 'add.pid')

// Ensure PID directory exists
function ensurePidDir() {
  if (!fs.existsSync(PID_DIR)) {
    fs.mkdirSync(PID_DIR, { recursive: true })
  }
}

// CLI command queue to prevent PID lock conflicts
let cliQueue = Promise.resolve()

// Track the listen process
let listenProcess = null

function runCliCommand(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(ADD_CLI, args, {
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    
    let stdout = ''
    let stderr = ''
    
    child.stdout.on('data', (data) => { stdout += data.toString() })
    child.stderr.on('data', (data) => { stderr += data.toString() })
    
    child.on('close', (code) => {
      if (code === 0) resolve(stdout.trim())
      else reject(new Error(stderr.trim() || `Exit code ${code}`))
    })
    
    child.on('error', (err) => reject(err))
  })
}

// Queue wrapper to serialize CLI calls
function queuedCommand(args) {
  return new Promise((resolve, reject) => {
    cliQueue = cliQueue.then(() => runCliCommand(args)).then(resolve, reject)
  })
}

// Write PID file for listen process
function writeListenPidFile(pid) {
  ensurePidDir()
  fs.writeFileSync(LISTEN_PID_FILE, pid.toString())
}

// Remove PID file for listen process
function removeListenPidFile() {
  if (fs.existsSync(LISTEN_PID_FILE)) {
    fs.unlinkSync(LISTEN_PID_FILE)
  }
}

// Check if a listen process is already running (from PID file)
function checkExistingListenProcess() {
  if (fs.existsSync(LISTEN_PID_FILE)) {
    const pid = parseInt(fs.readFileSync(LISTEN_PID_FILE, 'utf8').trim(), 10)
    if (!isNaN(pid)) {
      try {
        // Check if process exists (signal 0 doesn't kill, just checks)
        process.kill(pid, 0)
        console.log(`Found existing listen process with PID ${pid}`)
        return pid
      } catch (e) {
        // Process doesn't exist, remove stale PID file
        console.log('Stale PID file found, removing...')
        removeListenPidFile()
      }
    }
  }
  return null
}

// Kill existing listen process from PID file
function killExistingListenProcess() {
  const pid = checkExistingListenProcess()
  if (pid) {
    try {
      process.kill(pid, 'SIGTERM')
      console.log(`Killed existing listen process (PID ${pid})`)
      // Give it a moment to terminate
      setTimeout(() => {}, 500)
    } catch (e) {
      console.log(`Could not kill process ${pid}:`, e.message)
    }
  }
  removeListenPidFile()
}

// Start the background listen process
function startListenProcess() {
  // First check and kill any existing listen process from PID file
  killExistingListenProcess()
  
  if (listenProcess) {
    console.log('Listen process already running')
    return
  }
  
  console.log('Starting background add listen process...')
  listenProcess = spawn(ADD_CLI, ['listen'], {
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
  })
  
  // Buffer stdout (data arrives in chunks) and forward inbound P2P messages
  // to the renderer. The client emits one line per received message:
  //   [HH:MM:SS] From: <NULL_ID> (<FP>) | <text>
  let listenBuf = ''
  const INBOUND_RE = /^\[.*?\] From: (NN-[A-Z0-9-]+) \(([A-F0-9]+)\) \| (.*)$/
  const forwardInbound = (line) => {
    const m = line.match(INBOUND_RE)
    if (!m) return
    const [, nullId, fp, text] = m
    const win = mainWindow
    if (win && !win.isDestroyed()) {
      win.webContents.send('add-incoming-message', { from: nullId, fingerprint: fp, text })
    }
  }
  listenProcess.stdout?.on('data', (data) => {
    const chunk = data.toString()
    console.log(`[listen] ${chunk.trim()}`)
    listenBuf += chunk
    let nl
    while ((nl = listenBuf.indexOf('\n')) !== -1) {
      const line = listenBuf.slice(0, nl).trim()
      listenBuf = listenBuf.slice(nl + 1)
      if (line) forwardInbound(line)
    }
  })
  // Flush any trailing line on close
  listenProcess.on('close', (code) => {
    if (listenBuf.trim()) forwardInbound(listenBuf.trim())
    listenBuf = ''
    console.log(`Listen process exited with code ${code}`)
    listenProcess = null
    removeListenPidFile()
  })
  
  listenProcess.stderr?.on('data', (data) => {
    console.error(`[listen] ${data.toString().trim()}`)
  })
  

  listenProcess.on('error', (err) => {
    console.error('Listen process error:', err)
    listenProcess = null
    removeListenPidFile()
  })
  
  // Write PID file after successful spawn
  writeListenPidFile(listenProcess.pid)
  console.log(`Listen process started with PID ${listenProcess.pid}`)
}

// Kill the background listen process
function killListenProcess() {
  if (listenProcess) {
    console.log(`Killing listen process (PID ${listenProcess.pid})...`)
    listenProcess.kill('SIGTERM')
    listenProcess = null
    removeListenPidFile()
  } else {
    // Also try to kill from PID file if we don't have the process reference
    killExistingListenProcess()
  }
}

// Restart the listen process
function restartListenProcess() {
  killListenProcess()
  // Small delay to ensure port is released
  setTimeout(startListenProcess, 500)
}

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: 'Gnoppix - Add Messenger 0.2',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 20, y: 20 },
  })

  const devUrl = process.env.VITE_DEV_SERVER_URL || 'http://localhost:5173'
  const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged

  if (isDev) {
    mainWindow.loadURL(devUrl)
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'))
  }

  // Surface load failures instead of a silent white window.
  mainWindow.webContents.on('did-fail-load', (_e, code, desc) => {
    console.error('Window failed to load:', code, desc)
  })

  return mainWindow
}

// IPC Handlers
ipcMain.handle('add-init', async () => {
  const output = await queuedCommand(['init'])
  const idMatch = output.match(/Null ID:\s*(NN-[A-Za-z0-9-]+)/)
  const fpMatch = output.match(/Fingerprint:\s*([A-Fa-f0-9]+)/)
  return { id: idMatch?.[1] || '', fingerprint: fpMatch?.[1] || '' }
})

ipcMain.handle('add-id', async () => {
  const output = await queuedCommand(['id'])
  const idMatch = output.match(/Null ID:\s*(NN-[A-Za-z0-9-]+)/)
  const fpMatch = output.match(/Fingerprint:\s*([A-Fa-f0-9]+)/)
  return { id: idMatch?.[1] || '', fingerprint: fpMatch?.[1] || '' }
})

ipcMain.handle('add-register', async () => queuedCommand(['register']))
ipcMain.handle('add-register-all-bootstraps', async () => queuedCommand(['register-all-bootstraps']))
ipcMain.handle('add-check-register', async () => queuedCommand(['check-register']))
ipcMain.handle('add-check-contact-status', async () => {
  const output = await queuedCommand(['contact-status'])
  // CLI prints one line per contact:
  //   "  ✓ <fp8> (NN-xxxx-xxxx) - ONLINE at <addr>"
  //   "  ✗ <fp8> (NN-xxxx-xxxx) - OFFLINE"
  // Parse into [{ nullId, isOnline }] for the renderer's status store.
  const statuses = []
  for (const line of output.split('\n')) {
    const m = line.match(/(NN-[A-Za-z0-9-]+)\)\s*-\s*(ONLINE|OFFLINE)/)
    if (m) statuses.push({ nullId: m[1], isOnline: m[2] === 'ONLINE' })
  }
  return statuses
})

ipcMain.handle('add-add-contact', async (_, nullId, fingerprint) =>
  queuedCommand(['add-contact', nullId, fingerprint]))

ipcMain.handle('add-contacts', async () => {
  const output = await queuedCommand(['contacts'])
  const contacts = []
  for (const line of output.split('\n')) {
    // CLI format: "  NN-xxxx-xxxx -> FINGERPRINT"
    const match = line.match(/(NN-[A-Za-z0-9-]+)\s*->\s*([A-Fa-f0-9]+)/)
    if (match) contacts.push({ nullId: match[1], fingerprint: match[2] })
  }
  return contacts
})

ipcMain.handle('add-alias', async (_, name, nullId) =>
  queuedCommand(['alias', name, nullId]))

ipcMain.handle('add-aliases', async () => {
  const output = await queuedCommand(['aliases'])
  const aliases = []
  for (const line of output.split('\n')) {
    // CLI format: "  NAME -> NN-xxxx-xxxx"  (insertion order, oldest first)
    const match = line.match(/\s*(.+?)\s*->\s*(NN-[A-Za-z0-9-]+)/)
    if (match) aliases.push({ alias: match[1], nullId: match[2] })
  }
  return aliases
})

ipcMain.handle('add-send', async (_, nullId, message, ttl) => {
  const args = ['send', nullId, message]
  if (ttl) args.push('--ttl', ttl)
  return queuedCommand(args)
})

ipcMain.handle('add-read', async (_, json) => {
  const output = await queuedCommand(json ? ['read', '--json'] : ['read'])
  if (!json) return output
  // Parse one JSON object per line: {"from":"<null_id>","text":"<msg>"}
  return output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{') && line.endsWith('}'))
    .map((line) => {
      try {
        return JSON.parse(line)
      } catch {
        return null
      }
    })
    .filter((m) => m && m.from && typeof m.text === 'string')
})
ipcMain.handle('add-listen', async () => queuedCommand(['listen']))

ipcMain.handle('add-start-listen', async () => {
  startListenProcess()
  return { success: true, message: 'Background listen process started' }
})

ipcMain.handle('add-stop-listen', async () => {
  killListenProcess()
  return { success: true, message: 'Background listen process stopped' }
})

ipcMain.handle('add-restart-listen', async () => {
  restartListenProcess()
  return { success: true, message: 'Background listen process restarted' }
})

ipcMain.handle('add-listen-status', async () => {
  return { running: !!listenProcess, pid: listenProcess?.pid || null }
})

app.whenReady().then(() => {
  createWindow()

  // Auto-start background listen process
  startListenProcess()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  // Kill listen process on app quit
  killListenProcess()
  if (process.platform !== 'darwin') {
    app.quit()
  }
})