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

const { app, BrowserWindow, ipcMain, shell, Menu } = require('electron')
const { spawn, execSync } = require('child_process')
const path = require('path')
const fs = require('fs')
const os = require('os')

// Single-instance: only ONE add-desktop may own the CLI singleton lock
// (~/.add/add.pid) and the background listener at a time. A second launch
// focuses the existing window instead of spawning another listener that
// would collide with the pid lock and the listen pid file.
if (!app.requestSingleInstanceLock()) {
  app.quit()
}

// Read version from package.json
function getAppVersion() {
  try {
    const pkgPath = path.join(__dirname, '../package.json')
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
    return pkg.version || '0.0.0'
  } catch {
    return '0.0.0'
  }
}

// Resolve add CLI path for dev and packaged modes
function getAddCliPath() {
  // 1. Environment variable override
  if (process.env.ADD_CLI_PATH) {
    return process.env.ADD_CLI_PATH
  }

  // Windows binaries carry a .exe suffix; everything else is extensionless.
  const ext = process.platform === 'win32' ? '.exe' : ''

  // 2. Packaged mode: resources/extra/add[.exe]
  if (app.isPackaged) {
    const packagedPath = path.join(process.resourcesPath, 'add' + ext)
    if (fs.existsSync(packagedPath)) {
      return packagedPath
    }
  }

  // 3. Development mode: relative to project
  const devPath = path.join(__dirname, '../../target/release/add' + ext)
  if (fs.existsSync(devPath)) {
    return devPath
  }

  // 4. Fallback to current directory
  return './add' + ext
}

const ADD_CLI = getAddCliPath()
// PID file paths
const PID_DIR = path.join(os.homedir(), '.add')
const LISTEN_PID_FILE = path.join(PID_DIR, 'add_listen.pid')
const APP_PID_FILE = path.join(PID_DIR, 'add.pid')

// Reap stale CLI processes from a previous (crashed) app run. Without this,
// an orphaned `add`/`add listen` keeps holding ~/.add/add.pid and every
// one-shot command (id, read, send) fails with "Another add instance is
// already running", which in turn made the UI flip to createIdentity.
function reapStaleAddProcesses() {
  for (const pidFile of [APP_PID_FILE, LISTEN_PID_FILE]) {
    try {
      if (!fs.existsSync(pidFile)) continue
      const raw = fs.readFileSync(pidFile, 'utf8').trim()
      const pid = parseInt(raw, 10)
      if (!Number.isFinite(pid) || pid <= 0) {
        fs.unlinkSync(pidFile)
        continue
      }
      // Only reap if the PID is actually alive AND points at an `add` process.
      // Skip our own live listener PID (written lazily further down).
      let alive = false
      try { process.kill(pid, 0); alive = true } catch { /* not running */ }
      if (!alive) {
        fs.unlinkSync(pidFile)
        continue
      }
      // confirm it's an add process (avoid killing an unrelated PID that
      // happens to occupy the now-stale number)
      let isAdd = false
      try {
        const stat = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim()
        isAdd = stat === 'add' || stat.startsWith('add')
      } catch { /* can't read /proc — treat as non-add, leave it alone */ }
      if (isAdd) {
        try {
          process.kill(pid, 'SIGTERM')
          console.log(`[reap] Terminated stale add process PID ${pid} (${pidFile})`)
        } catch { /* already gone */ }
      }
      // Remove the stale pid file regardless so we don't trip on it later.
      try { fs.unlinkSync(pidFile) } catch { /* ignore */ }
    } catch { /* ignore per-file errors */ }
  }
}

// Ensure PID directory exists
function ensurePidDir() {
  if (!fs.existsSync(PID_DIR)) {
    fs.mkdirSync(PID_DIR, { recursive: true })
  }
}

// CLI command queue to prevent PID lock conflicts
let cliQueue = Promise.resolve();

// In-memory store for DB passphrase (never persisted to disk)
let dbPassphrase = null;
let mainWindow = null;
let listenProcess = null;

function runCliCommand(args, input) {
  return new Promise((resolve, reject) => {
    // Build env with passphrase if stored in memory (never persisted to disk)
    const childEnv = { ...process.env }
    if (dbPassphrase) {
      childEnv.ADD_DB_PASSPHRASE = dbPassphrase
    }

    // Check if we need TPM access (init with --pin, unlock with --pin)
    const needsTpm = (args[0] === 'init' && args.includes('--pin')) ||
                     (args[0] === 'unlock' && args.includes('--pin'))

    // If TPM needed, spawn sg directly (no shell) so the space-containing
    // ADD_CLI path stays intact. sg invokes `bash -c '<cliCmd>'`, which keeps
    // the path as one word and passes the real args inside the -c string.
    let cmd = ADD_CLI
    let cmdArgs = args

    if (needsTpm) {
      const cliCmd = [ADD_CLI, ...args]
        .map(a => a.includes(' ') ? `'${a}'` : a)
        .join(' ')
      cmd = 'sg'
      cmdArgs = ['tss', '-c', cliCmd]
    }

    const child = spawn(cmd, cmdArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv,
    })

    let stdout = ''
    let stderr = ''

    child.stdout.on('data', (data) => { stdout += data.toString() })
    child.stderr.on('data', (data) => { stderr += data.toString() })

    // When we have a body to send, write it to stdin and close the stream so
    // the CLI (which reads `-` from stdin) receives the full payload without
    // hitting the OS command-line argument length limit.
    // For TPM commands we can't easily pipe stdin through sg, so skip input.
    if (input != null && !needsTpm) {
      child.stdin.write(input)
      child.stdin.end()
    } else {
      // No input to send. Close stdin immediately so CLIs that read a GPG
      // passphrase (or any prompt) from stdin get EOF and proceed instead of
      // blocking forever — this is the "Create Identity hangs" bug.
      child.stdin.end()
    }

    child.on('close', (code) => {
      if (code === 0) resolve(stdout.trim())
      else reject(new Error(stderr.trim() || `Exit code ${code}`))
    })

    child.on('error', (err) => reject(err))
  })
}

// Queue wrapper to serialize CLI calls
function queuedCommand(args, input) {
  return new Promise((resolve, reject) => {
    cliQueue = cliQueue.then(() => runCliCommand(args, input)).then(resolve, reject)
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
  // Idempotent: if a listener is already alive (handle + live PID), do nothing.
  // This guards against the listener being killed-then-not-respawned when
  // startListen is invoked twice in quick succession (React StrictMode double
  // effect, or re-entrant unlock flow).
  if (listenProcess && !listenProcess.killed) {
    let alive = false
    try { process.kill(listenProcess.pid, 0); alive = true } catch { /* dead handle */ }
    if (alive) {
      console.log('Listen process already running, leaving it alone')
      return
    }
  }
  // Kill any existing listen process (stale PID file from a crashed run, or a
  // previous call). Clear our handle so we respawn fresh below.
  killExistingListenProcess()
  listenProcess = null

  console.log('Starting background add listen process...')
  console.log('[listen] dbPassphrase available:', !!dbPassphrase)
  // Build env with passphrase if stored in memory
  const listenEnv = { ...process.env }
  if (dbPassphrase) {
    listenEnv.ADD_DB_PASSPHRASE = dbPassphrase
    console.log('[listen] ADD_DB_PASSPHRASE set in env')
  } else {
    console.warn('[listen] WARNING: dbPassphrase not set!')
  }
  listenProcess = spawn(ADD_CLI, ['listen'], {
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: false,
    env: listenEnv,
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

// Apply a defense-in-depth Content-Security-Policy and deny all permission
// requests for a renderer window. contextIsolation already blocks Node access;
// this is the second line of defense against any future XSS in the renderer.
// img-src allows: 'self' (bundled assets), data: (base64 attachments rendered
// inline), and file: (animated emoji GIFs unpacked from the asar).
function hardenWebContents(win) {
  const ses = win.webContents.session
  ses.setPermissionRequestHandler((_webContents, _permission, callback) => {
    // No renderer permission grants (camera/mic/geolocation/etc.) are needed.
    callback(false)
  })
  ses.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self';",
          "img-src 'self' data: file:;",
          "style-src 'self' 'unsafe-inline';",
          "script-src 'self';",
          "font-src 'self' data:;",
          "connect-src 'self';",
          "object-src 'none';",
          "base-uri 'self';",
        ].join(' '),
      },
    })
  })
}

function createWindow() {
  const version = getAppVersion()
  const mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: `Gnoppix - Add Messenger ${version}`,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 20, y: 20 },
  })

  hardenWebContents(mainWindow)

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
ipcMain.handle('add-init', async (_, opts) => {
  const args = ['init']
  if (opts?.pin) args.push('--pin', opts.pin)
  if (opts?.password) args.push('--password', opts.password)
  const output = await queuedCommand(args)
  const idMatch = output.match(/Null ID:\s*(NN-[A-Za-z0-9-]+)/)
  const fpMatch = output.match(/Fingerprint:\s*([A-Fa-f0-9]+)/)
  const result = { id: idMatch?.[1] || '', fingerprint: fpMatch?.[1] || '' }
  // Publish the user's cert bundle to the (now authenticated) cert store so
  // contacts can discover it. Best-effort: if the bootstrap is unreachable,
  // don't fail onboarding — log and continue.
  try {
    await queuedCommand(['publish-cert'])
    console.log('[add-init] cert published to bootstrap servers')
  } catch (e) {
    console.warn('[add-init] cert publish skipped (bootstrap unreachable?):', e.message)
  }
  return result
})

ipcMain.handle('add-publish-cert', async () => {
  try {
    const output = await queuedCommand(['publish-cert'])
    return { success: true, output }
  } catch (e) {
    return { success: false, error: e.message }
  }
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
  // Pass the message body via stdin (using "-" as the argv placeholder) so
  // large payloads (file attachments) are not constrained by the OS
  // command-line argument length limit. Plain short messages also go through
  // stdin for a single uniform path.
  const args = ['send', nullId, '-']
  if (ttl) args.push('--ttl', ttl)
  return queuedCommand(args, message)
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

ipcMain.handle('add-set-passphrase', async (_, passphrase) => {
  dbPassphrase = passphrase
  return { success: true }
})

ipcMain.handle('add-submit-passphrase', async (_, passphrase) => {
  // Test the passphrase by running a read command with it
  try {
    const { spawn } = require('child_process')
    const childEnv = { ...process.env, ADD_DB_PASSPHRASE: passphrase }
    const child = spawn(ADD_CLI, ['read', '--json'], {
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv,
    })
    
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (data) => { stdout += data.toString() })
    child.stderr.on('data', (data) => { stderr += data.toString() })
    
    return new Promise((resolve) => {
      child.on('close', (code) => {
        if (code === 0) {
          // Passphrase verified - now store it and emit for dialog
          dbPassphrase = passphrase
          ipcMain.emit('passphrase-submitted', passphrase)
          resolve({ success: true })
        } else {
          resolve({ success: false, error: stderr.trim() || 'Invalid passphrase' })
        }
      })
      child.on('error', (err) => {
        resolve({ success: false, error: err.message })
      })
    })
  } catch (err) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('add-clear-passphrase', async () => {
  dbPassphrase = null
  return { success: true }
})

ipcMain.handle('add-unlock', async (_, opts) => {
  const args = ['unlock']
  if (opts.pin) args.push('--pin', opts.pin)
  if (opts.password) args.push('--password', opts.password)
  await queuedCommand(args)
})

// Self-destruct: delete ~/.add directory (messages, keys, identity)
ipcMain.handle('add-self-destruct', async (_, homeDir) => {
  const addDir = path.join(homeDir, '.add')
  if (fs.existsSync(addDir)) {
    fs.rmSync(addDir, { recursive: true, force: true })
  }
  return { success: true, message: 'Identity destroyed' }
})

// Backup/Restore functions for ~/.add directory
const { createWriteStream } = require('fs')
const { pipeline } = require('stream/promises')
const archiver = require('archiver')
const unzipper = require('unzipper')

// Backup ~/.add to ~/.add-backup with timestamp, keep max 4 backups
ipcMain.handle('add-backup', async () => {
  try {
    const homeDir = os.homedir()
    const addDir = path.join(homeDir, '.add')
    const backupDir = path.join(homeDir, '.add-backup')
    
    if (!fs.existsSync(addDir)) {
      return { success: false, error: 'No .add directory found to backup' }
    }
    
    // Ensure backup directory exists
    if (!fs.existsSync(backupDir)) {
      fs.mkdirSync(backupDir, { recursive: true })
    }
    
    // Generate timestamped backup filename
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').split('Z')[0]
    const backupName = `add-backup-${timestamp}.zip`
    const backupPath = path.join(backupDir, backupName)
    
    // Create zip archive
    const output = createWriteStream(backupPath)
    const archive = archiver('zip', { zlib: { level: 9 } })
    
    await pipeline(archive, output)
    
    // Add all files from .add directory
    archive.directory(addDir, false)
    await archive.finalize()
    
    // Cleanup old backups (keep max 4)
    const backups = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('add-backup-') && f.endsWith('.zip'))
      .map(f => ({ name: f, time: fs.statSync(path.join(backupDir, f)).mtimeMs }))
      .sort((a, b) => b.time - a.time)
    
    for (let i = 4; i < backups.length; i++) {
      fs.unlinkSync(path.join(backupDir, backups[i].name))
    }
    
    const stats = fs.statSync(backupPath)
    return { 
      success: true, 
      backupName,
      backupPath,
      size: stats.size,
      timestamp: new Date().toISOString()
    }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// List available backups in ~/.add-backup
ipcMain.handle('add-list-backups', async () => {
  try {
    const backupDir = path.join(os.homedir(), '.add-backup')
    if (!fs.existsSync(backupDir)) {
      return { success: true, backups: [] }
    }
    
    const backups = fs.readdirSync(backupDir)
      .filter(f => f.startsWith('add-backup-') && f.endsWith('.zip'))
      .map(f => {
        const fullPath = path.join(backupDir, f)
        const stats = fs.statSync(fullPath)
        return {
          name: f,
          path: fullPath,
          size: stats.size,
          mtime: stats.mtime.toISOString()
        }
      })
      .sort((a, b) => new Date(b.mtime) - new Date(a.mtime))
    
    return { success: true, backups }
  } catch (err) {
    return { success: false, error: err.message, backups: [] }
  }
})

// Delete a backup
ipcMain.handle('add-delete-backup', async (_, backupName) => {
  try {
    const backupDir = path.join(os.homedir(), '.add-backup')
    const backupPath = path.join(backupDir, backupName)
    
    if (!fs.existsSync(backupPath)) {
      return { success: false, error: 'Backup file not found' }
    }
    
    fs.unlinkSync(backupPath)
    return { success: true, message: `Deleted ${backupName}` }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

// Restore ~/.add from a backup zip
ipcMain.handle('add-restore', async (_, backupName) => {
  try {
    const homeDir = os.homedir()
    const addDir = path.join(homeDir, '.add')
    const backupDir = path.join(homeDir, '.add-backup')
    const backupPath = path.join(backupDir, backupName)
    
    if (!fs.existsSync(backupPath)) {
      return { success: false, error: 'Backup file not found' }
    }
    
    // Remove existing .add directory
    if (fs.existsSync(addDir)) {
      fs.rmSync(addDir, { recursive: true, force: true })
    }
    
    // Create fresh .add directory
    fs.mkdirSync(addDir, { recursive: true })
    
    // Extract backup
    await pipeline(
      fs.createReadStream(backupPath),
      unzipper.Extract({ path: addDir })
    )
    
    return { success: true, message: `Restored from ${backupName}` }
  } catch (err) {
    return { success: false, error: err.message }
  }
})

ipcMain.handle('add-passwd', async (_, current, newPass) => {
  runCliCommand(['passwd', '--current', current, '--new', newPass])
})

// Handle IPC calls from About window
ipcMain.handle('add-open-external', async (_, url) => {
  openInDefaultBrowser(url)
})

ipcMain.handle('add-get-version', async () => {
  return getAppVersion()
})

// Read a bundled sticker asset and return it as a base64 data URL.
// The preload is sandboxed (no fs), so it delegates here. Assets are unpacked
// next to the asar at <resources>/app.asar.unpacked/dist/<relPath> so animated
// formats render; fall back to the plain asar copy if needed.
ipcMain.handle('add-read-asset', async (_, relPath) => {
  try {
    const base = process.resourcesPath || path.dirname(process.execPath)
    const candidates = [
      path.join(base, 'app.asar.unpacked', 'dist', relPath),
      path.join(base, 'dist', relPath),
    ]
    for (const abs of candidates) {
      if (fs.existsSync(abs)) {
        const buf = fs.readFileSync(abs)
        const ext = relPath.split('.').pop()?.toLowerCase() || 'bin'
        const mime = ext === 'svg' ? 'image/svg+xml' : `image/${ext === 'jpg' ? 'jpeg' : ext}`
        return `data:${mime};base64,${buf.toString('base64')}`
      }
    }
    return null
  } catch {
    return null
  }
})

// Open `url` in the OS default browser.
// - Linux: xdg-open forwards to an already-running browser, which trips
//   LibreWolf's "already running" profile lock. We spawn the browser binary
//   directly with a fresh temp profile per click (see openInLinuxBrowser).
// - macOS / Windows: shell.openExternal is the correct native API and has no
//   such single-instance lock problem, so use it directly.
function openInDefaultBrowser(url) {
  if (process.platform === 'linux') {
    openInLinuxBrowser(url)
    return
  }
  // darwin / win32 — native, reliable, no profile-lock issue
  shell.openExternal(url)
}

// Linux: spawn the default browser binary directly (bypassing xdg-open's
// single-instance forwarding) with a unique throwaway profile per click so we
// never collide with the locked default profile of a stuck/running instance.
function openInLinuxBrowser(url) {
  try {
    const browser = resolveDefaultBrowser()
    if (!browser) {
      shell.openExternal(url)
      return
    }
    // Unique temp profile dir per click so we never touch the locked default
    // profile of a stuck/running browser instance.
    const tmpProfile = fs.mkdtempSync(path.join(os.tmpdir(), 'add-browser-'))
    let args
    if (browser.family === 'chromium') {
      args = ['--user-data-dir=' + tmpProfile, '--new-window', url]
    } else {
      // firefox / librewolf
      args = ['-profile', tmpProfile, '--new-instance', url]
    }
    // Explicit cwd: if the app was launched from a dir that no longer exists,
    // the spawned shell would print "getcwd() failed" and may fail to start.
    const child = spawn(browser.cmd, args, {
      detached: true,
      stdio: 'ignore',
      cwd: os.homedir(),
    })
    child.unref()
  } catch {
    // Last resort: let the OS figure it out
    shell.openExternal(url)
  }
}

function resolveDefaultBrowser() {
  let cmd = ''
  try {
    cmd = execSync('xdg-settings get default-web-browser', { encoding: 'utf8' }).trim()
  } catch {
    return null
  }
  if (!cmd) return null
  // xdg-settings returns e.g. "librewolf.desktop" — strip the .desktop suffix
  cmd = cmd.replace(/\.desktop$/, '')
  const families = {
    firefox: ['librewolf', 'firefox', 'firefox-esr', 'tor-browser'],
    chromium: ['chromium', 'google-chrome', 'chrome', 'brave', 'vivaldi', 'edge'],
  }
  for (const family of ['firefox', 'chromium']) {
    if (families[family].some((k) => cmd.includes(k))) {
      return { cmd, family }
    }
  }
  // Unknown browser: assume firefox-style CLI
  return { cmd, family: 'firefox' }
}

function createAppMenu() {
  const version = getAppVersion()
  const template = [
    {
      label: 'File',
      submenu: [
        { role: 'quit' }
      ]
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { type: 'separator' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' }
      ]
    },
    {
      label: 'Support',
      submenu: [
        {
          label: 'Contact us',
          click: () => openInDefaultBrowser('https://gnoppix.org/contact/')
        },
        {
          label: 'Report a Problem',
          click: () => openInDefaultBrowser('https://github.com/gnoppix/add/issues')
        },
        { type: 'separator' },
        {
          label: 'Other Privacy Services',
          click: () => openInDefaultBrowser('https://gnoppix.org/solutions/index.html')
        },
        {
          label: 'Visit our Forum',
          click: () => openInDefaultBrowser('https://forum.gnoppix.org/c/general/4')
        },
        {
          label: 'Source Code',
          click: () => openInDefaultBrowser('https://github.com/gnoppix/add')
        },
        { type: 'separator' },
        {
          label: 'Become a Supporter',
          click: () => openInDefaultBrowser('https://gnoppix.org/sponsor/index.html')
        },
        {
          label: 'About',
          click: () => {
            const aboutWin = new BrowserWindow({
              width: 400,
              height: 420,
              resizable: false,
              minimizable: false,
              maximizable: false,
              fullscreenable: false,
              title: 'About',
              titleBarStyle: 'hiddenInset',
              trafficLightPosition: { x: 20, y: 20 },
              webPreferences: {
                nodeIntegration: false,
                contextIsolation: true,
                preload: path.join(__dirname, 'preload.js')
              }
            })
            hardenWebContents(aboutWin)
            aboutWin.loadFile(path.join(__dirname, 'about.html'))
          }
        }
      ]
    }
  ]

  const menu = Menu.buildFromTemplate(template)
  Menu.setApplicationMenu(menu)
}

// Show passphrase entry dialog before creating main window
function showPassphraseDialog() {
  return new Promise((resolve) => {
    const dialogWin = new BrowserWindow({
      width: 400,
      height: 220,
      resizable: false,
      minimizable: false,
      maximizable: false,
      fullscreenable: false,
      title: 'Unlock Add Messenger',
      titleBarStyle: 'hiddenInset',
      trafficLightPosition: { x: 20, y: 20 },
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        preload: path.join(__dirname, 'preload.js')
      }
    })

    dialogWin.setMenuBarVisibility(false)
    
    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px; background: var(--color-background, #fff); color: var(--color-text, #000); }
          h2 { margin: 0 0 8px; font-size: 1.25rem; font-weight: 600; }
          p { margin: 0 0 24px; font-size: 0.875rem; opacity: 0.7; }
          input { width: 100%; padding: 12px; font-size: 1rem; border: 1px solid var(--color-border, #ddd); border-radius: 6px; box-sizing: border-box; margin-bottom: 16px; }
          input:focus { outline: none; border-color: var(--color-primary, #3b82f6); box-shadow: 0 0 0 3px var(--color-primary-light, rgba(59,130,246,0.2)); }
          button { width: 100%; padding: 12px; font-size: 1rem; font-weight: 500; background: var(--color-primary, #3b82f6); color: white; border: none; border-radius: 6px; cursor: pointer; }
          button:hover { opacity: 0.9; }
          button:disabled { opacity: 0.5; cursor: not-allowed; }
          .error { color: var(--color-error, #ef4444); font-size: 0.875rem; margin-top: 8px; min-height: 20px; }
        </style>
      </head>
      <body>
        <h2>Unlock Add Messenger</h2>
        <p>Enter your database passphrase to decrypt messages and keys.</p>
        <input type="password" id="passphrase" placeholder="Passphrase" autocomplete="off" autofocus />
        <button id="submit" disabled>Unlock</button>
        <div id="error" class="error"></div>
        <script>
          const input = document.getElementById('passphrase')
          const btn = document.getElementById('submit')
          const error = document.getElementById('error')
          
          input.addEventListener('input', () => {
            btn.disabled = input.value.length === 0
          })
          
          input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !btn.disabled) {
              submit()
            }
          })
          
          function submit() {
            btn.disabled = true
            btn.textContent = 'Unlocking...'
            window.addAPI.setPassphrase(input.value).then((result) => {
              if (result.success) {
                // Passphrase stored in main process, now submit it back
                window.addAPI.submitPassphrase(input.value).then(() => {
                  window.close()
                })
              } else {
                error.textContent = result.error || 'Failed to set passphrase'
                btn.disabled = false
                btn.textContent = 'Unlock'
              }
            }).catch((err) => {
              error.textContent = err.message || 'Error'
              btn.disabled = false
              btn.textContent = 'Unlock'
            })
          }
          
          btn.addEventListener('click', submit)
          
          // Focus input on load
          input.focus()
        </script>
      </body>
      </html>
    `
    
    dialogWin.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html))
    
    dialogWin.on('closed', () => {
      // If dialog was closed without submitting, quit the app
      if (!passphraseEntered) {
        app.quit()
      }
    })
    
    let passphraseEntered = false
    
    // Listen for passphrase submission from dialog
    ipcMain.once('passphrase-submitted', (_, passphrase) => {
      passphraseEntered = true
      dialogWin.close()
      resolve(passphrase)
    })
  })
}

app.whenReady().then(async () => {
  // Kill any orphaned `add`/`add listen` from a previous (crashed) run before
  // we start issuing CLI commands, otherwise the singleton pid lock blocks us.
  reapStaleAddProcesses()

  // Create window first, then show unlock dialog inside the app
  createWindow()
  createAppMenu()

  // Auto-start background listen process (will wait for unlock)
  console.log('[main] App ready, waiting for unlock...')

  // A second instance tried to launch: focus the existing window instead of
  // spawning another listener (which would collide with the pid/lock files).
  app.on('second-instance', (event, argv) => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      mainWindow.focus()
    }
  })

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

// Robust cleanup: kill the background listener on ANY exit path, including
// when the main process is terminated by a signal (SIGINT/SIGTERM) or via
// app.quit(). Without this the spawned `add listen` child is orphaned and
// keeps holding the listen port after the UI exits.
function cleanupOnExit() {
  killListenProcess()
}

app.on('before-quit', cleanupOnExit)

process.on('SIGINT', () => {
  cleanupOnExit()
  process.exit(130)
})
process.on('SIGTERM', () => {
  cleanupOnExit()
  process.exit(143)
})