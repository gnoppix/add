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

/**
 * Linux D-Bus hardening (engineering, not guesswork):
 *
 * FACT (captured from add-xvfb-run.log): when a session D-Bus exists, Chromium
 * connects to it and — if that bus gets disconnected (e.g. during startx/startxfce4
 * bring-up, or the bus is later torn down) — aborts with
 *   FATAL:dbus/bus.cc:1245] D-Bus connection was disconnected. Aborting.
 * Under XFCE/startx, DBUS_SESSION_BUS_ADDRESS IS already set, so a
 * "if (!DBUS_SESSION_BUS_ADDRESS)" guard is a no-op and never protected anything.
 *
 * FIX: on Linux, ALWAYS re-exec the browser under a *private, dedicated* session
 * bus via `dbus-run-session`. That bus lives exactly for this app's lifetime and
 * is never the session/X bus, so a flaky system bus can't kill Chromium (and thus
 * can't drop the X session to login). The re-exec is guarded by ADD_DESKTOP_HAS_BUS
 * so we never loop. macOS/Windows don't use this bus path → untouched.
 *
 * DEBUGGING: every launch writes structured facts to ~/.cache/add-desktop-debug.log
 * (env-var check, bus address, re-exec decision, uncaught exceptions, exit codes)
 * so a crash can be compared against what we expected.
 */
const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawn: childSpawn, execSync } = require('child_process')

function dbgLog(...args) {
  try {
    const dir = path.join(os.homedir(), '.cache')
    fs.mkdirSync(dir, { recursive: true })
    const ts = new Date().toISOString()
    fs.appendFileSync(
      path.join(dir, 'add-desktop-debug.log'),
      `[${ts}] ${args.map((a) => (typeof a === 'object' ? JSON.stringify(a) : String(a))).join(' ')}\n`
    )
  } catch { /* best effort */ }
}

if (process.platform === 'linux' && process.env.ADD_DESKTOP_HAS_BUS !== '1') {
  let hasRunner = false
  try {
    execSync('command -v dbus-run-session', { stdio: 'ignore' })
    hasRunner = true
  } catch { hasRunner = false }
  dbgLog('linux-bus-guard', {
    dbusAddr: process.env.DBUS_SESSION_BUS_ADDRESS || '(unset)',
    hasRunner,
  })
  if (hasRunner) {
    const args = [process.execPath, ...process.argv.slice(1)]
    const childEnv = { ...process.env, ADD_DESKTOP_HAS_BUS: '1' }
    dbgLog('re-exec under dbus-run-session')
    const child = childSpawn('dbus-run-session', args, {
      stdio: 'inherit',
      env: childEnv,
    })
    child.on('exit', (code) => {
      dbgLog('dbus-run-session child exited', code)
      process.exit(code === null ? 1 : code)
    })
    // Block the parent; the re-exec'd child is the real app.
    process.exit(0)
  } else {
    dbgLog('dbus-run-session NOT available — running without private bus')
  }
}

// Global crash instrumentation: never silently disappear.
process.on('uncaughtException', (err) => {
  dbgLog('uncaughtException', err && err.stack ? err.stack : String(err))
})
process.on('unhandledRejection', (reason) => {
  dbgLog('unhandledRejection', String(reason))
})

const { app, BrowserWindow, ipcMain, shell, Menu } = require('electron')
const { spawn } = require('child_process')
const dbKeyManager = require('./db-key-manager.js')

// Harden Linux against X-session crashes.
// 1) GL: route GL to software (llvmpipe) so Chromium never probes the X server's
//    hardware GLX/mesa driver at startup (a buggy hardware GLX path can crash X).
// 2) D-Bus: handled above — we now always run under a private session bus, so
//    Chromium never hits the fatal "bus disconnected" abort.
// Must run BEFORE any app event handlers or whenReady.
if (process.platform === 'linux') {
  app.disableHardwareAcceleration()
  app.commandLine.appendSwitch('disable-gpu')
  app.commandLine.appendSwitch('disable-gpu-compositing')
  app.commandLine.appendSwitch('disable-software-rasterizer')
  app.commandLine.appendSwitch('disable-gpu-sandbox')
  app.commandLine.appendSwitch('disable-features', 'UseChromeOSDirectVideoDecoder,Vulkan')
  // /dev/shm is often tiny on startx sessions; a full renderer can OOM-kill X.
  app.commandLine.appendSwitch('disable-dev-shm-usage')
  // Software GL: never touch the hardware X GLX driver.
  process.env.LIBGL_ALWAYS_SOFTWARE = '1'
  process.env.GALLIUM_DRIVER = 'llvmpipe'
  process.env.ELECTRON_DISABLE_GPU = '1'
  process.env.ELECTRON_DISABLE_GPU_COMPOSITING = '1'
  dbgLog('linux GL flags applied')
}

// Version check integration
const { initializeVersionCheck, setupVersionCheckIPC } = require('./version-check-integration.js')

// Single-instance: only ONE add-desktop may own the CLI singleton lock
// (~/.add/add.pid) and the background listener at a time. A second launch
// focuses the existing window instead of spawning another listener that
// would collide with the pid lock and the listen pid file.
const gotSingleInstance = app.requestSingleInstanceLock()
dbgLog('requestSingleInstanceLock', gotSingleInstance)
if (!gotSingleInstance) {
  dbgLog('second instance — quitting')
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

  // 2. Packaged mode: resources/add (binary is placed at resources/add by electron-builder extraResources)
  if (app.isPackaged) {
    const candidates = [
      path.join(process.resourcesPath, 'add' + ext),  // Primary: extraResources places it directly at resources/add
      path.join(process.resourcesPath, 'add', 'add' + ext),  // Fallback: nested structure
      path.join(process.resourcesPath, 'extra', 'add' + ext),
    ]
    for (const packagedPath of candidates) {
      try {
        if (fs.statSync(packagedPath).isFile()) {
          return packagedPath
        }
      } catch { /* ignore */ }
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

// True ONLY for the Rust `add` CLI binary (e.g. `add` or `add listen`).
// Critically this must NOT match our own Electron app `add-desktop` or its
// Chromium child processes (GPU/network/zygote) — those are also named
// `add-desktop` and live under /proc/<pid>/comm as `add-desktop`. Killing them
// made Chromium abort (FATAL:dbus/bus.cc:1245) and dropped the X session.
function isRustAddCli(pid) {
  if (pid === process.pid) return false
  if (listenProcess && listenProcess.pid === pid) return false
  // Fast path: /proc/<pid>/comm is the short process name (no args).
  try {
    const comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim()
    if (comm === 'add') return true
    if (comm === 'add-desktop') return false       // our Electron app — NEVER reap
    if (comm.startsWith('add')) return false        // add-desktop children
  } catch { /* can't read /proc */ }
  // Slow path: full command line. Match only a bare `add` or `add listen`
  // invocation: basename ends in `/add` (or ` add`) and is NOT `add-desktop`.
  try {
    const cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8')
      .split('\u0000').filter(Boolean).join(' ').trim()
    const base = cmdline.split(/\s+/)[0] || ''
    const name = base.split('/').pop() || ''
    if (name === 'add-desktop') return false
    if (name === 'add') return true
    // e.g. `add listen` or `/path/to/add listen`
    if (/\badd(\s+listen)?$/.test(cmdline)) return true
  } catch { /* can't read /proc */ }
  return false
}

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
      let alive = false
      try { process.kill(pid, 0); alive = true } catch { /* not running */ }
      if (!alive) {
        fs.unlinkSync(pidFile)
        continue
      }
      // Only reap the real Rust `add` CLI — never our own add-desktop/Chromium.
      if (isRustAddCli(pid)) {
        try {
          process.kill(pid, 'SIGTERM')
          console.log(`[reap] Terminated stale add process PID ${pid} (${pidFile})`)
        } catch { /* already gone */ }
      }
      try { fs.unlinkSync(pidFile) } catch { /* ignore */ }
    } catch { /* ignore per-file errors */ }
  }

  // Fallback: kill any orphaned `add` CLI (exact name only) holding the lock,
  // but NEVER add-desktop or its Chromium children.
  try {
    const { execSync } = require('child_process')
    // pgrep -x matches the exact process NAME (comm), so 'add' won't match
    // 'add-desktop'. (-u limits to current user; '|| true' avoids non-zero exit.)
    const currentUser = os.userInfo().username
    let out = ''
    try {
      out = String(execSync(`pgrep -x -u ${currentUser} add || true`)).trim()
    } catch (_) {}
    if (out) {
      const pids = out.split(/\s+/).map(n => parseInt(n, 10)).filter(Number.isFinite)
      for (const pid of pids) {
        if (!isRustAddCli(pid)) continue
        try {
          process.kill(pid, 'SIGTERM')
          console.log(`[reap] Terminated orphan add process PID ${pid}`)
        } catch {}
      }
    }
  } catch { /* ignore fallback cleanup errors */ }
}

// Ensure PID directory exists
function ensurePidDir() {
  if (!fs.existsSync(PID_DIR)) {
    fs.mkdirSync(PID_DIR, { recursive: true })
  }
}

// CLI command queue to prevent PID lock conflicts.
// Two queues: the DEFAULT queue serializes identity/messaging/listener control
// (id, send, listen, init, unlock, ...) and the READ queue isolates `add read`
// (loadMessages / message polling). This prevents a slow or DB-locked `add read`
// — which blocks while the persistent `add listen` holds the SQLite write lock on
// ~/.add/messages.db — from wedging every other command (e.g. getMyId) behind it.
let cliQueue = Promise.resolve();
let cliReadQueue = Promise.resolve();

// In-memory store for DB passphrase (never persisted to disk)
let dbPassphrase = null;
let mainWindow = null;
let listenProcess = null;

function runCliCommand(args, input) {
  console.log(`[runCliCommand] Spawning: ${ADD_CLI} ${args.join(' ')}` + (input ? ' (stdin)' : ''))
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
    dbgLog('runCliCommand spawned', cmd, JSON.stringify(cmdArgs), 'pid=', child.pid)

    let stdout = ''
    let stderr = ''
    let settled = false

    // Hard timeout so a hung CLI can never block the renderer (and thus the
    // whole UI) forever. add-id that hangs silently is exactly what left myId
    // null and hid the Settings items. 12s is generous for a local key read.
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      try { child.kill('SIGKILL') } catch {}
      dbgLog('runCliCommand TIMEOUT after 12s', cmd, JSON.stringify(cmdArgs),
             'stdout=', JSON.stringify(stdout), 'stderr=', JSON.stringify(stderr))
      reject(new Error(`CLI command timed out after 12s: ${cmd} ${cmdArgs.join(' ')}`))
    }, 12000)

    child.stdout.on('data', (data) => { 
      stdout += data.toString()
      console.log(`[runCliCommand] stdout:`, data.toString())
    })
    child.stderr.on('data', (data) => { 
      stderr += data.toString()
      console.warn(`[runCliCommand] stderr:`, data.toString())
    })

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
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (code === 0) resolve(stdout.trim())
      else reject(new Error(stderr.trim() || `Exit code ${code}`))
    })

    child.on('error', (err) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(err)
    })
  })
}

// Queue wrapper to serialize CLI calls, with retry for singleton lock contention
function queuedCommand(args, input) {
  // Route read-only `read` onto its own queue so a DB-locked `add read`
  // (blocked behind the listener's SQLite write lock) can never stall
  // identity lookups / message sends / listener control.
  const isRead = args[0] === 'read'
  const queue = isRead ? cliReadQueue : cliQueue
  // NOTE: previously this wrapped the chain in `new Promise((resolve,reject)=>{...; return chain})`.
  // An executor's return value is DISCARDED by Promise — resolve/reject were never
  // called, so queuedCommand() returned a promise that stayed PENDING FOREVER, which
  // made every IPC call (add-id, add-read, ...) hang ("reply was never sent"). Return
  // the chained promise directly so it settles with the command's result.
  const chain = queue.then(async () => {
    // Retry up to 3 times if the command fails due to another instance holding the lock
    const maxRetries = 3
    let lastErr = null
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        console.log(`[queuedCommand] Executing: add ${args.join(' ')}${input ? ' (with stdin)' : ''}`)
        const result = await runCliCommand(args, input)
        console.log(`[queuedCommand] Command success: add ${args.join(' ')}, output:`, result)
        return result
      } catch (err) {
        // Check if this is a lock contention error ("Another add instance is already running")
        const msg = err instanceof Error ? String(err).toLowerCase() : String(err).toLowerCase()
        console.log(`[queuedCommand] Command failed: add ${args.join(' ')}, error:`, err)
        if (msg.includes('another add instance is already running') ||
            msg.includes('already another instance is running')) {
          if (attempt < maxRetries) {
            // Before retry, reap stale add processes to clear the singleton lock
            console.log(`[queuedCommand] Lock contention, attempt ${attempt}/${maxRetries} — reaping stale processes before retry...`)
            reapStaleAddProcesses()
            await new Promise((r) => setTimeout(r, 300 * attempt))
            continue
          }
        }
        lastErr = err
        break // Not a lock error or max retries reached, reject with the error
      }
    }
    if (lastErr) throw lastErr
    throw new Error('CLI command failed')
  })
  if (isRead) cliReadQueue = chain
  else cliQueue = chain
  return chain
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
        return pid
      } catch (e) {
        // Process doesn't exist, remove stale PID file
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
      // Give it a moment to terminate
      setTimeout(() => {}, 500)
    } catch (e) {
      // ignore errors
    }
  }
  removeListenPidFile()
}

// Start the background listen process
function startListenProcess(passphrase) {
  // Idempotent: if a listener is already alive (handle + live PID), do nothing.
  // This guards against the listener being killed-then-not-respawned when
  // startListen is invoked twice in quick succession (React StrictMode double
  // effect, or re-entrant unlock flow).
  if (listenProcess && !listenProcess.killed) {
    let alive = false
    try { process.kill(listenProcess.pid, 0); alive = true } catch { /* dead handle */ }
    if (alive) {
      return
    }
  }
  // Kill any existing listen process (stale PID file from a crashed run, or a
  // previous call). Clear our handle so we respawn fresh below.
  killExistingListenProcess()
  listenProcess = null

  // Build env with passphrase if stored in memory or passed directly
  const listenEnv = { ...process.env }
  const effectivePassphrase = passphrase || dbPassphrase
  if (effectivePassphrase) {
    listenEnv.ADD_DB_PASSPHRASE = effectivePassphrase
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
  // Null ID format: NN-XXXX-XXXX where X is base64 (A-Z, a-z, 0-9, +, /)
  let listenBuf = ''
  const INBOUND_RE = /^\[.*?\] From: (NN-[A-Za-z0-9+/]{4}-[A-Za-z0-9+/]{4}) \(([A-F0-9]+)\) \| (.*)$/
  const forwardInbound = (line) => {
    console.log('[main] forwardInbound called with line:', line)
    const m = line.match(INBOUND_RE)
    if (!m) {
      console.log('[main] forwardInbound: line did not match regex')
      return
    }
    const [, nullId, fp, text] = m
    console.log('[main] forwardInbound: parsed message from:', nullId, 'fp:', fp, 'text:', text)
    const win = mainWindow
    if (win && !win.isDestroyed()) {
      console.log('[main] forwardInbound: sending add-incoming-message IPC to renderer')
      win.webContents.send('add-incoming-message', { from: nullId, fingerprint: fp, text })
    } else {
      console.log('[main] forwardInbound: window not available')
    }
  }
  listenProcess.stdout?.on('data', (data) => {
    listenBuf += data.toString()
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
    listenProcess = null
    removeListenPidFile()
  })

  listenProcess.on('error', (err) => {
    // ignore errors for the background listener process
    listenProcess = null
    removeListenPidFile()
  })

  // Write PID file after successful spawn
  writeListenPidFile(listenProcess.pid)
}

// Kill the background listen process
function killListenProcess() {
  if (listenProcess) {
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
  setTimeout(() => startListenProcess(dbPassphrase), 500)
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
  dbgLog('createWindow')
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

  mainWindow.webContents.on('did-finish-load', () => {
    dbgLog('renderer did-finish-load')
  })

  // Bridge the RENDERER console into the debug log so frontend failures (e.g.
  // chatStore.initialize, getMyId results) become visible facts instead of
  // being lost on stdout. level: 0=debug 1=warn 2=error 3=info (electron enum).
  mainWindow.webContents.on('console-message', (_e, level, message, sourceId, lineNo) => {
    dbgLog('[renderer]', `L${level}`, `${message}${sourceId ? ` (${sourceId}:${lineNo})` : ''}`)
  })

  mainWindow.on('close', () => {
    dbgLog('window close event')
  })

  mainWindow.on('closed', () => {
    dbgLog('window closed')
  })

  return mainWindow
}

// IPC Handlers
ipcMain.handle('add-init', async (_, opts) => {
  const args = ['init']
  if (opts?.pin) args.push('--pin', opts.pin)
  if (opts?.password) args.push('--password', opts.password)
  const output = await queuedCommand(args)
  const idMatch = output.match(/Null ID:\s*(NN-[A-Za-z0-9+\/]{4}-[A-Za-z0-9+\/]{4})/)
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
  // Also register the new identity on all bootstrap servers
  try {
    await queuedCommand(['register-all-bootstraps'])
    console.log('[add-init] registered on all bootstrap servers')
  } catch (e) {
    console.warn('[add-init] bootstrap registration skipped:', e.message)
  }
  return result
})

ipcMain.handle('add-id', async () => {
  let output
  try {
    output = await queuedCommand(['id'])
    dbgLog('add-id handler RAW OUTPUT len=', (output || '').length, 'head=', (output || '').slice(0, 60))
  } catch (e) {
    dbgLog('add-id handler ERROR:', e && e.message ? e.message : String(e))
    throw e
  }
  const idMatch = output.match(/Null ID:\s*(NN-[A-Za-z0-9+\/]{4}-[A-Za-z0-9+\/]{4})/)
  const fpMatch = output.match(/Fingerprint:\s*([A-Fa-f0-9]+)/)
  const result = { id: idMatch?.[1] || '', fingerprint: fpMatch?.[1] || '' }
  dbgLog('add-id handler RETURNING', JSON.stringify(result))
  return result
})

ipcMain.handle('add-register', async () => queuedCommand(['register']))
ipcMain.handle('add-check-register', async () => queuedCommand(['check-register']))
ipcMain.handle('add-check-contact-status', async () => {
  const output = await queuedCommand(['contact-status'])
  // CLI prints one line per contact:
  //   "  ✓ <fp8> (NN-xxxx-xxxx) - ONLINE at <addr>"
  //   "  ✗ <fp8> (NN-xxxx-xxxx) - OFFLINE"
  // Parse into [{ nullId, isOnline }] for the renderer's status store.
  const statuses = []
  for (const line of output.split('\n')) {
    const m = line.match(/(NN-[A-Za-z0-9+\/]{4}-[A-Za-z0-9+\/]{4})\)\s*-\s*(ONLINE|OFFLINE)/)
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
    const match = line.match(/(NN-[A-Za-z0-9+\/]{4}-[A-Za-z0-9+\/]{4})\s*->\s*([A-Fa-f0-9]+)/)
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
      const match = line.match(/\s*(.+?)\s*->\s*(NN-[A-Za-z0-9+\/]{4}-[A-Za-z0-9+\/]{4})/)
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

ipcMain.handle('add-start-listen', async (_, passphrase) => {
  startListenProcess(passphrase)
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

// --- Unified Passphrase / DB Key Management ---
// These handlers use the dbKeyManager to load the encryption key via passphrase,
// enabling both CLI and Desktop UI to share the same encrypted messages.db

ipcMain.handle('add-load-db-key', async (_, passphrase) => {
  console.log('[add-load-db-key] Loading DB encryption key...')
  const result = await dbKeyManager.loadDbKey(passphrase)
  if (result.success) {
    dbPassphrase = passphrase // Store for background listener
    console.log('[add-load-db-key] DB key loaded successfully')
  }
  return result
})

ipcMain.handle('add-init-identity', async (_, passphrase) => {
  console.log('[add-init-identity] Initializing new identity...')
  return await dbKeyManager.initIdentity(passphrase)
})

ipcMain.handle('add-read-messages', async (_, passphrase, json) => {
  console.log('[add-read-messages] Reading messages with passphrase...')
  return await dbKeyManager.readMessages(passphrase, json)
})

ipcMain.handle('add-send-message', async (_, passphrase, nullId, message, ttl) => {
  console.log(`[add-send-message] Sending to ${nullId}`)
  return await dbKeyManager.sendMessage(passphrase, nullId, message, ttl)
})

ipcMain.handle('add-unlock-vault', async (_, passphrase) => {
  console.log('[add-unlock-vault] Unlocking vault...')
  return await dbKeyManager.unlockVault(passphrase)
})

ipcMain.handle('add-start-listener', async (_, passphrase) => {
  console.log('[add-start-listener] Starting background listener...')
  return await dbKeyManager.startListener(passphrase)
})

ipcMain.handle('add-register-all-bootstraps', async (_, passphrase) => {
  console.log('[add-register-all-bootstraps] Registering on all bootstraps...')
  return await dbKeyManager.registerAllBootstraps(passphrase)
})

ipcMain.handle('add-get-contacts', async (_, passphrase) => {
  console.log('[add-get-contacts] Fetching contacts...')
  return await dbKeyManager.getContacts(passphrase)
})

ipcMain.handle('add-get-aliases', async (_, passphrase) => {
  console.log('[add-get-aliases] Fetching aliases...')
  return await dbKeyManager.getAliases(passphrase)
})

ipcMain.handle('add-publish-cert', async (_, passphrase) => {
  console.log('[add-publish-cert] Publishing certificate...')
  return await dbKeyManager.publishCert(passphrase)
})

ipcMain.handle('add-unlock', async (_, opts) => {
  const args = ['unlock']
  if (opts.pin) args.push('--pin', opts.pin)
  if (opts.password) args.push('--password', opts.password)
  console.log(`[add-unlock] Executing unlock command: add ${args.join(' ')}`)
  await queuedCommand(args)
  console.log('[add-unlock] Unlock completed, triggering bootstrap registration...')
  // Also register the new identity on all bootstrap servers after unlock
  try {
    await queuedCommand(['register-all-bootstraps'])
    console.log('[add-unlock] registered on all bootstrap servers')
  } catch (e) {
    console.warn('[add-unlock] bootstrap registration skipped:', e.message)
  }
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
const { ZipArchive } = require('archiver')
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
    const archive = new ZipArchive({ zlib: { level: 9 } })

    // Add all files from .add directory FIRST
    archive.directory(addDir, false)
    await archive.finalize()

    // Now stream the finalized archive to disk
    await pipeline(archive, output)
    
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
  dbgLog('app.whenReady resolved')
  // Kill any orphaned `add`/`add listen` from a previous (crashed) run before
  // we start issuing CLI commands, otherwise the singleton pid lock blocks us.
  reapStaleAddProcesses()

  // Create window first, then show unlock dialog inside the app
  createWindow()
  createAppMenu()

  // Setup version check IPC and initialize periodic checks
  setupVersionCheckIPC()
  initializeVersionCheck(mainWindow)

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

app.on('before-quit', (e) => {
  dbgLog('before-quit', { defaultPrevented: e.defaultPrevented })
  cleanupOnExit()
})

app.on('quit', (e, exitCode) => {
  dbgLog('quit', { exitCode })
})

process.on('SIGINT', () => {
  dbgLog('SIGINT')
  cleanupOnExit()
  process.exit(130)
})
process.on('SIGTERM', () => {
  dbgLog('SIGTERM')
  cleanupOnExit()
  process.exit(143)
})