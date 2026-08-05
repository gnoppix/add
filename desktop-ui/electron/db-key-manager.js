/**
 * Database Encryption Key Manager for Electron Main Process
 * 
 * Bridges the CLI's DbEncryptionKey logic to the desktop UI.
 * Uses the CLI binary to load/manage the database encryption key.
 * 
 * The CLI already handles:
 * - AES-256-GCM key generation/storage
 * - age-encrypted key file (.add/db_key.json.age)
 * - Passphrase-based unlocking
 * - ADD_DB_PASSPHRASE env var for headless operation
 */

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

const ADD_CLI = path.join(os.homedir(), '.local', 'bin', 'add'); // fallback
const MESSAGES_DB = path.join(os.homedir(), '.add', 'messages.db');
const DB_KEY_PATH = path.join(os.homedir(), '.add', 'db_key.json');

/**
 * Find the add CLI binary
 */
function findAddCli() {
  const candidates = [
    path.join(process.resourcesPath, 'add'),
    path.join(process.resourcesPath, 'add', 'add'),
    path.join(process.resourcesPath, 'extra', 'add'),
    path.join(__dirname, '../../target/release/add'),
    path.join(__dirname, '../../target/bundle/add'),
    '/usr/local/bin/add',
    '/usr/bin/add',
    process.env.ADD_CLI_PATH,
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      if (require('fs').statSync(candidate).isFile()) {
        return candidate;
      }
    } catch { /* ignore */ }
  }
  return 'add'; // fallback to PATH
}

let cachedAddCli = null;
function getAddCli() {
  if (!cachedAddCli) {
    cachedAddCli = findAddCli();
  }
  return cachedAddCli;
}

/**
 * Execute a CLI command and return stdout
 */
function runCliCommand(args, input, env = {}) {
  return new Promise((resolve, reject) => {
    const cli = getAddCli();
    const childEnv = { ...process.env, ...env };
    
    const child = spawn(cli, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: childEnv,
    });

    let stdout = '';
    let stderr = '';
    
    child.stdout.on('data', (data) => { stdout += data.toString(); });
    child.stderr.on('data', (data) => { stderr += data.toString(); });
    
    if (input != null) {
      child.stdin.write(input);
      child.stdin.end();
    } else {
      child.stdin.end();
    }

    child.on('close', (code) => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(stderr.trim() || `Exit code ${code}`));
    });
    
    child.on('error', reject);
  });
}

/**
 * Load the database encryption key using the provided passphrase.
 * This mirrors the CLI's `load_db_key_interactive` logic.
 * 
 * @param {string} passphrase - User's passphrase
 * @returns {Promise<{success: boolean, key?: string, error?: string}>}
 */
async function loadDbKey(passphrase) {
  try {
    // The CLI's `add id` command will load the DB key internally when passphrase is provided
    // We can verify the passphrase works by running a simple command that requires the DB
    const result = await runCliCommand(['id'], null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    
    // Parse the output to get identity
    const idMatch = result.match(/Null ID:\s*(NN-[A-Za-z0-9+\/]{4}-[A-Za-z0-9+\/]{4})/);
    const fpMatch = result.match(/Fingerprint:\s*([A-Fa-f0-9]+)/);
    
    if (idMatch && fpMatch) {
      return { 
        success: true, 
        key: 'loaded', // The CLI manages the key internally
        identity: { id: idMatch[1], fingerprint: fpMatch[1] }
      };
    }
    
    return { success: false, error: 'Failed to parse identity from CLI output' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Initialize a new identity with passphrase
 */
async function initIdentity(passphrase) {
  try {
    const result = await runCliCommand(['init', '--password', passphrase], null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    
    const idMatch = result.match(/Null ID:\s*(NN-[A-Za-z0-9+\/]{4}-[A-Za-z0-9+\/]{4})/);
    const fpMatch = result.match(/Fingerprint:\s*([A-Fa-f0-9]+)/);
    
    if (idMatch && fpMatch) {
      return { 
        success: true, 
        identity: { id: idMatch[1], fingerprint: fpMatch[1] }
      };
    }
    
    return { success: false, error: 'Failed to parse identity from init output' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Read messages from the encrypted database
 */
async function readMessages(passphrase, json = true) {
  try {
    const args = ['read'];
    if (json) args.push('--json');
    const result = await runCliCommand(args, null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Send a message
 */
async function sendMessage(passphrase, nullId, message, ttl) {
  try {
    const args = ['send', nullId, '-'];
    if (ttl) args.push('--ttl', ttl);
    const result = await runCliCommand(args, message, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Check if identity exists
 */
async function checkIdentityExists() {
  try {
    const path = require('path');
    const fs = require('fs');
    const identityFile = path.join(os.homedir(), '.add', 'identity.json');
    const dbKeyFile = path.join(os.homedir(), '.add', 'db_key.json');
    return { exists: fs.existsSync(identityFile) && fs.existsSync(dbKeyFile) };
  } catch {
    return { exists: false };
  }
}

/**
 * Unlock the vault with passphrase
 */
async function unlockVault(passphrase) {
  try {
    const result = await runCliCommand(['unlock', '--password', passphrase], null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Start the background listener
 */
async function startListener(passphrase) {
  try {
    const result = await runCliCommand(['listen'], null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Stop the background listener
 */
async function stopListener() {
  try {
    const result = await runCliCommand(['listen-status'], null);
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Get listener status
 */
async function listenerStatus() {
  try {
    const result = await runCliCommand(['listen-status'], null);
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Register on all bootstrap servers
 */
async function registerAllBootstraps(passphrase) {
  try {
    const result = await runCliCommand(['register-all-bootstraps'], null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Get contacts
 */
async function getContacts(passphrase) {
  try {
    const result = await runCliCommand(['contacts'], null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Get aliases
 */
async function getAliases(passphrase) {
  try {
    const result = await runCliCommand(['aliases'], null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Publish certificate
 */
async function publishCert(passphrase) {
  try {
    const result = await runCliCommand(['publish-cert'], null, {
      ADD_DB_PASSPHRASE: passphrase,
    });
    return { success: true, data: result };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

module.exports = {
  loadDbKey,
  initIdentity,
  readMessages,
  sendMessage,
  checkIdentityExists,
  unlockVault,
  startListener,
  stopListener,
  listenerStatus,
  registerAllBootstraps,
  getContacts,
  getAliases,
  publishCert,
  getAddCli,
};