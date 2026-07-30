/**
 * Add Version Check Agent - Node.js implementation
 * Checks local 'add' CLI version against latest GitHub release
 *
 * Usage:
 *   node version-check.js
 *
 * Exits: 0 = up to date or error, 1 = update available
 */

const { execFile } = require('child_process');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

/**
 * Resolve the add CLI path (matches main.js logic)
 */
function getAddCliPath() {
  // 1. Environment variable override
  if (process.env.ADD_CLI_PATH) {
    return process.env.ADD_CLI_PATH;
  }

  // Windows binaries carry a .exe suffix; everything else is extensionless.
  const ext = process.platform === 'win32' ? '.exe' : '';

  // 2. Packaged mode: resources/add/add[.exe] or resources/extra/add[.exe]
  if (process.resourcesPath) {
    const candidates = [
      path.join(process.resourcesPath, 'add', 'add' + ext),
      path.join(process.resourcesPath, 'extra', 'add' + ext),
      path.join(process.resourcesPath, 'add' + ext)
    ];
    for (const packagedPath of candidates) {
      if (fs.existsSync(packagedPath)) {
        return packagedPath;
      }
    }
  }

  // 3. Development mode: relative to project
  const devPath = path.join(__dirname, '../../target/release/add' + ext);
  if (fs.existsSync(devPath)) {
    return devPath;
  }

  // 4. Fallback to current directory
  return './add' + ext;
}

// Configuration
const CONFIG = {
  localCommand: getAddCliPath(),
  localArgs: ['-V'],
  githubApiUrl: 'https://api.github.com/repos/gnoppix/add/releases/latest',
  githubReleasesUrl: 'https://github.com/gnoppix/add/releases',
  cachePath: path.join(os.homedir(), '.cache', 'add_version_check.json'),
  cacheMaxAge: 6 * 60 * 60 * 1000, // 6 hours
  requestTimeout: 10000, // 10 seconds
  userAgent: 'add-version-check-agent/1.0'
};

/**
 * Parse version string to comparable array [major, minor, patch, build?]
 */
function parseVersion(version) {
  if (!version || version === 'UNAVAILABLE' || version === 'UNKNOWN') {
    return null;
  }
  // Strip common prefixes
  const clean = version.trim().replace(/^[vV]?/, '').replace(/^add-/i, '');
  const parts = clean.split(/[.-]/).map(p => parseInt(p, 10)).filter(n => !isNaN(n));
  while (parts.length < 3) parts.push(0);
  // Keep up to 4 parts (major, minor, patch, build)
  return parts.slice(0, 4);
}

/**
 * Compare two version arrays [major, minor, patch, build?]
 * Returns: -1 if a < b, 0 if equal, 1 if a > b
 */
function compareVersions(a, b) {
  if (!a && !b) return 0;
  if (!a) return -1;
  if (!b) return 1;
  const maxLen = Math.max(a.length, b.length);
  for (let i = 0; i < maxLen; i++) {
    const aVal = a[i] || 0;
    const bVal = b[i] || 0;
    if (aVal < bVal) return -1;
    if (aVal > bVal) return 1;
  }
  return 0;
}

/**
 * Get local version by running `add -V`
 */
async function getLocalVersion() {
  return new Promise((resolve) => {
    const child = execFile(CONFIG.localCommand, CONFIG.localArgs, {
      timeout: 5000,
      maxBuffer: 1024
    }, (error, stdout, stderr) => {
      if (error) {
        resolve('UNAVAILABLE');
        return;
      }
      const version = stdout.trim();
      if (!version) {
        resolve('UNAVAILABLE');
        return;
      }
      // Extract version from output like "add 0.3.28" or "0.3.28"
      // Match semantic version pattern, optionally with 'add ' prefix
      const match = version.match(/(?:add\s+)?(\d+\.\d+\.\d+)/i);
      resolve(match ? `v${match[1]}` : 'UNAVAILABLE');
    });
  });
}

/**
 * Fetch latest release from GitHub API
 */
async function getRemoteVersion() {
  return new Promise((resolve) => {
    const req = https.get(CONFIG.githubApiUrl, {
      timeout: CONFIG.requestTimeout,
      headers: {
        'User-Agent': CONFIG.userAgent,
        'Accept': 'application/vnd.github.v3+json'
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode !== 200) {
          resolve('UNKNOWN');
          return;
        }
        try {
          const release = JSON.parse(data);
          const tag = release.tag_name || release.name;
          resolve(tag || 'UNKNOWN');
        } catch {
          resolve('UNKNOWN');
        }
      });
    });

    req.on('error', () => resolve('UNKNOWN'));
    req.on('timeout', () => {
      req.destroy();
      resolve('UNKNOWN');
    });
  });
}

/**
 * Load cached result if fresh
 */
function loadCache() {
  try {
    if (!fs.existsSync(CONFIG.cachePath)) return null;
    const data = JSON.parse(fs.readFileSync(CONFIG.cachePath, 'utf8'));
    if (!data.checked_at) return null;
    const age = Date.now() - new Date(data.checked_at).getTime();
    if (age > CONFIG.cacheMaxAge) return null;
    return data;
  } catch {
    return null;
  }
}

/**
 * Save result to cache
 */
function saveCache(result) {
  try {
    const dir = path.dirname(CONFIG.cachePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(CONFIG.cachePath, JSON.stringify(result, null, 2));
  } catch {
    // Ignore cache write errors
  }
}

/**
 * Main version check function
 */
async function checkVersion() {
  // Try cache first
  const cached = loadCache();
  if (cached) {
    return cached;
  }

  // Fetch versions
  const [localVersion, remoteVersion] = await Promise.all([
    getLocalVersion(),
    getRemoteVersion()
  ]);

  // Compare
  const localParsed = parseVersion(localVersion);
  const remoteParsed = parseVersion(remoteVersion);
  const comparison = compareVersions(localParsed, remoteParsed);

  let status;
  if (localVersion === 'UNAVAILABLE' || remoteVersion === 'UNKNOWN') {
    status = 'UNKNOWN';
  } else if (comparison >= 0) {
    status = 'UP_TO_DATE';
  } else {
    status = 'UPDATE_AVAILABLE';
  }

  const result = {
    status,
    local_version: localVersion,
    latest_version: remoteVersion,
    release_url: `${CONFIG.githubReleasesUrl}/tag/${remoteVersion}`,
    checked_at: new Date().toISOString()
  };

  // Cache result
  saveCache(result);

  return result;
}

// CLI entry point
if (require.main === module) {
  checkVersion()
    .then(result => {
      console.log(JSON.stringify(result, null, 2));
      // Exit 1 if update available (useful for CI/scripts), 0 otherwise
      process.exit(result.status === 'UPDATE_AVAILABLE' ? 1 : 0);
    })
    .catch(err => {
      console.error('Version check failed:', err.message);
      // Fail gracefully - exit 0 so app doesn't block
      console.log(JSON.stringify({
        status: 'UNKNOWN',
        local_version: 'UNAVAILABLE',
        latest_version: 'UNKNOWN',
        release_url: CONFIG.githubReleasesUrl,
        checked_at: new Date().toISOString()
      }, null, 2));
      process.exit(0);
    });
}

module.exports = { checkVersion, parseVersion, compareVersions, getLocalVersion, getRemoteVersion };