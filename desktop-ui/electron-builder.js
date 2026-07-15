/**
 * electron-builder configuration for Add Desktop.
 *
 * Cross-platform packaging: the native `add` core (a Rust binary) is bundled as
 * an extraResource. Its filename differs per platform:
 *   - Linux / macOS : `add`      (no extension)
 *   - Windows       : `add.exe`
 * The Electron main process resolves the correct name at runtime (see
 * electron/main.js -> getAddCliPath). The CI build step copies the freshly built
 * binary into `../target/bundle/` (a fixed, triple-independent location) so this
 * config does not need to know the Rust target triple. For macOS a universal
 * (lipo'd) binary is placed there to cover both Intel and Apple Silicon.
 */
const isWin = process.platform === 'win32'
const addBinary = isWin ? 'add.exe' : 'add'

/** @type {import('electron-builder').Configuration} */
module.exports = {
  appId: 'org.add.desktop',
  productName: 'Add Desktop',
  directories: {
    output: 'dist-electron'
  },
  files: [
    'dist/**/*',
    'electron/**/*'
  ],
  extraResources: [
    {
      from: `../target/bundle/${addBinary}`,
      to: addBinary,
      filter: ['**/*']
    }
  ],
  extraMetadata: {
    main: 'electron/main.js'
  },
  linux: {
    target: 'deb',
    executableName: 'add-desktop',
    category: 'Network'
  },
  win: {
    target: 'nsis',
    executableName: 'add-desktop'
  },
  mac: {
    target: 'dmg',
    category: 'public.app-category.social-networking'
  },
  nsis: {
    oneClick: false,
    perMachine: false,
    allowToChangeInstallationDirectory: true
  },
  asar: true,
  compression: 'maximum'
}
