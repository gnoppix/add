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
  // Animated formats (gif/webp/apng/avif) must NOT stay packed inside the
  // asar: Chromium reads only the first frame from an asar stream, so stickers
  // render frozen. Unpacking them to real files on disk lets the browser
  // animate normally. The path is 'dist/emoji/gif/*.{gif,webp,apng,avif,...}'
  // inside the asar (dist/ is the app root there). Static png/jpg/svg are fine
  // packed, but unpacking them too keeps the loader simple.
  asarUnpack: ['dist/**/*.{gif,webp,apng,avif,png,jpg,jpeg,svg}'],
  compression: 'maximum'
}
