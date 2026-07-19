#!/usr/bin/env node
/**
 * Regenerate emoji/sticker asset maps from the sticker image directory.
 *
 *   public/emoji/gif/<name>.<ext>   (ext ∈ ALLOWED_EXT)
 *
 * Produces:
 *   - src/emoji/codepoint_map.json   emoji codepoint -> "<base>.<ext>"
 *                                    (for codepoint-named files, e.g. 1f600.gif)
 *   - src/emoji/sticker_pack.json    ["<name>.<ext>", ...]
 *                                    (generic pack stickers, e.g. AgAD....webp)
 *
 * Supported formats (ALLOWED_EXT): gif, webp, apng, avif, png, jpg, jpeg, svg.
 *   Animated: gif / webp / apng / avif. Static: png / jpg / svg.
 *   The renderer loads by extension, so mixing formats needs no code change.
 *
 * Naming:
 *   - Codepoint form:  "<cp>.<ext>"  where cp is lowercase hex, dash-joined for
 *     sequences, e.g. "1f600.gif" or "1f468-200d-1f469.webp". These map to the
 *     Unicode emoji and render via the emoji picker.
 *   - Any other name (e.g. "AgAD....webp") is treated as a generic sticker-pack
 *     file and listed in sticker_pack.json, shown in the "Stickers" tab.
 *
 * Usage:  npm run gen:emoji   (or: node scripts/gen-emoji-assets.mjs)
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, '..')

const ALLOWED_EXT = ['gif', 'webp', 'apng', 'avif', 'png', 'jpg', 'jpeg', 'svg']
const CP_RE = /^([0-9a-f]+(?:-[0-9a-f]+)*)\.([a-z0-9]+)$/i
const DEFAULT_CATEGORY = 'Base Stickers'

const GIF_DIR = path.join(ROOT, 'public', 'emoji', 'gif')
const MAP_OUT = path.join(ROOT, 'src', 'emoji', 'codepoint_map.json')
const PACK_OUT = path.join(ROOT, 'src', 'emoji', 'sticker_pack.json')
const CAT_OUT = path.join(ROOT, 'src', 'emoji', 'filtered_categories.json')

function codepointToEmoji(cp) {
  return cp
    .split('-')
    .map((h) => String.fromCodePoint(parseInt(h, 16)))
    .join('')
}

function buildMaps() {
  if (!fs.existsSync(GIF_DIR)) {
    console.error(`Sticker dir not found: ${GIF_DIR}`)
    process.exit(1)
  }

  const files = fs.readdirSync(GIF_DIR)
  const cpMap = new Map() // cp -> { ext, base }  (priority = ALLOWED_EXT order)
  const pack = [] // generic sticker filenames

  for (const f of files) {
    const m = f.match(CP_RE)
    if (!m) {
      // Not a codepoint name → generic pack sticker (validate ext).
      const ext = f.split('.').pop()?.toLowerCase()
      if (ext && ALLOWED_EXT.includes(ext)) pack.push(f)
      continue
    }
    const cp = m[1].toLowerCase()
    const ext = m[2].toLowerCase()
    const existing = cpMap.get(cp)
    if (!existing || ALLOWED_EXT.indexOf(ext) < ALLOWED_EXT.indexOf(existing.ext)) {
      cpMap.set(cp, { ext, base: `${cp}.${ext}` })
    }
  }

  // codepoint_map.json
  const map = {}
  for (const [cp, { base }] of [...cpMap.entries()].sort()) map[cp] = base

  // sticker_pack.json (sorted for stable diffs)
  pack.sort()

  // filtered_categories.json — keep existing categories; append any codepoint
  // emoji not already present to DEFAULT_CATEGORY.
  let cats = {}
  if (fs.existsSync(CAT_OUT)) {
    try {
      cats = JSON.parse(fs.readFileSync(CAT_OUT, 'utf8'))
    } catch {
      cats = {}
    }
  }
  const known = new Set(Object.values(cats).flat())
  const fresh = []
  for (const cp of [...cpMap.keys()].sort()) {
    const emoji = codepointToEmoji(cp)
    if (!known.has(emoji)) fresh.push(emoji)
  }
  if (!cats[DEFAULT_CATEGORY]) cats[DEFAULT_CATEGORY] = []
  cats[DEFAULT_CATEGORY] = [...cats[DEFAULT_CATEGORY], ...fresh]

  fs.writeFileSync(MAP_OUT, JSON.stringify(map, null, 2) + '\n')
  fs.writeFileSync(PACK_OUT, JSON.stringify(pack, null, 2) + '\n')
  fs.writeFileSync(CAT_OUT, JSON.stringify(cats, null, 2) + '\n')

  const extCount = {}
  for (const f of files) {
    const e = f.split('.').pop()?.toLowerCase()
    if (e && ALLOWED_EXT.includes(e)) extCount[e] = (extCount[e] || 0) + 1
  }
  console.log(`Scanned ${files.length} files in ${path.relative(ROOT, GIF_DIR)}`)
  console.log(`codepoint_map.json  : ${Object.keys(map).length} entries`)
  console.log(`sticker_pack.json   : ${pack.length} generic stickers`)
  console.log(`filtered_categories : ${Object.keys(cats).length} categories, ${fresh.length} new emoji added`)
  console.log(`Formats             : ${JSON.stringify(extCount)}`)
}

buildMaps()
