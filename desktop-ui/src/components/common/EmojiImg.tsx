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
 * Emoji renderer: Moetwemoji GIF assets for consistent colorful emoji in picker.
 * Falls back to rendering the Unicode character if no GIF asset exists.
 */
import React, { useRef, useEffect } from 'react'
import emojiMap from '../../emoji/codepoint_map.json'

// Skin-tone modifiers + ZWJ. Stripped when a base emoji has no asset under its
// full (composed) codepoint, so "👍🏽" and "👨‍👩‍👧" still resolve to their base GIF
// instead of silently falling back to Unicode (L3).
const SKIN_TONE = /[\u{1F3FB}-\u{1F3FF}]/gu
const ZWJ = /\u200D/g

function toCodepoint(emoji: string): string {
  const codePoints: number[] = []
  for (const cp of emoji) {
    const h = cp.codePointAt(0)
    if (h) codePoints.push(h)
  }
  return codePoints.map((h) => h.toString(16).toLowerCase()).join('-')
}

/**
 * Resolve a GIF filename for an emoji, tolerant of skin-tone / ZWJ composition
 * (L3). Tries the full codepoint key first; if that misses, retries after
 * stripping skin tones + ZWJ so composed variants map to the base asset.
 */
function emojiToFilename(emoji: string): string | null {
  const map = emojiMap as Record<string, string>
  const full = toCodepoint(emoji)
  if (map[full]) return map[full]
  const base = toCodepoint(emoji.replace(SKIN_TONE, '').replace(ZWJ, ''))
  return map[base] || null
}

interface EmojiImgProps {
  emoji: string
  size?: number
  className?: string
}
// Resolve the GIF file location.
// Resolve a sticker asset's URL.
// `filename` is the raw map value, which already includes its extension
// (e.g. "1f600.gif" or "1f600.webp") — see scripts/gen-emoji-assets.mjs.
// - Dev (Vite): served from public/ at "/emoji/gif/<filename>".
// - Packaged (Electron asar): the asar packs animated formats frozen
//   (frame 1 only), so electron-builder unpacks them to
//   app.asar.unpacked/dist/emoji/gif/. We point at the REAL unpacked file so
//   Chromium animates it. process.resourcesPath is unavailable in the
//   context-isolated renderer, so we use window.addAPI.resourcesPath (preload).
function gifUrl(filename: string): string {
  const resourcesPath = typeof window !== 'undefined' && window.addAPI?.resourcesPath
  const isPackaged = typeof window !== 'undefined' && window.addAPI?.isPackaged === true

  if (isPackaged && resourcesPath) {
    return `file://${resourcesPath}/app.asar.unpacked/dist/emoji/gif/${filename}`
  }
  // Dev: Vite serves public/emoji/gif
  return `/emoji/gif/${filename}`
}

export const EmojiImg: React.FC<EmojiImgProps> = ({ emoji, size = 20, className = '' }) => {
  const url = emojiToUrl(emoji)
  // No GIF asset: fall back to rendering the Unicode character
  if (!url) {
    return (
      <span
        style={{ fontSize: size, lineHeight: 1 }}
        className={className}
      >
        {emoji}
      </span>
    )
  }

  const imgRef = useRef<HTMLImageElement>(null)

  // Aggressively kick the GIF animation in Electron:
  // 1. Force a fresh src assignment after mount (triggers decoder restart).
  // 2. Use a unique key (via url + timestamp) to force remount if needed.
  // 3. Call decode() to ensure the image is fully loaded before painting.
  useEffect(() => {
    const img = imgRef.current
    if (!img) return
    // Restart animation by re-assigning src (with cache-buster) after a paint.
    const animationFrame = requestAnimationFrame(() => {
      const freshUrl = `${url}#t=${Date.now()}`
      img.src = freshUrl
      // Also call decode() to prime the decoder.
      img.decode?.().catch(() => {})
    })
    return () => cancelAnimationFrame(animationFrame)
  }, [url])

  return (
    <img
      ref={imgRef}
      src={url}
      alt={emoji}
      style={{ width: size, height: size, verticalAlign: 'middle' }}
      className={`emoji-img ${className}`}
      // No loading="lazy" — it freezes GIFs in Electron.
    />
  )
}

/** Returns the GIF URL for an emoji, or null if no asset exists. */
export function emojiToUrl(emoji: string): string | null {
  const filename = emojiToFilename(emoji)
  if (!filename) return null
  return gifUrl(filename)
}

/**
 * If the entire string is composed of emoji that each have a GIF asset,
 * return the individual emoji characters (so they can be rendered as
 * animated stickers). Otherwise return null (treat as plain text).
 */
export function stickerEmojis(content: string): string[] | null {
  const chars = Array.from(content)
  if (chars.length === 0) return null
  const result: string[] = []
  for (const c of chars) {
    if (!emojiToUrl(c)) return null
    result.push(c)
  }
  return result
}