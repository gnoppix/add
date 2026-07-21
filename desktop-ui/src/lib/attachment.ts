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
 * Downscale an image data URL so it fits under MAX_ATTACHMENT_BYTES when sent
 * as a sticker. Uses an offscreen canvas (renderer only). Returns the original
 * dataUrl if it is already small enough or decoding fails.
 */
export function downscaleImageDataUrl(
  dataUrl: string,
  maxDim = 512,
  quality = 0.82
): Promise<string> {
  return new Promise((resolve) => {
    if (typeof document === 'undefined' || typeof Image === 'undefined') {
      resolve(dataUrl)
      return
    }
    const img = new Image()
    img.onload = () => {
      const { width, height } = img
      const scale = Math.min(1, maxDim / Math.max(width, height))
      if (scale >= 1) {
        resolve(dataUrl)
        return
      }
      try {
        const canvas = document.createElement('canvas')
        canvas.width = Math.max(1, Math.round(width * scale))
        canvas.height = Math.max(1, Math.round(height * scale))
        const ctx = canvas.getContext('2d')
        if (!ctx) {
          resolve(dataUrl)
          return
        }
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
        const out = canvas.toDataURL('image/webp', quality)
        resolve(out.startsWith('data:image') ? out : dataUrl)
      } catch {
        resolve(dataUrl)
      }
    }
    img.onerror = () => resolve(dataUrl)
    img.src = dataUrl
  })
}

/**
 * Attachment helpers.
 *
 * The Add CLI `send` channel is text-only — there is no file-transfer command
 * in the backend. To keep file sharing real (not a dead button) without a
 * backend change, we carry small files inside the existing encrypted message
 * as a base64 envelope. The envelope is a single self-delimiting block so it
 * round-trips through `add send` / `add read --json` unchanged:
 *
 *   \u0001ADDATT v1
 *   <filename>
 *   <byte-size>
 *   <base64>
 *   \u0001ENDADDATT
 *
 * The 2 MB cap (MAX_ATTACHMENT_BYTES) is enforced at selection time so the
 * resulting base64 payload (~2.7 MB) still fits comfortably in the relay
 * mailbox.
 */

import { MAX_ATTACHMENT_BYTES, ATTACHMENT_RE } from '../types'

export interface AttachmentMeta {
  name: string
  mime: string
  size: number
  data: string // base64, no prefix
}

/** Read a File into its base64 payload (the part after `data:...;base64,`). */
export function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(new Error('Failed to read file'))
    reader.onload = () => {
      const result = reader.result as string
      const comma = result.indexOf(',')
      resolve(comma >= 0 ? result.slice(comma + 1) : result)
    }
    reader.readAsDataURL(file)
  })
}

/** Serialize an attachment into the wire envelope string. */
export function encodeAttachment(a: AttachmentMeta): string {
  // Filenames are placed on their own line of the envelope, so strip any
  // CR/LF to preserve the single-line invariant (a literal newline would
  // misalign the parser). Replace with spaces.
  // Also strip Unicode bidi / zero-width controls (L4) so a name like
  // "‮exe.txt" can't spoof the visible extension order.
  const name =
    a.name
      .replace(/[\u202A-\u202E\u2066-\u2069\u200E\u200F\uFEFF\u200B-\u200D]/g, '')
      .replace(/[\r\n]+/g, ' ')
      .trim() || 'file'
  // v2 carries the MIME type so images can be rendered inline (not just downloaded).
  return `\u0001ADDATT v2\n${name}\n${a.mime}\n${a.size}\n${a.data}\n\u0001ENDADDATT`
}

/** Rebuild a viewable data: URL from an attachment's base64 payload. */
export function attachmentDataUrl(a: AttachmentMeta): string {
  const clean = a.data.includes(',') ? a.data.slice(a.data.indexOf(',') + 1) : a.data
  const mime = a.mime || 'application/octet-stream'
  return `data:${mime};base64,${clean}`
}

/** Known sticker filenames (from bundled pack). */
const KNOWN_STICKERS = new Set([
  "AgAD0wEAArMeMEc.webp",
  "AgAD1AIAAiSuMEc.webp",
  "AgAD3wEAAgNOMUc.webp",
  "AgAD4QEAAlsHMEc.webp",
  "AgAD4QEAAvD4KUc.webp",
  "AgAD5wIAAohuMUc.webp",
  "AgAD6AEAArydMUc.webp",
  "AgAD8gMAAlkNKEc.webp",
  "AgAD9AEAAs0iKEc.webp",
  "AgADAQIAAs-QMUc.webp",
  "AgADCQIAAogeKUc.webp",
  "AgADDwIAAlCNKEc.webp",
  "AgADFQIAAofXMUc.webp",
  "AgADIAIAAljNMUc.webp",
  "AgADIAMAAgnYGUQ.webp",
  "AgADJQMAAjUwKEc.webp",
  "AgADJQMAArRdKUc.webp",
  "AgADJgIAAhurMEc.webp",
  "AgADKQIAAm-aKEc.webp",
  "AgADKQIAAnM7MUc.webp",
  "AgADKwIAAonnMUc.webp",
  "AgADLwMAAoU-MUc.webp",
  "AgADMAIAAlQ7KEc.webp",
  "AgADMAQAAhyYKEc.webp",
  "AgADNQIAAiZ8MEc.webp",
  "AgADNwIAAh8GKEc.webp",
  "AgADQAUAAoiEMEc.webp",
  "AgADVAIAApvVMUc.webp",
  "AgADVgMAAnNoMEc.webp",
  "AgADXwIAAvZ9MUc.webp",
  "AgADZAIAApt9MEc.webp",
  "AgAD_wEAAg62MUc.webp",
  "AgADaAMAAhABMEc.webp",
  "AgADagIAApFlKEc.webp",
  "AgADbQEAAgXqKUc.webp",
  "AgADcQIAAvC5MEc.webp",
  "AgADdgIAAh7pMUc.webp",
  "AgADfAIAApqyMEc.webp",
  "AgADgAIAAgxWKEc.webp",
  "AgADggIAAtYxKUc.webp",
  "AgADhAIAAlmOKEc.webp",
  "AgADiQIAAqbhMEc.webp",
  "AgADkgIAAhc3KUc.webp",
  "AgADlAEAAp7xMEc.webp",
  "AgADngIAAv9iMUc.webp",
  "AgADqAEAAur2MEc.webp",
  "AgADtAIAAv1TMUc.webp",
  "AgADtQIAAitvMUc.webp",
  "AgADvgEAAkdyKEc.webp",
  "AgADyQcAAuN4BAAB.webp",
  "AgADywIAAn6AIEQ.webp",
])

export function isKnownSticker(name: string): boolean {
  return KNOWN_STICKERS.has(name)
}

/**
 * Parse a message body; returns the attachment (and the leading caption) if present.
 * Rejects oversized payloads (M2): the 2 MB cap is only enforced at SEND time in the
 * UI, so a hostile peer/relay could push an arbitrarily large base64 blob. We cap on
 * parse too, so nothing beyond MAX_ATTACHMENT_BYTES ever reaches state or storage.
 *
 * v3: Known sticker reference format: `<filename>\n\n0\n\n` sends only the filename,
 * size 0. Receiver renders from bundled assets via StickerImg.
 */
export function parseAttachment(
  body: string
): { meta: AttachmentMeta; caption: string } | null {
  const m = body.match(ATTACHMENT_RE)
  if (!m) return null
  const name = m[2]
  const mime = m[3] || ''
  const size = parseInt(m[4], 10)
  const data = m[5]
  if (!name || !Number.isFinite(size)) return null
  // v3 sticker reference: size=0 and empty data means "use bundled asset"
  if (size === 0 && !data && isKnownSticker(name)) {
    return { meta: { name, mime: 'image/webp', size: 0, data: '' }, caption: '' }
  }
  if (size > MAX_ATTACHMENT_BYTES) return null
  return { meta: { name, mime, size, data }, caption: '' }
}

/** Format a byte count as a human-readable size. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB']
  let value = bytes / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i++
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`
}

export const MAX_ATTACHMENT_LABEL = formatBytes(MAX_ATTACHMENT_BYTES)