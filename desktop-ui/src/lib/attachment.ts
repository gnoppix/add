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
  // CR/LF from the name to preserve the single-line invariant (a name with a
  // literal newline would otherwise misalign the parser). Replace with spaces.
  const name = a.name.replace(/[\r\n]+/g, ' ').trim() || 'file'
  return `ADDATT v1\n${name}\n${a.size}\n${a.data}\nENDADDATT`
}

/** Parse a message body; returns the attachment (and the leading caption) if present. */
export function parseAttachment(
  body: string
): { meta: AttachmentMeta; caption: string } | null {
  const m = body.match(ATTACHMENT_RE)
  if (!m) return null
  const name = m[1]
  const size = parseInt(m[2], 10)
  const data = m[3]
  if (!name || !Number.isFinite(size)) return null
  return { meta: { name, mime: '', size, data }, caption: '' }
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

