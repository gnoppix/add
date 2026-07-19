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
 * Message types and interfaces for Add Desktop
 */

export type MessageStatus = 'sending' | 'sent' | 'delivered' | 'read' | 'error'

export interface Message {
  id: string
  content: string
  timestamp: Date
  status: MessageStatus
  senderId: string
  ttl?: string // Auto-destruct timer (e.g., '2h', '12h', '24h', '48h', '5d', '7d', '14d')
  attachment?: {
    name: string
    mime: string
    size: number
    data: string // base64 (no padding prefix) of the file contents
  }
}

// Max file attachment size: 5 MB. The Add CLI `send` channel is text-only, so
// attachments are base64-encoded and carried inside the encrypted message
// envelope; 5 MB keeps the payload within relay/mailbox limits while allowing
// animated stickers (webp/apng) to retain quality.
export const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024

// Matches a serialized attachment envelope embedded in a message body.
// The data group allows empty (a 0-byte file base64-encodes to '').
// v2 carries a MIME type so images can be rendered inline (not just downloaded).
export const ATTACHMENT_RE =
  // eslint-disable-next-line no-control-regex
  /^\u0001ADDATT v(\d)\n([^\n]+)\n([^\n]*)\n(\d+)\n([A-Za-z0-9+/=]*)\n\u0001ENDADDATT$/

export interface Conversation {
  id: string
  name: string
  fingerprint?: string
  avatarUrl?: string
  lastMessage?: string
  lastMessageTimestamp?: Date
  unreadCount: number
  isOnline?: boolean
  isGroup?: boolean
}