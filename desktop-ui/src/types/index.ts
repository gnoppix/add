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
}

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