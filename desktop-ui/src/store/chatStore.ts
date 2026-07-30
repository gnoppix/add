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

import { create } from 'zustand'
import type { Conversation, Message, MessageStatus } from '../types/index'
import { generateInitialsAvatar } from '../lib/identicon'
import { parseAttachment } from '../lib/attachment'

// Track sent message content to filter out relay echoes
// (only used to detect our own messages echoed back via relay)
const sentContent = new Set<string>()
const markSent = (text: string) => {
  sentContent.add(text)
}

// Dedupe key for incoming relay messages. The relay mailbox is not reliably
// purged, so `add read --json` can return the same messages on every poll.
// We track content seen this session so the UI never shows duplicates.
const seenIncoming = new Set<string>()
const incomingKey = (from: string, text: string) => `${from}\u0000${text}`

// Persistence key: survives app restart so sent/received history isn't lost.
const STORE_KEY = 'add-chat-state-v1'

interface ChatStore {
  activeConversationId: string | null
  conversations: Conversation[]
  messages: Record<string, Message[]>
  searchQuery: string
  myId: string | null
  myFingerprint: string | null
  isAuthenticated: boolean
  _initializing: boolean

  setActiveConversation: (id: string | null) => void
  addConversation: (conversation: Conversation) => void
  addMessage: (conversationId: string, message: Message) => void
  updateMessageStatus: (conversationId: string, messageId: string, status: MessageStatus) => void
  markAsRead: (conversationId: string) => void
  setSearchQuery: (query: string) => void
  getFilteredConversations: () => Conversation[]
  updateContactOnlineStatus: (nullId: string, isOnline: boolean) => void
  renameAlias: (nullId: string, alias: string) => void
  addIncomingMessage: (conversationId: string, content: string) => void
  loadMessages: () => Promise<void>
  checkContactsOnlineStatus: () => Promise<void>
  clearMessages: (conversationId: string) => void
  deleteConversation: (nullId: string) => void

  // Presence / listener control (shared so the avatar LED and sidebar agree)
  listenRunning: boolean
  checkListenStatus: () => Promise<void>
  startListen: () => Promise<void>
  stopListen: () => Promise<void>
  toggleListen: () => Promise<void>
  _lastToggleAt?: number

  // Passphrase management (stored in memory, never persisted to disk)
  setPassphrase: (passphrase: string) => void
  storeSetPassphrase: (passphrase: string) => void
  submitPassphrase: (passphrase: string) => void
  clearPassphrase: () => void

  initialize: () => Promise<void>
  loadContacts: () => Promise<void>
  sendMessage: (content: string, ttl?: string) => Promise<void>

  // Internal persistence methods (not exposed via IPC)
  persist: () => void
  hydrate: () => void
}

// Electron API wrapper
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getEvaAPI(): any | null {
  if (typeof window !== 'undefined' && window.addAPI) {
    return window.addAPI
  }
  return null
}

export const useChatStore = create<ChatStore>((set, get) => ({
  activeConversationId: null,
  conversations: [],
  messages: {},
  searchQuery: '',
  myId: null,
  myFingerprint: null,
  isAuthenticated: false,
  _initializing: false,
  listenRunning: false,
  _lastToggleAt: 0,

  setActiveConversation: id => {
    set({ activeConversationId: id })
    if (id) {
      get().markAsRead(id)
      // Pull any messages waiting on the relay for this (and other) conversations.
      get().loadMessages()
    }
  },

  addConversation: conversation => {
    // Never add our own Null ID as a contact (self-echo from relay).
    const myId = get().myId
    if (myId && conversation.id === myId) return
    set(state => {
      // Idempotent: don't create a second entry for the same contact id.
      if (state.conversations.some(c => c.id === conversation.id)) {
        return {
          conversations: state.conversations.map(c =>
            c.id === conversation.id ? { ...c, ...conversation } : c
          ),
        }
      }
      return { conversations: [conversation, ...state.conversations] }
    })
    get().persist()
  },

  addMessage: (conversationId, message) => {
    set(state => {
      const existingMessages = state.messages[conversationId] || []
      return {
        messages: {
          ...state.messages,
          [conversationId]: [...existingMessages, message],
        },
        conversations: state.conversations.map(conv =>
          conv.id === conversationId
            ? { ...conv, lastMessage: message.content, lastMessageTimestamp: message.timestamp }
            : conv
        ),
      }
    })
    get().persist()
  },

  updateMessageStatus: (conversationId, messageId, status) =>
    set(state => ({
      messages: {
        ...state.messages,
        [conversationId]: (state.messages[conversationId] || []).map(msg =>
          msg.id === messageId ? { ...msg, status } : msg
        ),
      },
    })),

  markAsRead: conversationId =>
    set(state => ({
      conversations: state.conversations.map(conv =>
        conv.id === conversationId ? { ...conv, unreadCount: 0 } : conv
      ),
    })),

  setSearchQuery: query => set({ searchQuery: query }),

  getFilteredConversations: () => {
    const { conversations, searchQuery } = get()
    if (!searchQuery) return conversations
    return conversations.filter(conv => conv.name.toLowerCase().includes(searchQuery.toLowerCase()))
  },

  updateContactOnlineStatus: (nullId: string, isOnline: boolean) =>
    set(state => ({
      conversations: state.conversations.map(conv =>
        conv.id === nullId ? { ...conv, isOnline } : conv
      ),
    })),

  renameAlias: (nullId: string, alias: string) =>
    set(state => ({
      conversations: state.conversations.map(conv =>
        conv.id === nullId ? { ...conv, name: alias } : conv
      ),
    })),

  addIncomingMessage: (conversationId: string, content: string) => {
    // An incoming message may carry a file-attachment envelope.
    const parsed = parseAttachment(content)
    const attachment = parsed?.meta
    const body = attachment ? '' : content
    // Dedupe key: for attachments, fold in the name+size so two different
    // files from the same sender are not treated as one repeat.
    const dedupeContent = attachment ? `\u0000${attachment.name}\u0000${attachment.size}` : body
    const key = incomingKey(conversationId, dedupeContent)
    if (seenIncoming.has(key)) return
    seenIncoming.add(key)

    set(state => {
      const existingMessages = state.messages[conversationId] || []
      const message: Message = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        content: body,
        timestamp: new Date(),
        senderId: conversationId, // received: sender is the contact's Null ID
        status: 'read',
        attachment,
      }
      const isActive = state.activeConversationId === conversationId
      return {
        messages: {
          ...state.messages,
          [conversationId]: [...existingMessages, message],
        },
        conversations: state.conversations.map(conv =>
          conv.id === conversationId
            ? {
                ...conv,
                lastMessage: attachment
                  ? `${attachment.mime.startsWith('image/') ? '📷' : '📎'} ${attachment.name}`
                  : body,
                lastMessageTimestamp: message.timestamp,
                unreadCount: isActive ? 0 : conv.unreadCount + 1,
              }
            : conv
        ),
      }
    })
    get().persist()
  },

  checkContactsOnlineStatus: async () => {
    const api = getEvaAPI()
    if (!api) return

    try {
      const result = await api.checkContactStatus()
      // Result should be an array of { nullId, isOnline }
      if (Array.isArray(result)) {
        for (const { nullId, isOnline } of result) {
          get().updateContactOnlineStatus(nullId, isOnline)
        }
      }
    } catch (error) {
      console.error('Failed to check contact status:', error)
    }
  },

  // Periodic relay poll - moved into this store scope for proper debounce/backoff tracking
  loadMessages: async () => {
    const api = getEvaAPI()
    if (!api) return

    let raw: unknown
    try {
      raw = await api.read(true)
    } catch (error) {
      console.error('Failed to read messages:', error)
      // Do not throw - polling should be resilient
      return
    }

    // When called with `true`, the IPC layer returns an array of
    // { from: nullId, text } objects (parsed from `add read --json`).
    if (!Array.isArray(raw)) return
    const incoming = raw as Array<{ from: string; text: string }>
    if (incoming.length === 0) return

    const state = get()
    const myId = state.myId
    for (const { from, text } of incoming) {
      // Never create a conversation / show a message from our own Null ID.
      // Self-echoes can arrive via the relay round-trip.
      if (myId && from === myId) continue

      // Dedupe key: for attachments, fold in the name+size so two different
      // files from the same sender are not treated as one repeat; for plain text use content.
      const dedupeContent = text || ''
      const key = incomingKey(from, dedupeContent)
      if (seenIncoming.has(key)) continue

      seenIncoming.add(key)

      // Ensure a conversation exists for the sender (creates one on first message).
      const exists = state.conversations.some(c => c.id === from)
      if (!exists) {
        state.addConversation({
          id: from,
          name: from,
          avatarUrl: generateInitialsAvatar(from),
          lastMessage: '',
          lastMessageTimestamp: new Date(),
          unreadCount: 0,
          isOnline: false,
          isGroup: false,
        })
      }
      get().addIncomingMessage(from, text)
    }
  },

  // --- Persistence: survive app restart ---
  // Sent/received messages are kept in localStorage so a stop/restart of the
  // desktop UI does not discard the conversation history. Relay `read` only
  // returns *received* mail, so without this, sent messages were lost on reload.
  persist: () => {
    try {
      const { conversations, messages } = get()
      // Privacy: never write attachment base64 payloads to plaintext
      // localStorage. Strip the `data` field but keep name/mime/size so the
      // conversation list still shows "📷 name" after reload. The actual file
      // bytes are regenerated from the relay/peer on the next live read.
      const sanitize = (m: Message): Message =>
        m.attachment ? { ...m, attachment: { ...m.attachment, data: '' } } : m
      const safeMessages: Record<string, Message[]> = {}
      for (const [id, list] of Object.entries(messages)) {
        safeMessages[id] = (list || []).map(sanitize)
      }
      localStorage.setItem(STORE_KEY, JSON.stringify({ conversations, messages: safeMessages }))
    } catch {
      /* storage full / unavailable — non-fatal */
    }
  },

  hydrate: () => {
    try {
      const raw = localStorage.getItem(STORE_KEY)
      if (!raw) return
      const saved = JSON.parse(raw) as {
        conversations: Conversation[]
        messages: Record<string, Message[]>
      }
      // Repair Date objects (JSON serializes them to strings).
      const fix = (m: Message): Message => ({ ...m, timestamp: new Date(m.timestamp) })
      const messages: Record<string, Message[]> = {}
      for (const [id, list] of Object.entries(saved.messages || {})) {
        messages[id] = (list || []).map(fix)
        // Re-seed the incoming dedupe set so reloads don't re-show old mail.
        for (const m of messages[id]) {
          if (m.senderId === 'me') continue
          const dedupeContent = m.attachment
            ? `\u0000${m.attachment.name}\u0000${m.attachment.size}`
            : m.content
          seenIncoming.add(incomingKey(m.senderId, dedupeContent))
        }
      }
      // Restore BOTH conversations and messages from localStorage.
      // Conversations (contacts) are persisted so they survive app restarts
      // without requiring CLI re-authentication.
      const conversations = (saved.conversations || []).map(c => ({
        ...c,
        lastMessageTimestamp: new Date(c.lastMessageTimestamp || Date.now()),
      }))
      set({ conversations, messages })
    } catch {
      /* corrupt state -- ignore */
    }
  },

  initialize: async () => {
    console.log('[chatStore] initialize() called')
    // Guard against re-entrant / concurrent calls (App.tsx triggers it both
    // from onUnlock and the 'ready' useEffect, producing a double-invoke).
    if (get()._initializing) {
      console.log('[chatStore] initialize() already in progress — skipping duplicate')
      return
    }
    set({ _initializing: true })
    const api = getEvaAPI()
    if (!api) {
      console.warn('[chatStore] Add API not available (running in browser?)')
      return
    }
    // `getMyId()` can transiently throw "Another add instance is already
    // running" if a stale CLI process still holds the singleton pid lock
    // (e.g. an orphaned listener from a crashed run, or a concurrent command).
    // Retry a few times with a short backoff before giving up — a lock error
    // must NEVER be confused with "no identity" (which would wrongly offer to
    // wipe and recreate the vault via createIdentity).
    const readIdentity = async (): Promise<{ id: string; fingerprint: string } | null> => {
      for (let attempt = 1; attempt <= 5; attempt++) {
        try {
          console.log(`[chatStore] readIdentity attempt ${attempt}`)
          return await api.getMyId()
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err)
          if (msg.includes('already running') && attempt < 5) {
            console.warn(`[chatStore] getMyId blocked by lock (attempt ${attempt}/5), retrying...`)
            await new Promise(r => setTimeout(r, 600))
            continue
          }
          throw err
        }
      }
      throw new Error('getMyId: exceeded retry attempts')
    }

    try {
      console.log('[chatStore] reading identity...')
      const identity = await readIdentity()
      if (!identity?.id) {
        // Genuinely no identity — let the UI prompt to create one.
        console.log('[chatStore] no identity found')
        set({ isAuthenticated: false })
        return
      }
      console.log('[chatStore] identity found:', identity.id)
      set({ myId: identity.id, myFingerprint: identity.fingerprint, isAuthenticated: true })

      get().hydrate()

      // Register with all known bootstrap nodes in the background (fire-and-forget).
      // This refreshes our presence/cert + our freshly-advertised listener
      // address on the bootstrap network. Failures are non-fatal (bootstrap
      // nodes temporarily unreachable).
      api
        .registerAllBootstraps()
        .then(() => console.log('[chatStore] register-all-bootstraps completed'))
        .catch((err: unknown) => console.warn('[chatStore] register-all-bootstraps failed:', err))

      // Load existing message history (read-only `add read`). This runs BEFORE
      // startListen on purpose: `add listen` holds an exclusive SQLite write
      // lock on ~/.add/messages.db, and a concurrent `add read` would block on
      // that lock. Reading first (listener not yet up) avoids the deadlock and
      // guarantees the UI shows the ID immediately even if the listener is slow.
      try {
        await get().loadMessages()
        console.log('[chatStore] initial message load complete')
      } catch (err: unknown) {
        console.warn('[chatStore] initial message load failed (non-fatal):', err)
      }

      // Always start the P2P listener after identity + history are loaded, so
      // inbound messages arrive without requiring a manual toggle. The listener
      // is started LAST so it can never wedge the identity/history load above.
      try {
        await api.startListen()
        set({ listenRunning: true })
        console.log('[chatStore] Auto-started P2P listener on unlock')
      } catch (err) {
        console.error('[chatStore] Failed to auto-start listener:', err)
      }
    } catch (err) {
      console.error('[chatStore] initialize failed:', err)
      // Only mark unauthenticated if we never actually got an identity.
      // A failure in loadMessages/startListen (network, listener) must NOT
      // wipe a successfully-loaded identity — that would hide the ID and
      // collapse the Settings menu (gated on isAuthenticated).
      if (!get().myId) {
        set({ isAuthenticated: false })
      }
    } finally {
      set({ _initializing: false })
    }
    },

  loadContacts: async () => {
    const api = getEvaAPI()
    if (!api) return

    try {
      const [contacts, aliases] = await Promise.all([api.contacts(), api.aliases()])
      const { addConversation } = get()

      // Build alias map for display names
      const aliasMap = new Map<string, string>(aliases.map((a: { alias: string; nullId: string }) => [a.nullId, a.alias]))

      // Only the user's real contacts populate the list — start clean, no
      // injected default entries.
      contacts.forEach((contact: { nullId: string; fingerprint: string }) =>
        addConversation({
          id: contact.nullId,
          name: aliasMap.get(contact.nullId) || contact.nullId,
          fingerprint: contact.fingerprint,
          avatarUrl: generateInitialsAvatar(contact.nullId),
          lastMessage: '',
          lastMessageTimestamp: new Date(),
          unreadCount: 0,
          isOnline: false,
          isGroup: false,
        })
      )
    } catch (error) {
      console.error('Failed to load contacts:', error)
    }
  },

  sendMessage: async (content: string, ttl?: string) => {
    const { activeConversationId, addMessage } = get()
    const api = getEvaAPI()
    if (!activeConversationId || !api) return

    // Track content to prevent relay echo duplicates
    markSent(content)

    // Parse attachment for storage purposes
    const parsed = parseAttachment(content)
    const body = parsed?.meta ? '' : content

    // Add message immediately to chat display (will show as sending)
    const message: Message = {
      id: Date.now().toString(),
      content: body,
      timestamp: new Date(),
      senderId: 'me',
      status: 'sending',
      ttl,
      attachment: parsed?.meta,
    }
    addMessage(activeConversationId, message)

    try {
      await api.send(activeConversationId, content, ttl)
    } catch (error) {
      console.error('Failed to send message:', error)
    }
  },

  clearMessages: (conversationId: string) =>
    set(state => {
      const newMessages = { ...state.messages }
      delete newMessages[conversationId]
      return { messages: newMessages }
    }),

  deleteConversation: (nullId: string) =>
    set(state => ({
      conversations: state.conversations.filter(c => c.id !== nullId),
    })),

  checkListenStatus: async () => {
    const api = getEvaAPI()
    if (!api) return
    try {
      const status = await api.listenStatus()
      set({ listenRunning: status.running })
    } catch (err) {
      console.error('Check listen status failed:', err)
    }
  },

  startListen: async () => {
    const api = getEvaAPI()
    if (!api) return
    try {
      await api.startListen()
      set({ listenRunning: true })
    } catch (err) {
      console.error('Start listen failed:', err)
    }
  },

  stopListen: async () => {
    const api = getEvaAPI()
    if (!api) return
    try {
      await api.stopListen()
      set({ listenRunning: false })
    } catch (err) {
      console.error('Stop listen failed:', err)
    }
  },

  toggleListen: async () => {
    const state = get()
    // Debounce: ignore clicks for 3s after the last toggle so rapid tapping
    // doesn't thrash the listener start/stop.
    const now = Date.now()
    if (state._lastToggleAt && now - state._lastToggleAt < 3000) return
    set({ _lastToggleAt: now })

    if (state.listenRunning) {
      await get().stopListen()
    } else {
      await get().startListen()
    }
  },

  // Passphrase is stored in memory via main process (never persisted to disk)
  setPassphrase: (passphrase: string) => {
    const api = getEvaAPI()
    if (api) {
      void api.setPassphrase(passphrase)
    }
  },
  storeSetPassphrase: (passphrase: string) => {
    const api = getEvaAPI()
    if (api) {
      void api.setPassphrase(passphrase)
    }
  },
  submitPassphrase: (passphrase: string) => {
    const api = getEvaAPI()
    if (api) {
      return api.submitPassphrase(passphrase)
    }
    return Promise.reject(new Error('IPC API not available'))
  },
  clearPassphrase: () => {
    const api = getEvaAPI()
    if (api) {
      void api.clearPassphrase()
    }
  },
}))
