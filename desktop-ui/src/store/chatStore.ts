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

// Dedupe key for incoming relay messages. The relay mailbox is not reliably
// purged (relay_purge depends on ML-DSA-87 keys not present in the GPG build),
// so `add read --json` can return the same messages on every poll. We track
// content seen this session so the UI never shows duplicates.
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
  
  initialize: () => Promise<void>
  loadContacts: () => Promise<void>
  sendMessage: (content: string) => Promise<void>
}

// Electron API wrapper
export function getEvaAPI(): typeof window.addAPI | null {
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

  setActiveConversation: (id) => {
    set({ activeConversationId: id })
    if (id) {
      get().markAsRead(id)
      // Pull any messages waiting on the relay for this (and other) conversations.
      get().loadMessages()
    }
  },

  addConversation: (conversation) => {
    // Never add our own Null ID as a contact (self-echo from relay/reflector).
    const myId = get().myId
    if (myId && conversation.id === myId) return
    set((state) => {
      // Idempotent: don't create a second entry for the same contact id.
      if (state.conversations.some((c) => c.id === conversation.id)) {
        return {
          conversations: state.conversations.map((c) =>
            c.id === conversation.id ? { ...c, ...conversation } : c
          ),
        }
      }
      const next = { conversations: [conversation, ...state.conversations] }
      get().persist()
      return next
    })
  },

  addMessage: (conversationId, message) =>
    set((state) => {
      const existingMessages = state.messages[conversationId] || []
      return {
        messages: {
          ...state.messages,
          [conversationId]: [...existingMessages, message],
        },
        conversations: state.conversations.map((conv) =>
          conv.id === conversationId
            ? { ...conv, lastMessage: message.content, lastMessageTimestamp: message.timestamp }
            : conv
        ),
      }
    }),

  updateMessageStatus: (conversationId, messageId, status) =>
    set((state) => ({
      messages: {
        ...state.messages,
        [conversationId]: (state.messages[conversationId] || []).map((msg) =>
          msg.id === messageId ? { ...msg, status } : msg
        ),
      },
    })),

  markAsRead: (conversationId) =>
    set((state) => ({
      conversations: state.conversations.map((conv) =>
        conv.id === conversationId ? { ...conv, unreadCount: 0 } : conv
      ),
    })),

  setSearchQuery: (query) => set({ searchQuery: query }),

  getFilteredConversations: () => {
    const { conversations, searchQuery } = get()
    if (!searchQuery) return conversations
    return conversations.filter((conv) =>
      conv.name.toLowerCase().includes(searchQuery.toLowerCase())
    )
  },

  updateContactOnlineStatus: (nullId: string, isOnline: boolean) =>
    set((state) => ({
      conversations: state.conversations.map((conv) =>
        conv.id === nullId ? { ...conv, isOnline } : conv
      ),
    })),

  renameAlias: (nullId: string, alias: string) =>
    set((state) => ({
      conversations: state.conversations.map((conv) =>
        conv.id === nullId ? { ...conv, name: alias } : conv
      ),
    })),

  addIncomingMessage: (conversationId: string, content: string) => {
    // Dedupe: the relay mailbox may return the same message on every poll
    // (relay_purge is ineffective in the GPG build), so skip repeats.
    const key = incomingKey(conversationId, content)
    if (seenIncoming.has(key)) return
    seenIncoming.add(key)

    set((state) => {
      const existingMessages = state.messages[conversationId] || []
      const message: Message = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
        content,
        timestamp: new Date(),
        senderId: conversationId, // received: sender is the contact's Null ID
        status: 'read',
      }
      const isActive = state.activeConversationId === conversationId
      return {
        messages: {
          ...state.messages,
          [conversationId]: [...existingMessages, message],
        },
        conversations: state.conversations.map((conv) =>
          conv.id === conversationId
            ? {
                ...conv,
                lastMessage: content,
                lastMessageTimestamp: message.timestamp,
                unreadCount: isActive ? 0 : conv.unreadCount + 1,
              }
            : conv
        ),
      }
      get().persist()
    })
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

  loadMessages: async () => {
    const api = getEvaAPI()
    if (!api) return

    let raw: unknown
    try {
      raw = await api.read(true)
    } catch (error) {
      console.error('Failed to read messages:', error)
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
      // Self-echoes can arrive via the reflector or relay round-trip.
      if (myId && from === myId) continue
      // Ensure a conversation exists for the sender (creates one on first message).
      const exists = state.conversations.some((c) => c.id === from)
      if (!exists) {
        state.addConversation({
          id: from,
          name: from,
          avatarUrl: `https://i.pravatar.cc/150?u=${from}`,
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
      localStorage.setItem(STORE_KEY, JSON.stringify({ conversations, messages }))
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
          if (m.senderId !== 'me') seenIncoming.add(incomingKey(m.senderId, m.content))
        }
      }
      // Merge persisted conversations with any already-loaded ones (e.g. contacts
      // loaded by loadContacts) so neither source clobbers the other.
      const existing = get().conversations
      const myId = get().myId
      const merged = existing.slice()
      for (const c of saved.conversations || []) {
        // Never restore our own Null ID as a contact (a stale self-contact
        // may linger in localStorage from before this fix).
        if (myId && c.id === myId) continue
        // Repair Date (JSON serializes Dates to strings) so the
        // sidebar timestamp render doesn't throw on restart.
        const fixed = { ...c, lastMessageTimestamp: c.lastMessageTimestamp ? new Date(c.lastMessageTimestamp) : c.lastMessageTimestamp }
        if (!merged.some((m) => m.id === c.id)) merged.push(fixed)
      }
      set({ conversations: merged, messages })
    } catch {
      /* corrupt state — ignore */
    }
  },

  initialize: async () => {
    const api = getEvaAPI()
    if (!api) {
      console.warn('Add API not available (running in browser?)')
      return
    }
    try {
      const identity = await api.getMyId()
      set({ myId: identity.id, myFingerprint: identity.fingerprint, isAuthenticated: !!identity.id })
      get().hydrate()
    } catch (err) {
      set({ isAuthenticated: false })
    }
  },

  loadContacts: async () => {
    const api = getEvaAPI()
    if (!api) return

    try {
      const [contacts, aliases] = await Promise.all([api.contacts(), api.aliases()])
      const { addConversation } = get()
      
      // Build alias map for display names
      const aliasMap = new Map(aliases.map(a => [a.nullId, a.alias]))
      
      // Add Reflector Bot as default contact (ensures NN-UFtv-8fHu exists)
      const reflectorBot = {
        nullId: 'NN-UFtv-8fHu',
        fingerprint: '3957378550B111F2678DC1B4A58C27B22091D5CF',
      }
      
      // Merge contacts with reflector, using aliases for display names
      const allContacts = contacts.find(c => c.nullId === reflectorBot.nullId) 
        ? contacts 
        : [...contacts, reflectorBot]
      
      allContacts.forEach((contact) =>
        addConversation({
          id: contact.nullId,
          name: aliasMap.get(contact.nullId) || contact.nullId,
          avatarUrl: `https://i.pravatar.cc/150?u=${contact.nullId}`,
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
    const { activeConversationId, addMessage, updateMessageStatus } = get()
    const api = getEvaAPI()
    if (!activeConversationId || !api) return

    const message: Message = {
      id: Date.now().toString(),
      content,
      timestamp: new Date(),
      senderId: 'me',
      status: 'sending',
      ttl,
    }

    addMessage(activeConversationId, message)
      get().persist()

    try {
      const result = await api.send(activeConversationId, content, ttl)
      updateMessageStatus(activeConversationId, message.id, 'sent')
      // Reflector / loopback peers bounce the message back as an "Echo: ..." line.
      // Surface it as an incoming message in this conversation.
      if (typeof result === 'string') {
        const m = result.match(/^Echo: (.*)$/m)
        if (m) {
          get().addIncomingMessage(activeConversationId, m[1])
        }
      }
    } catch (error) {
      console.error('Failed to send message:', error)
      updateMessageStatus(activeConversationId, message.id, 'error')
    }
  },
}))