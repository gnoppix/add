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
  checkContactsOnlineStatus: () => Promise<void>
  
  initialize: () => Promise<void>
  loadContacts: () => Promise<void>
  sendMessage: (content: string) => Promise<void>
}

// Electron API wrapper
function getEvaAPI(): typeof window.addAPI | null {
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
    if (id) get().markAsRead(id)
  },

  addConversation: (conversation) =>
    set((state) => ({
      conversations: [conversation, ...state.conversations],
    })),

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

  initialize: async () => {
    const api = getEvaAPI()
    if (!api) {
      console.warn('Add API not available (running in browser?)')
      return
    }
    try {
      const identity = await api.getMyId()
      set({ myId: identity.id, myFingerprint: identity.fingerprint, isAuthenticated: !!identity.id })
    } catch (err) {
      set({ isAuthenticated: false })
    }
  },

  loadContacts: async () => {
    const api = getEvaAPI()
    if (!api) return

    try {
      const contacts = await api.contacts()
      const { addConversation } = get()
      
      // Add Reflector Bot as default contact for testing
      const reflectorBot = {
        nullId: 'NN-UFtv-8fHu',
        fingerprint: '3957378550B111F2678DC1B4A58C27B22091D5CF',
        alias: '🤖 Reflector Bot'
      }
      
      // Add reflector if not already in contacts
      const allContacts = contacts.find(c => c.nullId === reflectorBot.nullId) 
        ? contacts 
        : [...contacts, reflectorBot]
      
      allContacts.forEach((contact) =>
        addConversation({
          id: contact.nullId,
          name: contact.alias || contact.nullId,
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

    try {
      await api.send(activeConversationId, content, ttl)
      updateMessageStatus(activeConversationId, message.id, 'sent')
    } catch (error) {
      console.error('Failed to send message:', error)
      updateMessageStatus(activeConversationId, message.id, 'error')
    }
  },
}))