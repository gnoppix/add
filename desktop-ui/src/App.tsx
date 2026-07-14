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

/** Main App layout with split-pane structure */
import { useEffect } from 'react'
import { generateInitialsAvatar } from './lib/identicon'
import Sidebar from './components/sidebar/Sidebar'
import ChatPane from './components/chat/ChatPane'
import { useChatStore, getEvaAPI } from './store/chatStore'
import { useThemeStore } from './store/themeStore'

function App() {
  const { initialize, loadContacts, checkContactsOnlineStatus, loadMessages } = useChatStore()
  const { theme } = useThemeStore()

  // Initialize on mount
  useEffect(() => {
    initialize()
  }, [initialize])

  // Apply theme on mount
  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark')
    } else {
      document.documentElement.classList.remove('dark')
    }
  }, [theme])

  // Load contacts when authenticated
  useEffect(() => {
    loadContacts()
  }, [loadContacts])

  // Periodic online status check (every 30 seconds)
  useEffect(() => {
    const interval = setInterval(() => {
      checkContactsOnlineStatus()
    }, 30000)
    return () => clearInterval(interval)
  }, [checkContactsOnlineStatus])

  // Periodic relay poll: pull messages you've received (every 10 seconds)
  useEffect(() => {
    loadMessages()
    const interval = setInterval(() => {
      loadMessages()
    }, 10000)
    return () => clearInterval(interval)
  }, [loadMessages])

  // Live P2P inbound messages from the background listener (e.g. reflector
  // echo). The main process parses the listener stdout and pushes each
  // message here; we attribute it to the sender conversation and insert it.
  useEffect(() => {
    const api = getEvaAPI()
    if (!api?.on) return
    const off = api.on('add-incoming-message', (msg: { from: string; text: string }) => {
      const { from, text } = msg
      const state = useChatStore.getState()
      const myId = state.myId
      if (myId && from === myId) return // never show self-echoes
      if (!state.conversations.some((c) => c.id === from)) {
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
      state.addIncomingMessage(from, text)
    })
    return off
  }, [])

  return (
    <div className="flex h-screen w-full overflow-hidden bg-light-background dark:bg-dark-background">
      <Sidebar />
      <ChatPane />
    </div>
  )
}

export default App