/** Main App layout with split-pane structure */
import { useEffect, useState } from 'react'
import { generateInitialsAvatar } from './lib/identicon'
import Sidebar from './components/sidebar/Sidebar'
import ChatPane from './components/chat/ChatPane'
import { useChatStore, getEvaAPI } from './store/chatStore'
import { useThemeStore } from './store/themeStore'
import { StartupUnlockDialog } from './components/vault/StartupUnlockDialog'

function App() {
  const { initialize, loadContacts, checkContactsOnlineStatus, loadMessages } = useChatStore()
  const { theme } = useThemeStore()
  const [isUnlocked, setIsUnlocked] = useState(false)

  // The main process handles passphrase dialog at startup.
  // Once the main window is created, the passphrase is already stored in memory.
  useEffect(() => {
    const checkAndInitialize = async () => {
      const api = getEvaAPI()
      if (!api) return
      
      try {
        // Passphrase is already set in main process; this just verifies DB access
        await api.read(false)
        setIsUnlocked(true)
      } catch (e) {
        // If this fails, the main process dialog would have handled it
        setIsUnlocked(false)
      }
    }
    checkAndInitialize()
  }, [])

  // Initialize on mount (after unlock)
  useEffect(() => {
    if (isUnlocked) {
      initialize()
    }
  }, [initialize, isUnlocked])

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
    if (isUnlocked) {
      loadContacts()
    }
  }, [loadContacts, isUnlocked])

  // Online status check: initial probe 5s after mount, then every 27s.
  useEffect(() => {
    if (!isUnlocked) return
    const initial = setTimeout(() => {
      checkContactsOnlineStatus()
    }, 5000)
    const interval = setInterval(() => {
      checkContactsOnlineStatus()
    }, 27000)
    return () => {
      clearTimeout(initial)
      clearInterval(interval)
    }
  }, [checkContactsOnlineStatus, isUnlocked])

  // Periodic relay poll: pull messages you've received (every 10 seconds)
  useEffect(() => {
    if (!isUnlocked) return
    loadMessages()
    const interval = setInterval(() => {
      loadMessages()
    }, 10000)
    return () => clearInterval(interval)
  }, [loadMessages, isUnlocked])

  // Live P2P inbound messages from the background listener. The main process
  // parses the listener stdout and pushes each message here; we attribute it
  // to the sender conversation and insert it.
  useEffect(() => {
    if (!isUnlocked) return
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
  }, [isUnlocked])

  if (!isUnlocked) {
    return (
      <StartupUnlockDialog onUnlock={() => setIsUnlocked(true)} />
    )
  }

  return (
    <div 
      className="flex h-screen w-full overflow-hidden"
      style={{ backgroundColor: 'var(--color-background)' }}
    >
      <Sidebar />
      <ChatPane />
    </div>
  )
}

export default App