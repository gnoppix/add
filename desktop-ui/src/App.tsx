/** Main App layout with split-pane structure */
import { useEffect, useState } from 'react'
import { generateInitialsAvatar } from './lib/identicon'
import Sidebar from './components/sidebar/Sidebar'
import ChatPane from './components/chat/ChatPane'
import { useChatStore, getEvaAPI } from './store/chatStore'
import { StartupUnlockDialog } from './components/vault/StartupUnlockDialog'

function App() {
  const { initialize, loadMessages } = useChatStore()
  const [isUnlocked, setIsUnlocked] = useState(false)

  // Initialize on mount (after unlock)
  useEffect(() => {
    if (isUnlocked) {
      initialize()
    }
  }, [initialize, isUnlocked])

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