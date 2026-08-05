/** Main App layout with split-pane structure */
import { useEffect, useState, useRef } from 'react'
import { generateInitialsAvatar } from './lib/identicon'
import Sidebar from './components/sidebar/Sidebar'
import ChatPane from './components/chat/ChatPane'
import { useChatStore, getEvaAPI } from './store/chatStore'
import { StartupUnlockDialog } from './components/vault/StartupUnlockDialog'
import { CreateIdentityDialog } from './components/vault/CreateIdentityDialog'
import { ToastProvider } from './components/common/Toast'

type AppState = 'checking' | 'createIdentity' | 'unlock' | 'ready'

function App() {
  const { initialize, loadMessages, isAuthenticated } = useChatStore()
  const [appState, setAppState] = useState<AppState>('checking')
  // Skeleton UI state: shows main layout while checking identity in background
  const [showSkeleton, setShowSkeleton] = useState(true)

  // Check identity on mount - return early to show skeleton immediately
  useEffect(() => {
    // Only check if not yet authenticated
    if (isAuthenticated) return
    const checkIdentity = async () => {
      const api = getEvaAPI()
      if (!api) {
        setAppState('createIdentity')
        setShowSkeleton(false)
        return
      }
      try {
        // First check if ~/.add identity files exist
        const existsResult = await api.checkIdentityExists?.()
        const identityExists = existsResult?.exists === true

        if (identityExists) {
          // Identity files exist - show unlock dialog
          setAppState('unlock')
        } else {
          // No identity files - create new identity
          setAppState('createIdentity')
        }
      } catch {
        // If check fails, fall back to getMyId
        try {
          const identity = await api.getMyId()
          if (identity.id && identity.id.trim() !== '') {
            setAppState('unlock')
          } else {
            setAppState('createIdentity')
          }
        } catch {
          setAppState('createIdentity')
        }
      }

      // Allow skeleton to show briefly, then transition (simplified - no cleanup needed)
      setTimeout(() => setShowSkeleton(false), 300)
    }
    checkIdentity()
  }, [isAuthenticated])

  // Initialize on ready
  useEffect(() => {
    if (appState === 'ready') {
      // initialize() is now called with passphrase from StartupUnlockDialog.onUnlock
      // No need to call it here again
    }
  }, [initialize, appState])

  // Periodic relay poll with backoff for efficiency:
  // start after a short delay, then poll every 10s. If consecutive polls fail, increase interval up to 30s max.
  const backupMsRef = useRef<number>(10000)
  const intervalIdRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (appState !== 'ready') return

    // Initial poll after short delay for UI render
    const initialTimer = setTimeout(async () => {
      await loadMessages()
        .then(() => {
          backupMsRef.current = 10000
        }) // reset backoff on success
        .catch(() => {})

      // Start interval
      intervalIdRef.current = setInterval(async () => {
        await loadMessages()
          .then(() => {
            backupMsRef.current = 10000
          })
          .catch(() => {
            backupMsRef.current = Math.min(backupMsRef.current * 1.5, 30000) // exponential backoff up to 30s
          })
      }, backupMsRef.current)
    }, 800) // slight initial delay for UI render

    return () => {
      if (initialTimer) clearTimeout(initialTimer as unknown as number)
      if (intervalIdRef.current)
        clearInterval(intervalIdRef.current as ReturnType<typeof setInterval>)
    }
  }, [loadMessages, appState])

  // Live P2P inbound messages
  useEffect(() => {
    if (appState !== 'ready') return
    const api = getEvaAPI()
    if (!api?.on) return
    const off = api.on('add-incoming-message', (msg: { from: string; text: string }) => {
      console.log('[App] >>>>>>>>>>>>>>> received add-incoming-message IPC:', msg)
      // Avoid our own messages echoing back via relay
      const state = useChatStore.getState()
      const myId = state.myId
      if (myId && msg.from === myId) {
        console.log('[App] ignoring own message echo')
        return
      }
      console.log('[App] adding incoming message from:', msg.from)
      if (!state.conversations.some(c => c.id === msg.from)) {
        state.addConversation({
          id: msg.from,
          name: msg.from,
          avatarUrl: generateInitialsAvatar(msg.from),
          lastMessage: '',
          lastMessageTimestamp: new Date(),
          unreadCount: 0,
          isOnline: false,
          isGroup: false,
        })
      }
      state.addIncomingMessage(msg.from, msg.text)
    })
    return off
  }, [appState])

  return (
    <ToastProvider>
      {showSkeleton && appState === 'checking' && (
        <div
          className="flex h-screen w-full overflow-hidden"
          style={{ backgroundColor: 'var(--color-background)' }}
        >
          {/* Skeleton Sidebar */}
          <div className="w-64 bg-gray-100 dark:bg-gray-800 border-r border-gray-300 dark:border-gray-700">
            <div className="p-4">
              <div className="h-8 w-2/3 bg-gray-300 dark:bg-gray-600 rounded animate-pulse"></div>
            </div>
            <div className="px-2 space-y-1 py-2">
              {[...Array(6)].map((_, i) => (
                <div
                  key={i}
                  className="h-14 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"
                ></div>
              ))}
            </div>
          </div>
          {/* Skeleton ChatPane */}
          <div className="flex-1 flex flex-col bg-white dark:bg-gray-900">
            <div className="h-16 border-b border-gray-300 dark:border-gray-700 flex items-center px-4">
              <div className="h-8 w-48 bg-gray-300 dark:bg-gray-600 rounded animate-pulse"></div>
            </div>
            <div className="flex-1 p-4 space-y-2">
              {[...Array(5)].map((_, i) => {
                const isTall = i % 3 === 0
                const isLeft = i % 2 === 0
                return (
                  <div
                    key={i}
                    className={`${isTall ? 'h-16' : ''} bg-gray-200 dark:bg-gray-700 rounded animate-pulse ${isLeft ? 'ml-4' : 'mr-4'}`}
                  ></div>
                )
              })}
            </div>
            <div className="h-16 border-t border-gray-300 dark:border-gray-700 p-3">
              <div className="h-10 bg-gray-300 dark:bg-gray-600 rounded animate-pulse"></div>
            </div>
          </div>
        </div>
      )}

      {appState === 'createIdentity' && (
        <CreateIdentityDialog onCreated={() => setAppState('ready')} />
      )}

      {appState === 'unlock' && (
        <StartupUnlockDialog onUnlock={(passphrase) => {
          console.log('[App] >>>>>>>>>>>>> onUnlock called with passphrase, length:', passphrase?.length)
          initialize(passphrase)
          setAppState('ready')
        }} />
      )}

      {appState === 'ready' && (
        <div
          className="flex h-screen w-full overflow-hidden"
          style={{ backgroundColor: 'var(--color-background)' }}
        >
          <Sidebar />
          <ChatPane />
        </div>
      )}
    </ToastProvider>
  )
}

export default App