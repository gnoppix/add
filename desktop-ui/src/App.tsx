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
import Sidebar from './components/sidebar/Sidebar'
import ChatPane from './components/chat/ChatPane'
import { useChatStore } from './store/chatStore'
import { useThemeStore } from './store/themeStore'

function App() {
  const { initialize, loadContacts, checkContactsOnlineStatus } = useChatStore()
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

  return (
    <div className="flex h-screen w-full overflow-hidden bg-light-background dark:bg-dark-background">
      <Sidebar />
      <ChatPane />
    </div>
  )
}

export default App