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

/** Active chat header with contact info and action menu */
import { useState } from 'react'
import { useChatStore } from '../../store/chatStore'

function ChatHeader() {
  const { conversations, activeConversationId } = useChatStore()
  const [showMenu, setShowMenu] = useState(false)

  const activeConversation = conversations.find((c) => c.id === activeConversationId)

  if (!activeConversation) return null

  return (
    <header className="flex h-14 items-center justify-between border-b border-gray-200 dark:border-gray-700 px-4 bg-white dark:bg-dark-sidebar">
      <div className="flex items-center gap-3">
        <div className="relative h-8 w-8 rounded-full bg-gray-300">
          {activeConversation.avatarUrl ? (
            <img
              src={activeConversation.avatarUrl}
              alt={activeConversation.name}
              className="h-full w-full rounded-full object-cover"
            />
          ) : (
            <span className="flex h-full w-full items-center justify-center text-xs font-medium">
              {activeConversation.name.charAt(0)}
            </span>
          )}
          {activeConversation.isOnline && !activeConversation.isGroup && (
            <span className="absolute bottom-0 right-0 h-2.5 w-2.5 rounded-full border-2 border-white bg-green-500" />
          )}
        </div>
        <div>
          <h2 className="text-sm font-medium text-gray-900 dark:text-white">
            {activeConversation.name}
          </h2>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {activeConversation.isOnline ? 'Online' : 'Last seen recently'}
          </p>
        </div>
      </div>

      <div className="relative">
        <button
          onClick={() => setShowMenu(!showMenu)}
          className="flex h-8 w-8 items-center justify-center rounded-full text-gray-600 dark:text-gray-400 transition-colors hover:bg-gray-100 dark:hover:bg-gray-800"
          aria-label="Conversation Menu"
        >
          <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
            <circle cx="12" cy="5" r="2" />
            <circle cx="12" cy="12" r="2" />
            <circle cx="12" cy="19" r="2" />
          </svg>
        </button>

        {showMenu && (
          <div className="absolute right-0 mt-1 w-56 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-dark-sidebar py-1 shadow-lg">
            <button className="w-full px-3 py-2 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800">
              View Safety Numbers
            </button>
            <button className="w-full px-3 py-2 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800">
              Mute Notifications
            </button>
            <button className="w-full px-3 py-2 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800">
              Clear History
            </button>
            <button className="w-full px-3 py-2 text-left text-sm text-red-600 dark:text-red-400 hover:bg-gray-50 dark:hover:bg-gray-800">
              Delete Conversation
            </button>
          </div>
        )}
      </div>
    </header>
  )
}

export default ChatHeader
