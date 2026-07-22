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
import React, { useState } from 'react'
import { useChatStore } from '../../store/chatStore'

interface SafetyNumberModalProps {
  nullId: string
  fingerprint: string
  onClose: () => void
}

function SafetyNumberModal({ nullId, fingerprint, onClose }: SafetyNumberModalProps) {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50">
      <div className="w-80 rounded-lg bg-white p-6 shadow-xl">
        <h2 className="mb-4 text-lg font-semibold">Safety Number</h2>
        <div className="space-y-3 text-sm">
          <p>
            <span className="font-medium">Friend&apos;s ID:</span> {nullId}
          </p>
          <p>
            <span className="font-medium">Fingerprint:</span>{' '}
            <span className="font-mono break-all">{fingerprint}</span>
          </p>
        </div>
        <button
          onClick={onClose}
          className="mt-4 rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
        >
          Close
        </button>
      </div>
    </div>
  )
}

function ChatHeader() {
  const { conversations, activeConversationId, clearMessages, deleteConversation } = useChatStore()
  const [showMenu, setShowMenu] = useState(false)
  const [showSafetyNumbers, setShowSafetyNumbers] = useState(false)
  const [mutedContacts, setMutedContacts] = useState<Set<string>>(new Set())

  const activeConversation = conversations.find((c) => c.id === activeConversationId)

  if (!activeConversation) return null

  const handleMuteToggle = () => {
    setMutedContacts((prev) => {
      const next = new Set(prev)
      if (next.has(activeConversation.id)) {
        next.delete(activeConversation.id)
      } else {
        next.add(activeConversation.id)
      }
      return next
    })
    setShowMenu(false)
  }

  const handleDelete = () => {
    if (activeConversation) {
      clearMessages(activeConversation.id)
    }
    setShowMenu(false)
  }

  return (
    <>
      <header className="flex h-14 items-center justify-between border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-dark-sidebar px-4">
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

        <div className="relative z-50">
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
            <div className="absolute right-0 mt-1 w-56 rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-dark-sidebar py-1 shadow-lg z-50">
              <button
                onClick={() => setShowSafetyNumbers(true)}
                className="w-full px-3 py-2 text-left text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800"
              >
                View Safety Numbers
              </button>
              <label className="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer">
                <input
                  type="checkbox"
                  checked={mutedContacts.has(activeConversation.id)}
                  onChange={handleMuteToggle}
                  className="h-4 w-4"
                />
                Mute Notifications
              </label>
              <button
                onClick={handleDelete}
                className="w-full px-3 py-2 text-left text-sm text-red-600 dark:text-red-400 hover:bg-gray-50 dark:hover:bg-gray-800"
              >
                Delete Conversation
              </button>
            </div>
          )}
        </div>
      </header>

      {showSafetyNumbers && (
        <SafetyNumberModal
          nullId={activeConversation.id}
          fingerprint={activeConversation.fingerprint || 'Unknown'}
          onClose={() => setShowSafetyNumbers(false)}
        />
      )}
    </>
  )
}

export default ChatHeader