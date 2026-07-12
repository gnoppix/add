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

/** Individual conversation row in the sidebar */
import { useState } from 'react'
import type { Conversation } from '../../types'
import { useChatStore } from '../../store/chatStore'

interface ConversationRowProps {
  conversation: Conversation
}

function ConversationRow({ conversation }: ConversationRowProps) {
  const { activeConversationId, setActiveConversation, renameAlias } = useChatStore()
  const isActive = activeConversationId === conversation.id
  const isOnline = conversation.isOnline ?? false
  const [showMenu, setShowMenu] = useState(false)
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(conversation.name)
  const [menuPos, setMenuPos] = useState<{ x: number; y: number }>({ x: 0, y: 0 })

  const formatTime = (date?: Date | string | number) => {
    if (!date) return ''
    // Tolerate deserialized timestamps (plain strings from localStorage).
    const d = date instanceof Date ? date : new Date(date)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  const handleContextMenu = (e: React.MouseEvent) => {
    e.preventDefault()
    setMenuPos({ x: e.clientX, y: e.clientY })
    setShowMenu(true)
  }

  const startRename = () => {
    setShowMenu(false)
    setDraft(conversation.name)
    setEditing(true)
  }

  const commitRename = () => {
    const next = draft.trim()
    if (next && next !== conversation.name) {
      renameAlias(conversation.id, next)
      const api = window.addAPI
      if (api) api.alias(next, conversation.id).catch((err) => console.error('Alias update failed:', err))
    }
    setEditing(false)
  }

  if (editing) {
    return (
      <div className="flex w-full items-center gap-3 border-l-2 border-l-primary-500 bg-gray-100 px-3 py-2.5 dark:bg-gray-800">
        <div className="relative flex-shrink-0 w-3 h-3" />
        <div className="relative flex-shrink-0">
          <div className="h-12 w-12 rounded-full bg-gray-300" />
        </div>
        <div className="flex min-w-0 flex-1 flex-col items-start gap-1">
          <input
            autoFocus
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') commitRename()
              if (e.key === 'Escape') setEditing(false)
            }}
            onBlur={commitRename}
            className="w-full rounded border border-primary-500 px-1 py-0.5 text-sm"
          />
        </div>
      </div>
    )
  }

  return (
    <>
      <button
        onClick={() => setActiveConversation(conversation.id)}
        onContextMenu={handleContextMenu}
        className={`flex w-full items-center gap-3 border-l-2 px-3 py-2.5 transition-colors hover:bg-gray-50 dark:hover:bg-gray-800 ${
          isActive ? 'border-l-primary-500 bg-gray-100 dark:bg-gray-800' : 'border-l-transparent'
        }`}
      >
        {/* Online Status Indicator (left side of avatar) */}
        <div className="relative flex-shrink-0 w-3 h-3">
          <span
            className={`absolute left-0 top-1/2 -translate-y-1/2 w-2.5 h-2.5 rounded-full border-2 ${
              isOnline
                ? 'bg-green-500 border-white dark:border-dark-sidebar'
                : 'bg-red-500 border-white dark:border-dark-sidebar'
            }`}
            title={isOnline ? 'Online' : 'Offline'}
          />
        </div>

        {/* Avatar */}
        <div className="relative flex-shrink-0">
          <div className={`h-12 w-12 rounded-full bg-gray-300 ${!isOnline && !conversation.isGroup ? 'grayscale' : ''}`}>
            {conversation.avatarUrl ? (
              <img
                src={conversation.avatarUrl}
                alt={conversation.name}
                className={`h-full w-full rounded-full object-cover ${!isOnline && !conversation.isGroup ? 'grayscale' : ''}`}
              />
            ) : (
              <div className={`flex h-full w-full items-center justify-center text-sm font-medium text-gray-600 dark:text-gray-300 ${!isOnline && !conversation.isGroup ? 'grayscale' : ''}`}>
                {conversation.name.charAt(0)}
              </div>
            )}
          </div>
        </div>

        {/* Content */}
        <div className="flex min-w-0 flex-1 flex-col items-start">
          <div className="flex w-full items-center justify-between">
            <span className="truncate text-sm font-medium text-gray-900 dark:text-white">
              {conversation.name}
            </span>
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {formatTime(conversation.lastMessageTimestamp)}
            </span>
          </div>
          <div className="flex w-full items-center justify-between">
            <span className="truncate text-xs text-gray-500 dark:text-gray-400">
              {conversation.lastMessage || 'No messages yet'}
            </span>
            {conversation.unreadCount > 0 && (
              <span className="flex h-5 min-w-[20px] items-center justify-center rounded-full bg-primary-500 px-1 text-xs font-medium text-white">
                {conversation.unreadCount}
              </span>
            )}
          </div>
        </div>
      </button>

      {/* Right-click context menu */}
      {showMenu && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setShowMenu(false)} />
          <div
            className="fixed z-50 w-44 rounded-lg border border-gray-200 bg-white py-1 shadow-lg dark:border-gray-700 dark:bg-dark-sidebar"
            style={{ top: menuPos.y, left: menuPos.x }}
          >
            <div className="px-3 py-1 text-xs text-gray-400 dark:text-gray-500">
              {conversation.id}
            </div>
            <button
              onClick={startRename}
              className="w-full px-3 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 dark:text-gray-200 dark:hover:bg-gray-800"
            >
              Rename alias
            </button>
          </div>
        </>
      )}
    </>
  )
}

export default ConversationRow
