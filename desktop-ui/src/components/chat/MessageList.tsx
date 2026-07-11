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

/** Virtualized message list with auto-scroll to bottom */
import { useEffect, useRef, useMemo } from 'react'
import { useChatStore } from '../../store/chatStore'
import MessageBubble from './MessageBubble'

function MessageList() {
  const { activeConversationId, messages } = useChatStore()
  const listRef = useRef<HTMLDivElement>(null)

  // Get current user ID (in real app, this would come from auth)
  const currentUserId = 'current-user'

  const conversationMessages = activeConversationId ? messages[activeConversationId] || [] : []

  // Group messages by date
  const groupedMessages = useMemo(() => {
    const groups: { date: string; messages: typeof conversationMessages }[] = []
    let currentDate = ''
    let currentGroup: typeof conversationMessages = []

    conversationMessages.forEach((msg) => {
      const dateStr = msg.timestamp.toDateString()
      if (dateStr !== currentDate) {
        if (currentGroup.length > 0) {
          groups.push({ date: currentDate, messages: currentGroup })
        }
        currentDate = dateStr
        currentGroup = [msg]
      } else {
        currentGroup.push(msg)
      }
    })

    if (currentGroup.length > 0) {
      groups.push({ date: currentDate, messages: currentGroup })
    }

    return groups
  }, [conversationMessages])

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight
    }
  }, [conversationMessages])

  if (conversationMessages.length === 0) {
    return (
      <div className="flex h-full items-center justify-center bg-light-background dark:bg-dark-background">
        <p className="text-sm text-gray-500 dark:text-gray-400">No messages yet. Start the conversation!</p>
      </div>
    )
  }

  return (
    <div ref={listRef} className="flex-1 overflow-y-auto p-4 bg-light-background dark:bg-dark-background">
      {groupedMessages.map((group) => (
        <div key={group.date} className="mb-4">
          <div className="mb-2 text-center">
            <span className="rounded-full bg-gray-200 dark:bg-gray-700 px-2 py-0.5 text-xs text-gray-600 dark:text-gray-300">
              {group.date}
            </span>
          </div>
          {group.messages.map((message) => (
            <MessageBubble
              key={message.id}
              message={message}
              isOutgoing={message.senderId === currentUserId}
            />
          ))}
        </div>
      ))}
    </div>
  )
}

export default MessageList
