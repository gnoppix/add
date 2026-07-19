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

/**
 * Single conversation thread:
 *  - Incoming messages (from the contact) align LEFT.
 *  - Outgoing messages (from me) align RIGHT.
 * Messages keep their own chronological order and the view auto-scrolls to the
 * newest message at the bottom.
 */
import { useEffect, useRef } from 'react'
import { useChatStore } from '../../store/chatStore'
import MessageBubble from './MessageBubble'

// Outgoing messages are authored by the local user (senderId === 'me').
const OUTGOING_ID = 'me'

function MessageList() {
  const { activeConversationId, messages } = useChatStore()

  const scrollRef = useRef<HTMLDivElement>(null)

  const conversationMessages = activeConversationId ? messages[activeConversationId] || [] : []

  // Auto-scroll to the bottom as new messages arrive.
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [conversationMessages])

  if (conversationMessages.length === 0) {
    return (
      <div className="flex h-full items-center justify-center bg-light-background dark:bg-dark-background">
        <p className="text-sm text-gray-500 dark:text-gray-400">No messages yet. Start the conversation!</p>
      </div>
    )
  }

  return (
    <div
      ref={scrollRef}
      className="flex flex-1 flex-col gap-1 overflow-y-auto p-4 bg-light-background dark:bg-dark-background"
    >
      {conversationMessages.map((message) => (
        <MessageBubble
          key={message.id}
          message={message}
          isOutgoing={message.senderId === OUTGOING_ID}
        />
      ))}
    </div>
  )
}

export default MessageList
