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
 * Split-screen message list:
 *  - Left column  → messages I send (outgoing)
 *  - Right column → messages I receive (incoming)
 * Each column keeps its own chronological order and auto-scrolls to bottom.
 */
import { useEffect, useRef } from 'react'
import { useChatStore } from '../../store/chatStore'
import MessageBubble from './MessageBubble'

// Outgoing messages are authored by the local user (senderId === 'me').
const OUTGOING_ID = 'me'

function MessageList() {
  const { activeConversationId, messages } = useChatStore()

  const sentRef = useRef<HTMLDivElement>(null)
  const receivedRef = useRef<HTMLDivElement>(null)

  const conversationMessages = activeConversationId ? messages[activeConversationId] || [] : []

  const sent = conversationMessages.filter((m) => m.senderId === OUTGOING_ID)
  const received = conversationMessages.filter((m) => m.senderId !== OUTGOING_ID)

  // Auto-scroll both columns to the bottom when their content changes.
  useEffect(() => {
    if (sentRef.current) sentRef.current.scrollTop = sentRef.current.scrollHeight
  }, [sent])
  useEffect(() => {
    if (receivedRef.current) receivedRef.current.scrollTop = receivedRef.current.scrollHeight
  }, [received])

  if (conversationMessages.length === 0) {
    return (
      <div className="flex h-full items-center justify-center bg-light-background dark:bg-dark-background">
        <p className="text-sm text-gray-500 dark:text-gray-400">No messages yet. Start the conversation!</p>
      </div>
    )
  }

  const Column = ({
    title,
    list,
    refEl,
  }: {
    title: string
    list: typeof conversationMessages
    refEl: React.RefObject<HTMLDivElement>
  }) => (
    <div className="flex h-full min-w-0 flex-1 flex-col border-x border-gray-200 dark:border-gray-700">
      <div className="border-b border-gray-200 bg-gray-50 px-3 py-1.5 text-xs font-medium text-gray-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-400">
        {title} ({list.length})
      </div>
      <div ref={refEl} className="flex-1 overflow-y-auto p-4 bg-light-background dark:bg-dark-background">
        {list.length === 0 ? (
          <p className="text-xs text-gray-400 dark:text-gray-500">—</p>
        ) : (
          list.map((message) => (
            <MessageBubble
              key={message.id}
              message={message}
              isOutgoing={message.senderId === OUTGOING_ID}
            />
          ))
        )}
      </div>
    </div>
  )

  return (
    <div className="flex flex-1 overflow-hidden">
      <Column title="Sent" list={sent} refEl={sentRef} />
      <Column title="Received" list={received} refEl={receivedRef} />
    </div>
  )
}

export default MessageList
