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

/** Scrollable conversation list container */
import { useEffect, useRef } from 'react'
import { useChatStore } from '../../store/chatStore'
import ConversationRow from './ConversationRow'

function ConversationList() {
  const { getFilteredConversations } = useChatStore()
  const conversations = getFilteredConversations()
  const listRef = useRef<HTMLDivElement>(null)

  // Sort: online first (true), then offline (false)
  const sortedConversations = [...conversations].sort((a, b) => {
    const aOnline = a.isOnline ?? false
    const bOnline = b.isOnline ?? false
    if (aOnline && !bOnline) return -1
    if (!aOnline && bOnline) return 1
    return 0
  })

  // Ensure scroll is at top when list mounts
  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = 0
    }
  }, [conversations])

  return (
    <div ref={listRef} className="flex-1 overflow-y-auto bg-white dark:bg-dark-sidebar">
      {sortedConversations.length === 0 ? (
        <div className="flex items-center justify-center py-8 text-sm text-gray-500 dark:text-gray-400">
          No conversations found
        </div>
      ) : (
        sortedConversations.map((conversation) => (
          <ConversationRow key={conversation.id} conversation={conversation} />
        ))
      )}
    </div>
  )
}

export default ConversationList
