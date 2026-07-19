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

/** Main chat pane container */
import { useChatStore } from '../../store/chatStore'
import EmptyState from './EmptyState'
import ChatHeader from './ChatHeader'
import MessageList from './MessageList'
import MessageInput from './MessageInput'

function ChatPane() {
  const { activeConversationId } = useChatStore()

  return (
    <main className="flex h-full w-[70%] min-w-[400px] flex-col bg-light-background dark:bg-dark-background">
      {activeConversationId ? (
        <>
          <ChatHeader />
          <MessageList />
          <MessageInput />
        </>
      ) : (
        <EmptyState />
      )}
    </main>
  )
}

export default ChatPane
