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

/** Individual message bubble component */
import type { Message } from '../../types'
import { useState } from 'react'

interface MessageBubbleProps {
  message: Message
  isOutgoing: boolean
}

function MessageBubble({ message, isOutgoing }: MessageBubbleProps) {
  const [showTimestamp, setShowTimestamp] = useState(false)

  const formatTime = (date: Date | string | number) => {
    // Tolerate deserialized timestamps (plain strings from localStorage).
    const d = date instanceof Date ? date : new Date(date)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  const getStatusIcon = () => {
    if (!isOutgoing) return null
    switch (message.status) {
      case 'sending':
        return (
          <svg className="h-3 w-3 text-gray-400" viewBox="0 0 16 16">
            <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="2" fill="none" />
          </svg>
        )
      case 'sent':
        return (
          <svg className="h-3 w-3 text-gray-400" viewBox="0 0 16 16">
            <path d="M4 8l3 3 5-5" stroke="currentColor" strokeWidth="2" fill="none" />
          </svg>
        )
      case 'delivered':
        return (
          <svg className="h-3 w-3 text-gray-400" viewBox="0 0 16 16">
            <path d="M3 8l3 3 7-7" stroke="currentColor" strokeWidth="2" fill="none" />
            <path d="M5 8l2 2 5-5" stroke="currentColor" strokeWidth="2" fill="none" />
          </svg>
        )
      case 'read':
        return (
          <svg className="h-3 w-3 text-primary-500" viewBox="0 0 16 16">
            <path d="M3 8l3 3 7-7" stroke="currentColor" strokeWidth="2" fill="none" />
            <path d="M5 8l2 2 5-5" stroke="currentColor" strokeWidth="2" fill="none" />
          </svg>
        )
      default:
        return null
    }
  }

  return (
    <div
      className={`flex mb-1 ${isOutgoing ? 'justify-end' : 'justify-start'}`}
      onMouseEnter={() => setShowTimestamp(true)}
      onMouseLeave={() => setShowTimestamp(false)}
    >
      <div className="relative">
        <div
          className={`max-w-xs rounded-lg px-3 py-2 ${
            isOutgoing
              ? 'rounded-br-sm bg-color-bubble-sent text-white'
              : 'rounded-bl-sm bg-color-bubble-received text-color-text'
          }`}
        >
          <p className="text-sm">{message.content}</p>
          {showTimestamp && (
            <span
              className={`absolute top-full mt-1 text-xs ${
                isOutgoing ? 'right-0 text-white/80' : 'left-0 text-color-text-secondary'
              }`}
            >
              {formatTime(message.timestamp)}
            </span>
          )}
          {isOutgoing && showTimestamp && <div className="mt-0.5 inline-block">{getStatusIcon()}</div>}
        </div>
      </div>
    </div>
  )
}

export default MessageBubble
