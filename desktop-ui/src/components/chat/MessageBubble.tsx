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
import { formatBytes } from '../../lib/attachment'

interface MessageBubbleProps {
  message: Message
  isOutgoing: boolean
}

// Build a downloadable object URL from a base64 attachment and trigger a save.
function downloadAttachment(name: string, mime: string, data: string) {
  try {
    const clean = data.includes(',') ? data.slice(data.indexOf(',') + 1) : data
    const bin = atob(clean)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    const blob = new Blob([bytes], { type: mime || 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch {
    /* decode/launch failure — non-fatal */
  }
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
          {message.attachment && (
            <button
              type="button"
              onClick={() =>
                downloadAttachment(
                  message.attachment!.name,
                  message.attachment!.mime,
                  message.attachment!.data
                )
              }
              className={`mt-1 flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm ${
                isOutgoing ? 'bg-white/15 hover:bg-white/25' : 'bg-black/5 hover:bg-black/10'
              }`}
              title={`Download ${message.attachment.name}`}
            >
              <svg className="h-5 w-5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 10v6m0 0l-3-3m3 3l3-3M5 4h14a1 1 0 011 1v14a1 1 0 01-1 1H5a1 1 0 01-1-1V5a1 1 0 011-1z"
                />
              </svg>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{message.attachment.name}</span>
                <span className="block text-xs opacity-70">{formatBytes(message.attachment.size)}</span>
              </span>
            </button>
          )}
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
