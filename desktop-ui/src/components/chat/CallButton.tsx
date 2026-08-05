/**
 * CallButton - Start Call button for chat header
 */

import { useCallback } from 'react'
import { useCallStore } from '../../store/callStore'

interface CallButtonProps {
  peerId: string
  disabled?: boolean
  className?: string
}

export function CallButton({ peerId, disabled = false, className = '' }: CallButtonProps) {
  const { startCall, isInCall } = useCallStore()

  const handleClick = useCallback(async () => {
    if (disabled || isInCall) return
    try {
      await startCall(peerId)
    } catch (err) {
      console.error('[CallButton] Failed to start call:', err)
    }
  }, [peerId, disabled, isInCall, startCall])

  if (isInCall) {
    return (
      <button
        type="button"
        disabled={true}
        className={`flex h-8 w-8 items-center justify-center rounded-full bg-green-500 text-white transition-colors ${className}`}
        aria-label="On a call"
        title="On a call"
      >
        <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm0-14c-2.21 0-4 1.79-4 4h2c0-1.1.9-2 2-2s2 .9 2 2c0 2-3 1.75-3 5h2c0-2.25 3-2.5 3-5 0-2.21-1.79-4-4-4z" />
        </svg>
      </button>
    )
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      disabled={disabled}
      className={`flex h-8 w-8 items-center justify-center rounded-full transition-colors text-gray-600 hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed ${className}`}
      aria-label="Start voice call"
      title="Start voice call"
    >
      <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth={2}
          d="M7.5 14L18 14m2-8v6a3 3 0 01-3 3H15a3 3 0 01-3-3v-6a3 3 0 013-3h3z"
        />
      </svg>
    </button>
  )
}