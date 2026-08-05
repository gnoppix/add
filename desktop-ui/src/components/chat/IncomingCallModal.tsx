/**
 * IncomingCallModal - Modal for incoming call with Accept/Decline actions
 */

interface IncomingCallModalProps {
  callId: string
  peerName: string
  peerId: string
  onAccept: () => void
  onDecline: () => void
}

export function IncomingCallModal({ peerName, peerId, onAccept, onDecline }: IncomingCallModalProps) {

  const handleAccept = async () => {
    import('../../services/audioEffects').then(({ callSounds }) => {
      callSounds.stopRingtone()
      callSounds.playCallAccepted()
    })
    onAccept()
  }

  const handleDecline = async () => {
    import('../../services/audioEffects').then(({ callSounds }) => {
      callSounds.stopRingtone()
      callSounds.playCallRejected()
    })
    onDecline()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-full max-w-sm mx-4 rounded-xl bg-white p-6 shadow-2xl dark:bg-gray-800 animate-slide-in">
        {/* Caller info */}
        <div className="text-center mb-6">
          <div className="mx-auto mb-4 w-24 h-24 rounded-full bg-primary-100 flex items-center justify-center">
            <svg className="w-12 h-12 text-primary-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14v7m-3 0h6" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Incoming Call</h2>
          <p className="mt-1 text-gray-600 dark:text-gray-400">{peerName}</p>
          <p className="text-xs text-gray-500 dark:text-gray-500 font-mono">{peerId}</p>
        </div>

        {/* Call status */}
        <div className="mb-6 flex items-center justify-center gap-2">
          <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse" />
          <span className="text-sm text-gray-600 dark:text-gray-400">Ringing...</span>
        </div>

        {/* Action buttons */}
        <div className="flex gap-4">
          <button
            onClick={handleDecline}
            className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-red-500 px-4 py-3 text-white font-medium hover:bg-red-600 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
            Decline
          </button>
          <button
            onClick={handleAccept}
            className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-green-500 px-4 py-3 text-white font-medium hover:bg-green-600 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14v7m-3 0h6" />
            </svg>
            Accept
          </button>
        </div>
      </div>
    </div>
  )
}