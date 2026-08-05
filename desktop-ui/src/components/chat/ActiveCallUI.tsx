/**
 * ActiveCallUI - In-call UI with timer, mute, audio device selection, hangup
 */

import { useEffect, useState, useRef } from 'react'
import { useCallStore, webRTCCalling } from '../../store/callStore'

interface ActiveCallUIProps {
  callId: string
  peerName: string
  peerId: string
  onMinimize?: () => void
  onEndCall: () => void
}

export function ActiveCallUI({ callId, peerName, peerId, onEndCall }: ActiveCallUIProps) {
  const { 
    getCall, 
    endCall: storeEndCall,
    muted,
    audioOutputDevice,
    availableOutputDevices,
  } = useCallStore()

  const [duration, setDuration] = useState(0)
  const [audioLevel, setAudioLevel] = useState(0)
  const [showDevicePicker, setShowDevicePicker] = useState(false)
  
  const timerRef = useRef<ReturnType<typeof setInterval>>()
  const audioLevelRef = useRef<ReturnType<typeof setInterval>>()

  const call = getCall(callId)

  useEffect(() => {
    if (!call || call.state !== 'active') return

    // Update timer every second
    if (call.startTime) {
      const startTime = call.startTime.getTime()
      timerRef.current = setInterval(() => {
        setDuration(Date.now() - startTime)
      }, 1000)
      setDuration(Date.now() - startTime)
    }

    // Update audio level
    audioLevelRef.current = setInterval(() => {
      setAudioLevel(webRTCCalling.getAudioLevel())
    }, 100)

    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
      if (audioLevelRef.current) clearInterval(audioLevelRef.current)
    }
  }, [call])

  const handleEndCall = () => {
    storeEndCall(callId)
    onEndCall()
  }

  const handleToggleMute = () => {
    import('../../store/callStore').then(({ useCallStore }) => {
      useCallStore.getState().toggleMute()
    })
  }

  const handleDeviceChange = async (deviceId: string) => {
    await import('../../store/callStore').then(({ useCallStore }) => {
      useCallStore.getState().setAudioOutputDevice(deviceId)
    })
    setShowDevicePicker(false)
  }

  const formatTime = (ms: number): string => {
    const totalSeconds = Math.floor(ms / 1000)
    const minutes = Math.floor(totalSeconds / 60)
    const seconds = totalSeconds % 60
    return `${minutes}:${seconds.toString().padStart(2, '0')}`
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 w-full max-w-sm md:max-w-md animate-slide-in">
      <div className="rounded-xl bg-white shadow-2xl overflow-hidden dark:bg-gray-800">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-full bg-primary-100 flex items-center justify-center">
              <svg className="w-7 h-7 text-primary-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14v7m-3 0h6" />
              </svg>
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white">{peerName}</h3>
              <p className="text-xs text-gray-500 dark:text-gray-400 font-mono">{peerId}</p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <button
              onClick={handleEndCall}
              className="p-2 rounded-lg bg-red-500 text-white hover:bg-red-600 transition-colors"
              aria-label="End call"
              title="End call"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 2H9a2 2 0 00-2 2v20a2 2 0 002 2h6a2 2 0 002-2V4a2 2 0 00-2-2z" />
              </svg>
            </button>
          </div>
        </div>

        {/* Call timer and status */}
        <div className="px-4 py-3 bg-gray-50 dark:bg-gray-900/50 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-2 h-2 rounded-full ${call?.state === 'active' ? 'bg-green-500' : 'bg-yellow-500'}`} />
              <span className="font-mono text-lg font-semibold text-gray-900 dark:text-white">
                {formatTime(duration)}
              </span>
            </div>
            <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
              <span>Audio Level</span>
              <div className="w-20 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-primary-500 transition-all duration-100"
                  style={{ width: `${Math.min(100, audioLevel * 100)}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Controls */}
        <div className="p-4 flex items-center justify-center gap-4">
          {/* Mute button */}
          <button
            onClick={handleToggleMute}
            className={`flex items-center justify-center w-12 h-12 rounded-full transition-colors ${
              muted
                ? 'bg-red-500 text-white'
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600'
            }`}
            aria-label={muted ? 'Unmute' : 'Mute'}
            title={muted ? 'Unmute' : 'Mute'}
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {muted ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.5 15.75a2.25 2.25 0 00-3.182-.213 48.196 48.196 0 00-3.18.451 2.25 2.25 0 00-.042 4.56 47.755 47.755 0 003.181.45 2.25 2.25 0 001.776-.812 2.25 2.25 0 013.182 0 2.25 2.25 0 001.776.812 47.755 47.755 0 003.18-.45 2.25 2.25 0 00.041-4.56 48.215 48.215 0 00-3.18-.451 2.25 2.25 0 00-1.776.812 2.25 2.25 0 01-3.182 0z" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h12m-5 4v1a1 1 0 01-1 1H6a1 1 0 01-1-1v-1m10 0v1a1 1 0 01-1 1H9a1 1 0 01-1-1v-1m-2 5H6a2 2 0 01-2-2V7a2 2 0 012-2h12a2 2 0 012 2v8a2 2 0 01-2 2z" />
              )}
            </svg>
          </button>

          {/* Audio output device selector */}
          <div className="relative">
            <button
              onClick={() => setShowDevicePicker(!showDevicePicker)}
              className="flex items-center gap-1 w-12 h-12 rounded-full bg-gray-100 text-gray-700 hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-200 dark:hover:bg-gray-600 transition-colors"
              aria-label="Audio output device"
              title="Audio output device"
            >
              <svg className="w-6 h-6 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.536 8.464a5 5 0 010 7.072m2.828-9.9a9 9 0 010 12.728M5.586 15H4a1 1 0 01-1-1v-4a1 1 0 011-1h14a1 1 0 011 1v4a1 1 0 01-1 1H5.586l2 2z" />
              </svg>
            </button>

            {showDevicePicker && (
              <div className="absolute bottom-full right-0 mb-2 w-48 rounded-lg bg-white shadow-lg border border-gray-200 dark:bg-gray-800 dark:border-gray-700 py-1 z-10">
                <div className="px-3 py-2 text-xs font-medium text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                  Audio Output
                </div>
                {availableOutputDevices.map(device => (
                  <button
                    key={device.deviceId}
                    onClick={() => handleDeviceChange(device.deviceId)}
                    className={`w-full px-3 py-2 text-left text-sm transition-colors ${
                      audioOutputDevice === device.deviceId
                        ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300'
                        : 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span>{device.label || `Device ${device.deviceId.slice(0, 8)}...`}</span>
                      {audioOutputDevice === device.deviceId && (
                        <svg className="w-4 h-4 text-primary-500" fill="currentColor" viewBox="0 0 20 20">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                      )}
                    </div>
                  </button>
                ))}
                {availableOutputDevices.length === 0 && (
                  <div className="px-3 py-4 text-center text-sm text-gray-500 dark:text-gray-400">
                    No output devices found
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}