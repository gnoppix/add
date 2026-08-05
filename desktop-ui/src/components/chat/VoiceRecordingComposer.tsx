/**
 * VoiceRecordingComposer - Component for recording voice messages with live waveform visualization
 */

import { useState, useRef, useEffect, useCallback, type JSX } from 'react'
import { voiceRecorder, VoiceRecorderState, VoiceRecorderError, MAX_RECORDING_DURATION_MS } from '../../services/voiceRecorder'

interface VoiceRecordingComposerProps {
  /** Callback when recording is cancelled */
  onCancel: () => void
  /** Callback when recording is complete and ready to send */
  onSend: (blob: Blob, duration: number) => void
  /** Optional error callback */
  onError?: (error: VoiceRecorderError) => void
}

export function VoiceRecordingComposer({
  onCancel,
  onSend,
  onError,
}: VoiceRecordingComposerProps): JSX.Element {
  const [recorderState, setRecorderState] = useState<VoiceRecorderState>(VoiceRecorderState.Idle)
  const [recordingDuration, setRecordingDuration] = useState(0)
  const [peaks, setPeaks] = useState<number[]>([])
  const [error, setError] = useState<VoiceRecorderError | null>(null)
  const [showPreview, setShowPreview] = useState(false)
  const [previewBlob, setPreviewBlob] = useState<Blob | null>(null)
  const [previewDuration, setPreviewDuration] = useState(0)
  
  const durationIntervalRef = useRef<ReturnType<typeof setInterval>>()
  const peakHistoryRef = useRef<number[]>([])

  // Initialize recorder callbacks
  useEffect(() => {
    voiceRecorder.setOptions({
      onStateChange: setRecorderState,
      onPeak: (peak: number) => {
        // Keep last 50 peaks for waveform
        peakHistoryRef.current = [...peakHistoryRef.current.slice(-49), peak]
        setPeaks([...peakHistoryRef.current])
      },
      onError: (err: VoiceRecorderError) => {
        setError(err)
        onError?.(err)
        setRecorderState(VoiceRecorderState.Idle)
      },
      onComplete: (blob: Blob) => {
        const duration = voiceRecorder.getDuration()
        setPreviewBlob(blob)
        setPreviewDuration(duration)
        setShowPreview(true)
        setRecorderState(VoiceRecorderState.Idle)
      },
    })
  }, [onError])

  // Update recording duration timer
  useEffect(() => {
    if (recorderState === VoiceRecorderState.Recording) {
      durationIntervalRef.current = setInterval(() => {
        const dur = voiceRecorder.getDuration()
        setRecordingDuration(dur)
        
        // Auto-stop at max duration
        if (dur * 1000 >= MAX_RECORDING_DURATION_MS) {
          handleStop()
        }
      }, 100)
    } else {
      if (durationIntervalRef.current) {
        clearInterval(durationIntervalRef.current)
      }
    }
    
    return () => {
      if (durationIntervalRef.current) {
        clearInterval(durationIntervalRef.current)
      }
    }
  }, [recorderState])

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const handleStart = useCallback(async () => {
    console.log('[VoiceRecordingComposer] Start button clicked')
    setError(null)
    peakHistoryRef.current = []
    setPeaks([])
    setRecordingDuration(0)
    
    const started = await voiceRecorder.start()
    console.log('[VoiceRecordingComposer] voiceRecorder.start() returned:', started)
    if (!started) {
      // Error already handled via callback - but if no error was set, show generic error
      if (!error) {
        setError(VoiceRecorderError.RecordingFailed)
      }
    }
  }, [error])

  const handleStop = useCallback(async () => {
    if (recorderState !== VoiceRecorderState.Recording) return
    
    const result = await voiceRecorder.stop()
    if (result) {
      onSend(result.blob, result.duration)
    }
  }, [recorderState, onSend])

  const handleCancel = useCallback(() => {
    if (recorderState === VoiceRecorderState.Recording) {
      voiceRecorder.cancel()
    }
    setShowPreview(false)
    setPreviewBlob(null)
    setPeaks([])
    setRecordingDuration(0)
    onCancel()
  }, [recorderState, onCancel])

  const handleDiscardPreview = useCallback(() => {
    setShowPreview(false)
    setPreviewBlob(null)
    onCancel()
  }, [onCancel])

  const handleSendPreview = useCallback(() => {
    if (previewBlob) {
      onSend(previewBlob, previewDuration)
      setShowPreview(false)
      setPreviewBlob(null)
    }
  }, [previewBlob, previewDuration, onSend])

  // Recording view
  if (!showPreview) {
    const isRecording = recorderState === VoiceRecorderState.Recording
    const isInitializing = recorderState === VoiceRecorderState.Initializing
    
    return (
      <div className="flex items-center gap-3 p-3 bg-red-50 border border-red-200 rounded-lg animate-slide-in">
        {/* Recording indicator */}
        <div className="flex items-center gap-2">
          <div className={`h-3 w-3 rounded-full animate-pulse ${
            isRecording ? 'bg-red-500' : 'bg-gray-300'
          }`} />
          <span className="text-sm font-medium text-red-700">
            {isInitializing ? 'Initializing...' : isRecording ? 'Recording' : 'Ready'}
          </span>
        </div>

        {/* Timer */}
        <div className="text-lg font-mono tabular-nums text-red-700 mx-2">
          {formatTime(recordingDuration)} / 0:30
        </div>

        {/* Live waveform */}
        <div className="flex-1 h-8 flex items-end gap-1 overflow-hidden">
          {peaks.length > 0 ? (
            peaks.slice(-40).map((value, index) => (
              <div
                key={index}
                className="rounded bg-red-400 flex-shrink-0 transition-all duration-50"
                style={{ 
                  height: `${Math.max(4, 20 * value)}px`,
                  width: '3px',
                }}
              />
            ))
          ) : (
            Array.from({ length: 20 }).map((_, i) => (
              <div
                key={i}
                className="rounded bg-red-200 flex-shrink-0"
                style={{ height: '4px', width: '3px' }}
              />
            ))
          )}
        </div>

        {/* Control buttons */}
        <div className="flex items-center gap-2">
          {isRecording ? (
            <button
              onClick={handleStop}
              className="px-3 py-1.5 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 transition-colors"
            >
              Stop
            </button>
          ) : (
            <button
              onClick={handleStart}
              disabled={isInitializing}
              className="px-3 py-1.5 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isInitializing ? 'Starting...' : 'Start Recording'}
            </button>
          )}
          <button
            onClick={handleCancel}
            className="p-1.5 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors"
            aria-label="Cancel recording"
          >
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {error && (
          <div className="absolute bottom-full left-0 right-0 mb-2 p-2 text-xs text-red-700 bg-red-50 border border-red-200 rounded">
            {error === VoiceRecorderError.NoMicrophonePermission && 'Microphone permission denied. Please allow microphone access in browser settings.'}
            {error === VoiceRecorderError.MicrophoneNotFound && 'No microphone found. Please connect a microphone.'}
            {error === VoiceRecorderError.Timeout && 'Maximum recording duration (30s) reached.'}
            {error === VoiceRecorderError.PayloadTooLarge && 'Recording too large. Please try a shorter message.'}
            {error === VoiceRecorderError.RecordingFailed && 'Recording failed. Please try again.'}
            {error === VoiceRecorderError.EncodingFailed && 'Audio encoding not supported. Please try a different browser.'}
          </div>
        )}
      </div>
    )
  }

  // Preview view
  return (
    <div className="flex items-center gap-3 p-3 bg-green-50 border border-green-200 rounded-lg animate-slide-in">
      {/* Preview indicator */}
      <div className="flex items-center gap-2">
        <div className="h-3 w-3 rounded-full bg-green-500" />
        <span className="text-sm font-medium text-green-700">Preview</span>
      </div>

      {/* Duration */}
      <div className="text-lg font-mono tabular-nums text-green-700 mx-2">
        {formatTime(previewDuration)}
      </div>

      {/* Waveform (static) */}
      <div className="flex-1 h-8 flex items-end gap-1 overflow-hidden">
        {peaks.slice(-40).map((value, index) => (
          <div
            key={index}
            className="rounded bg-green-400 flex-shrink-0"
            style={{ 
              height: `${Math.max(4, 20 * value)}px`,
              width: '3px',
            }}
          />
        ))}
      </div>

      {/* Preview controls */}
      <div className="flex items-center gap-2">
        <button
          onClick={handleDiscardPreview}
          className="px-3 py-1.5 text-sm font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100 transition-colors"
        >
          Delete
        </button>
        <button
          onClick={handleSendPreview}
          className="px-3 py-1.5 text-sm font-medium text-white bg-green-600 rounded-lg hover:bg-green-700 transition-colors"
        >
          Send
        </button>
      </div>
    </div>
  )
}