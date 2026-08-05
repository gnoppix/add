/**
 * VoiceMessageBubble - Component for rendering voice messages with playback controls
 */

import { useState, useRef, useEffect, useCallback, type JSX } from 'react'
import { useVoiceNotesPlayback, useComputePeaks } from '../../services/voiceNotesPlaybackContext'

interface VoiceMessageBubbleProps {
  /** Base64 encoded audio data */
  data: string
  /** MIME type (audio/webm or audio/ogg) */
  mime: string
  /** Whether this is an outgoing message */
  isOutgoing: boolean
}

const BAR_COUNT = 47
const BAR_MIN_HEIGHT = 4
const BAR_MAX_HEIGHT = 20

export function VoiceMessageBubble({
  data,
  mime,
  isOutgoing,
}: VoiceMessageBubbleProps): JSX.Element {
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [duration, setDuration] = useState(0)
  const [hasError, setHasError] = useState(false)
  const audioRef = useRef<HTMLAudioElement | null>(null)
  const animationRef = useRef<number>()
  const { playAudio, pauseAudio } = useVoiceNotesPlayback()

  // Create blob URL for the audio
  const audioUrl = useRef<string | null>(null)
  useEffect(() => {
    if (!audioUrl.current) {
      const clean = data.includes(',') ? data.slice(data.indexOf(',') + 1) : data
      const binary = atob(clean)
      const bytes = new Uint8Array(binary.length)
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i)
      }
      const blob = new Blob([bytes], { type: mime })
      audioUrl.current = URL.createObjectURL(blob)
    }
    return () => {
      if (audioUrl.current) {
        URL.revokeObjectURL(audioUrl.current)
        audioUrl.current = null
      }
    }
  }, [data, mime])

  // Compute peaks for waveform
  const { peaks } = useComputePeaks({
    audioUrl: audioUrl.current ?? undefined,
    barCount: BAR_COUNT,
    enabled: !!audioUrl.current,
  })

  // Format time as mm:ss
  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  // Handle play/pause toggle
  const handleTogglePlay = useCallback(async () => {
    if (!audioUrl.current) return

    if (isPlaying) {
      // Pause
      if (audioRef.current) {
        pauseAudio(audioRef.current)
      }
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
      setIsPlaying(false)
    } else {
      // Play
      try {
        const audio = await playAudio(audioUrl.current)
        audioRef.current = audio
        
        setDuration(audio.duration)
        setIsPlaying(true)
        
        // Update current time during playback
        const updateTime = () => {
          if (audioRef.current && !audioRef.current.paused) {
            setCurrentTime(audioRef.current.currentTime)
            animationRef.current = requestAnimationFrame(updateTime)
          } else if (audioRef.current?.ended) {
            setIsPlaying(false)
            setCurrentTime(0)
          }
        }
        animationRef.current = requestAnimationFrame(updateTime)
        
        audio.addEventListener('ended', () => {
          setIsPlaying(false)
          setCurrentTime(0)
        })
      } catch (err) {
        console.error('Failed to play voice message:', err)
        setHasError(true)
      }
    }
  }, [isPlaying, playAudio, pauseAudio])

  // Handle scrubbing on waveform click
  const handleWaveformClick = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    if (!audioUrl.current || !duration || !audioRef.current) return
    
    const rect = e.currentTarget.getBoundingClientRect()
    const clickX = e.clientX - rect.left
    const width = rect.width
    const ratio = Math.max(0, Math.min(1, clickX / width))
    const newTime = ratio * duration
    
    audioRef.current.currentTime = newTime
    setCurrentTime(newTime)
  }, [duration])

  // Handle keyboard scrubbing (left/right arrows)
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (!audioRef.current || !duration) return
    
    const skip = e.shiftKey ? 10 : 5 // seconds
    let newTime = audioRef.current.currentTime
    
    if (e.key === 'ArrowRight') {
      newTime = Math.min(duration, newTime + skip)
    } else if (e.key === 'ArrowLeft') {
      newTime = Math.max(0, newTime - skip)
    } else {
      return
    }
    
    e.preventDefault()
    audioRef.current.currentTime = newTime
    setCurrentTime(newTime)
  }, [duration])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
      if (audioRef.current) {
        audioRef.current.pause()
        audioRef.current = null
      }
    }
  }, [])

  // Progress ratio for waveform highlight
  const progressRatio = duration > 0 ? currentTime / duration : 0
  const playedBarIndex = Math.floor(peaks.length * progressRatio)

  return (
    <div
      className={`flex items-center gap-2 p-2 rounded-lg ${isOutgoing ? 'bg-primary-600 text-white' : 'bg-gray-100 text-gray-800'}`}
      onKeyDown={handleKeyDown}
      tabIndex={0}
      role="button"
      aria-label={`Voice message, ${formatTime(duration || 0)}`}
    >
      {/* Play/Pause Button */}
      <button
        onClick={handleTogglePlay}
        disabled={hasError}
        className={`flex-shrink-0 p-1 rounded-full transition-colors ${
          isOutgoing 
            ? 'text-white hover:bg-white/20' 
            : 'text-gray-700 hover:bg-gray-200'
        } disabled:opacity-50`}
        aria-label={isPlaying ? 'Pause' : 'Play'}
      >
        {isPlaying ? (
          <svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24">
            <path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z" />
          </svg>
        ) : (
          <svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24">
            <path d="M8 5v14l11-7z" />
          </svg>
        )}
      </button>

      {/* Waveform Visualization */}
      <div
        onClick={handleWaveformClick}
        className="flex-1 h-10 flex items-end gap-0.5 cursor-pointer"
        role="slider"
        aria-label="Playback progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(progressRatio * 100)}
      >
        {peaks.map(({ value, index }) => {
          const height = Math.max(BAR_MIN_HEIGHT, BAR_MAX_HEIGHT * value)
          const isPlayed = index <= playedBarIndex && isPlaying
          
          return (
            <div
              key={index}
              className={`rounded transition-all duration-75 ${
                isOutgoing
                  ? isPlayed
                    ? 'bg-white'
                    : 'bg-white/50'
                  : isPlayed
                    ? 'bg-primary-600'
                    : 'bg-gray-400'
              }`}
              style={{ 
                height: `${height}px`,
                width: '3px',
                flexShrink: 0,
              }}
            />
          )
        })}
      </div>

      {/* Duration / Time Display */}
      <span className="flex-shrink-0 text-xs font-mono tabular-nums">
        {isPlaying ? formatTime(currentTime) : formatTime(duration || 0)}
      </span>

      {/* Error state */}
      {hasError && (
        <span className="text-xs text-red-500">
          {isOutgoing ? 'Failed to play' : 'Failed to load'}
        </span>
      )}
    </div>
  )
}