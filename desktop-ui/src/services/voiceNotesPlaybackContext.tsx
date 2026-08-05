/**
 * VoiceNotesPlaybackContext - Global context for voice message playback and waveform computation
 * Inspired by Signal's VoiceNotesPlaybackContext
 */

import { createContext, useContext, useEffect, useState, type ReactNode, type JSX } from 'react'
import { LRUCache } from 'lru-cache'
import PQueue from 'p-queue'

// Types
export type PeakType = { value: number; index: number } // 0 < peak < 1

export type ComputePeaksResult = {
  duration: number
  peaks: ReadonlyArray<PeakType>
}

export type VoiceNotesPlaybackContents = {
  computePeaks: (url: string, barCount: number) => Promise<ComputePeaksResult>
  playAudio: (url: string) => Promise<HTMLAudioElement>
  pauseAudio: (audio: HTMLAudioElement) => void
  getAudioDuration: (url: string) => Promise<number>
}

// Configuration
const MAX_WAVEFORM_COUNT = 1000
const MAX_PARALLEL_COMPUTE = 4
const MAX_AUDIO_DURATION = 30 // 30 seconds max for voice messages

// Global singleton instances
let audioContext: AudioContext | undefined

const waveformCache = new LRUCache<string, ComputePeaksResult>({
  max: MAX_WAVEFORM_COUNT,
})

const inProgressMap = new Map<string, Promise<ComputePeaksResult>>()
const computeQueue = new PQueue({
  concurrency: MAX_PARALLEL_COMPUTE,
})

const activeAudioElements = new Map<string, HTMLAudioElement>()

/**
 * Get audio duration from a blob URL
 */
async function getAudioDuration(url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const audio = new Audio()
    audio.muted = true
    audio.src = url
    
    audio.addEventListener('loadedmetadata', () => {
      if (Number.isNaN(audio.duration)) {
        reject(new Error('Invalid audio duration'))
        return
      }
      resolve(audio.duration)
    })
    
    audio.addEventListener('error', (event) => {
      reject(new Error(`Failed to load audio: ${event.type}`))
    })
  })
}

/**
 * Compute RMS peaks for waveform visualization
 */
async function doComputePeaks(url: string, barCount: number): Promise<ComputePeaksResult> {
  const cacheKey = `${url}:${barCount}`
  const existing = waveformCache.get(cacheKey)
  
  if (existing) {
    return Promise.resolve(existing)
  }

  // Load and decode audio
  const response = await fetch(url)
  const raw = await response.arrayBuffer()
  
  const duration = await getAudioDuration(url)
  
  // Initialize peaks array
  const peaks: PeakType[] = []
  for (let i = 0; i < barCount; i += 1) {
    peaks.push({ value: 0, index: i })
  }
  
  if (duration > MAX_AUDIO_DURATION) {
    const emptyResult = { peaks, duration }
    waveformCache.set(cacheKey, emptyResult)
    return emptyResult
  }

  if (!audioContext) {
    audioContext = new AudioContext()
    await audioContext.suspend()
  }

  const data = await audioContext.decodeAudioData(raw)

  // Compute RMS peaks
  const norms = new Array(barCount).fill(0)
  const samplesPerPeak = data.length / peaks.length

  for (
    let channelNum = 0;
    channelNum < data.numberOfChannels;
    channelNum += 1
  ) {
    const channel = data.getChannelData(channelNum)
    
    for (const [sample, sampleData] of channel.entries()) {
      const i = Math.floor(sample / samplesPerPeak)
      const peak = peaks[i]
      if (peak == null) {
        throw new Error('Missing peak')
      }
      peak.value += sampleData ** 2
      norms[i] += 1
    }
  }

  // Average and normalize
  let max = 1e-23
  for (const [i, peak] of peaks.entries()) {
    peak.value = Math.sqrt(peak.value / Math.max(1, norms[i]))
    max = Math.max(max, peak.value)
  }

  for (const peak of peaks) {
    peak.value /= max
  }

  const result = { peaks, duration }
  waveformCache.set(cacheKey, result)
  return result
}

/**
 * Public computePeaks function with deduplication
 */
export async function computePeaks(
  url: string,
  barCount: number
): Promise<ComputePeaksResult> {
  const computeKey = `${url}:${barCount}`
  
  const pending = inProgressMap.get(computeKey)
  if (pending) {
    return pending
  }

  const promise = computeQueue.add(() => doComputePeaks(url, barCount))
  inProgressMap.set(computeKey, promise)
  
  try {
    return await promise
  } finally {
    inProgressMap.delete(computeKey)
  }
}

/**
 * Play audio from URL
 */
export async function playAudio(url: string): Promise<HTMLAudioElement> {
  // Stop any currently playing audio for this URL
  const existing = activeAudioElements.get(url)
  if (existing) {
    existing.pause()
    existing.currentTime = 0
  }

  const audio = new Audio()
  audio.src = url
  activeAudioElements.set(url, audio)

  return new Promise((resolve, reject) => {
    audio.addEventListener('canplaythrough', () => {
      audio.play().then(() => resolve(audio)).catch(reject)
    })
    audio.addEventListener('error', (event) => {
      reject(new Error(`Audio playback error: ${event.type}`))
    })
  })
}

/**
 * Pause audio
 */
export function pauseAudio(audio: HTMLAudioElement): void {
  audio.pause()
}

/**
 * Stop all audio
 */
export function stopAllAudio(): void {
  for (const audio of activeAudioElements.values()) {
    audio.pause()
    audio.currentTime = 0
  }
  activeAudioElements.clear()
}

// Global contents
const globalContents: VoiceNotesPlaybackContents = {
  computePeaks,
  playAudio,
  pauseAudio,
  getAudioDuration,
}

export const VoiceNotesPlaybackContext = createContext<VoiceNotesPlaybackContents>(globalContents)

export type VoiceNotesPlaybackProviderProps = {
  children?: ReactNode
}

/**
 * Provider component for voice notes playback context
 */
export function VoiceNotesPlaybackProvider({
  children,
}: VoiceNotesPlaybackProviderProps): JSX.Element {
  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopAllAudio()
      if (audioContext) {
        audioContext.close()
        audioContext = undefined
      }
    }
  }, [])

  return (
    <VoiceNotesPlaybackContext.Provider value={globalContents}>
      {children}
    </VoiceNotesPlaybackContext.Provider>
  )
}

/**
 * Hook to access voice notes playback context
 */
export function useVoiceNotesPlayback(): VoiceNotesPlaybackContents {
  return useContext(VoiceNotesPlaybackContext)
}

/**
 * Hook to compute peaks for a voice message
 */
export function useComputePeaks({
  audioUrl,
  barCount = 47,
  enabled = true,
}: {
  audioUrl: string | undefined
  barCount?: number
  enabled?: boolean
}): { peaks: ReadonlyArray<PeakType>; hasPeaks: boolean; duration: number } {
  const [peaks, setPeaks] = useState<ReadonlyArray<PeakType>>([])
  const [hasPeaks, setHasPeaks] = useState(false)
  const [duration, setDuration] = useState(0)
  const { computePeaks: computePeaksFn } = useVoiceNotesPlayback()

  useEffect(() => {
    if (!enabled || !audioUrl) {
      setPeaks([])
      setHasPeaks(false)
      setDuration(0)
      return
    }

    let cancelled = false

    ;(async () => {
      try {
        const result = await computePeaksFn(audioUrl, barCount)
        if (cancelled) return
        setPeaks(result.peaks)
        setHasPeaks(true)
        setDuration(result.duration)
      } catch (err) {
        console.error('VoiceNotesPlayback: computePeaks error:', err)
        if (!cancelled) {
          setPeaks([])
          setHasPeaks(false)
          setDuration(0)
        }
      }
    })()

    return () => {
      cancelled = true
    }
  }, [audioUrl, barCount, enabled, computePeaksFn])

  // Return blank peaks if not computed yet
  if (!hasPeaks) {
    const blank: PeakType[] = []
    for (let i = 0; i < barCount; i += 1) {
      blank.push({ value: 0, index: i })
    }
    return { peaks: blank, hasPeaks: false, duration: 0 }
  }

  return { peaks, hasPeaks, duration }
}