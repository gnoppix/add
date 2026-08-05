/**
 * VoiceRecorder - Handles voice message recording using Web Audio API and MediaRecorder
 * Similar to Signal's AudioRecorder but using standard MediaRecorder API for Opus in WebM/Ogg
 */

// Simple console-based logger
const log = {
  info: (...args: unknown[]) => console.log('[VoiceRecorder]', ...args),
  warn: (...args: unknown[]) => console.warn('[VoiceRecorder]', ...args),
  error: (...args: unknown[]) => console.error('[VoiceRecorder]', ...args),
}

// Configuration constants
export const MAX_RECORDING_DURATION_MS = 30 * 1000 // 30 seconds
export const MAX_PAYLOAD_SIZE = 10 * 1024 * 1024 // 10 MB
export const SAMPLE_RATE = 24000 // 24 kHz for Opus
export const CHANNEL_COUNT = 1 // Mono

export enum VoiceRecorderState {
  Idle = 'idle',
  Initializing = 'initializing',
  Recording = 'recording',
  Stopping = 'stopping',
}

export enum VoiceRecorderError {
  NoMicrophonePermission = 'NoMicrophonePermission',
  MicrophoneNotFound = 'MicrophoneNotFound',
  RecordingFailed = 'RecordingFailed',
  EncodingFailed = 'EncodingFailed',
  PayloadTooLarge = 'PayloadTooLarge',
  Timeout = 'Timeout',
}

export interface VoiceRecorderOptions {
  onPeak?: (peak: number) => void // Peak level 0-1 for waveform visualization
  onStateChange?: (state: VoiceRecorderState) => void
  onError?: (error: VoiceRecorderError) => void
  onComplete?: (blob: Blob) => void
}

export interface RecordingResult {
  blob: Blob
  duration: number // in seconds
  size: number // in bytes
}

type State = 
  | { type: 'idle' }
  | { type: 'initializing' }
  | { 
      type: 'recording'
      mediaRecorder: MediaRecorder
      stream: MediaStream
      audioChunks: Blob[]
      startTime: number
      animationFrameId: number
    }
  | { type: 'stopping' }

export class VoiceRecorder {
  #state: State = { type: 'idle' }
  #options: VoiceRecorderOptions
  #timeoutId: ReturnType<typeof setTimeout> | null = null

  constructor(options: VoiceRecorderOptions = {}) {
    this.#options = options
  }

  /**
   * Update recorder options (for dynamic callback registration)
   */
  setOptions(options: VoiceRecorderOptions): void {
    this.#options = { ...this.#options, ...options }
  }

  get state(): VoiceRecorderState {
    switch (this.#state.type) {
      case 'idle':
        return VoiceRecorderState.Idle
      case 'initializing':
        return VoiceRecorderState.Initializing
      case 'recording':
        return VoiceRecorderState.Recording
      case 'stopping':
        return VoiceRecorderState.Stopping
    }
  }

  get isRecording(): boolean {
    return this.#state.type === 'recording'
  }

  /**
   * Warm up the recorder (request permissions early)
   */
  async warmup(): Promise<void> {
    if (this.#state.type !== 'idle') return
    
    try {
      // Pre-request microphone permission to speed up actual recording start
      const stream = await navigator.mediaDevices.getUserMedia({ 
        audio: { 
          channelCount: CHANNEL_COUNT,
          sampleRate: SAMPLE_RATE,
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        } 
      })
      // Stop tracks immediately - just warming up permissions
      stream.getTracks().forEach(track => track.stop())
    } catch (err) {
      log.warn('VoiceRecorder warmup failed (non-fatal):', err)
    }
  }

  /**
   * Start recording a voice message
   */
  async start(): Promise<boolean> {
    if (this.#state.type !== 'idle') {
      this.#options.onError?.(VoiceRecorderError.RecordingFailed)
      return false
    }

    this.#setState({ type: 'initializing' })

    try {
      // Request microphone permission
      const hasPermission = await this.#requestMicrophonePermission()
      if (!hasPermission) {
        this.#setState({ type: 'idle' })
        this.#options.onError?.(VoiceRecorderError.NoMicrophonePermission)
        return false
      }

      // Get user media stream
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          channelCount: CHANNEL_COUNT,
          sampleRate: SAMPLE_RATE,
          echoCancellation: true,
          noiseSuppression: true,
          autoGainControl: true,
        }
      })

      // Check if MediaRecorder supports Opus in WebM
      const mimeType = this.#getSupportedMimeType()
      if (!mimeType) {
        stream.getTracks().forEach(track => track.stop())
        this.#setState({ type: 'idle' })
        this.#options.onError?.(VoiceRecorderError.EncodingFailed)
        return false
      }

      const mediaRecorder = new MediaRecorder(stream, { mimeType })
      const audioChunks: Blob[] = []
      const startTime = Date.now()

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          audioChunks.push(event.data)
        }
      }

      mediaRecorder.onstop = async () => {
        const blob = new Blob(audioChunks, { type: mimeType })
        const duration = (Date.now() - startTime) / 1000
        
        log.info(`Recording stopped: ${duration.toFixed(2)}s, ${blob.size} bytes, ${mimeType}`)
        
        // Verify payload size
        if (blob.size > MAX_PAYLOAD_SIZE) {
          log.warn(`Voice message exceeds ${MAX_PAYLOAD_SIZE} bytes limit`)
          this.#options.onError?.(VoiceRecorderError.PayloadTooLarge)
          return
        }

        // Clean up
        stream.getTracks().forEach(track => track.stop())
        this.#clearTimeout()
        
        this.#setState({ type: 'idle' })
        this.#options.onComplete?.(blob)
      }

      mediaRecorder.onerror = (event) => {
        log.error('MediaRecorder error:', event)
        this.#clearTimeout()
        stream.getTracks().forEach(track => track.stop())
        this.#setState({ type: 'idle' })
        this.#options.onError?.(VoiceRecorderError.RecordingFailed)
      }

      // Start recording
      mediaRecorder.start(100) // Collect data every 100ms for smoother waveform updates

      // Set auto-stop timeout at 30 seconds
      this.#timeoutId = setTimeout(() => {
        log.info('Max recording duration reached (30s), stopping automatically')
        this.stop()
        this.#options.onError?.(VoiceRecorderError.Timeout)
      }, MAX_RECORDING_DURATION_MS)

      this.#setState({ 
        type: 'recording', 
        mediaRecorder, 
        stream, 
        audioChunks, 
        startTime,
        animationFrameId: 0,
      })

      // Start peak level monitoring for waveform visualization
      this.#startPeakMonitoring(stream)

      return true
    } catch (err) {
      log.error('Failed to start recording:', err)
      
      if (err instanceof DOMException) {
        if (err.name === 'NotAllowedError' || err.name === 'PermissionDeniedError') {
          this.#options.onError?.(VoiceRecorderError.NoMicrophonePermission)
        } else if (err.name === 'NotFoundError') {
          this.#options.onError?.(VoiceRecorderError.MicrophoneNotFound)
        } else {
          this.#options.onError?.(VoiceRecorderError.RecordingFailed)
        }
      } else {
        this.#options.onError?.(VoiceRecorderError.RecordingFailed)
      }
      
      this.#setState({ type: 'idle' })
      return false
    }
  }

  /**
   * Stop recording and return the audio blob
   */
  async stop(): Promise<RecordingResult | null> {
    if (this.#state.type !== 'recording') {
      return null
    }

    this.#setState({ type: 'stopping' })
    this.#clearTimeout()

    const { mediaRecorder, stream, audioChunks, startTime } = this.#state
    
    return new Promise((resolve) => {
      // Override onstop to resolve the promise
      const originalOnStop = mediaRecorder.onstop
      mediaRecorder.onstop = async () => {
        const blob = new Blob(audioChunks, { type: mediaRecorder.mimeType })
        const duration = (Date.now() - startTime) / 1000
        
        log.info(`Recording stopped manually: ${duration.toFixed(2)}s, ${blob.size} bytes`)
        
        stream.getTracks().forEach(track => track.stop())
        
        if (originalOnStop) {
          originalOnStop.call(mediaRecorder, { type: 'stop' } as BlobEvent)
        }
        
        this.#setState({ type: 'idle' })
        
        if (blob.size > MAX_PAYLOAD_SIZE) {
          this.#options.onError?.(VoiceRecorderError.PayloadTooLarge)
          resolve(null)
        } else {
          resolve({ blob, duration, size: blob.size })
        }
      }

      mediaRecorder.stop()
    })
  }

  /**
   * Cancel recording without saving
   */
  cancel(): void {
    if (this.#state.type === 'recording') {
      const { mediaRecorder, stream } = this.#state
      this.#clearTimeout()
      mediaRecorder.onstop = null // Prevent onstop handler
      mediaRecorder.stop()
      stream.getTracks().forEach(track => track.stop())
      log.info('Recording cancelled')
    }
    this.#setState({ type: 'idle' })
  }

  /**
   * Get current recording duration in seconds
   */
  getDuration(): number {
    if (this.#state.type === 'recording') {
      return (Date.now() - this.#state.startTime) / 1000
    }
    return 0
  }

  /**
   * Check if we're at max duration
   */
  isAtMaxDuration(): boolean {
    return this.getDuration() * 1000 >= MAX_RECORDING_DURATION_MS
  }

  #setState(state: State): void {
    this.#state = state
    let voiceState: VoiceRecorderState
    switch (state.type) {
      case 'idle': voiceState = VoiceRecorderState.Idle; break
      case 'initializing': voiceState = VoiceRecorderState.Initializing; break
      case 'recording': voiceState = VoiceRecorderState.Recording; break
      case 'stopping': voiceState = VoiceRecorderState.Stopping; break
    }
    this.#options.onStateChange?.(voiceState)
  }

  #clearTimeout(): void {
    if (this.#timeoutId) {
      clearTimeout(this.#timeoutId)
      this.#timeoutId = null
    }
  }

  #startPeakMonitoring(stream: MediaStream): void {
    if (this.#state.type !== 'recording') return

    const audioContext = new AudioContext()
    const source = audioContext.createMediaStreamSource(stream)
    const analyser = audioContext.createAnalyser()
    analyser.fftSize = 256
    analyser.smoothingTimeConstant = 0.8
    source.connect(analyser)

    const dataArray = new Uint8Array(analyser.frequencyBinCount)

    const updatePeak = () => {
      if (this.#state.type !== 'recording') {
        source.disconnect()
        audioContext.close()
        return
      }

      analyser.getByteFrequencyData(dataArray)
      
      // Calculate RMS-like peak level (0-1)
      let sum = 0
      for (let i = 0; i < dataArray.length; i++) {
        sum += dataArray[i] * dataArray[i]
      }
      const rms = Math.sqrt(sum / dataArray.length)
      const peak = Math.min(rms / 128, 1) // Normalize to 0-1
      
      this.#options.onPeak?.(peak)
      
      this.#state.animationFrameId = requestAnimationFrame(updatePeak)
    }

    updatePeak()
  }

  #getSupportedMimeType(): string | null {
    // Preferred order: Opus in WebM, then Opus in Ogg
    const types = [
      'audio/webm;codecs=opus',
      'audio/ogg;codecs=opus',
      'audio/webm',
      'audio/ogg',
    ]

    for (const type of types) {
      if (MediaRecorder.isTypeSupported(type)) {
        log.info(`Using mime type: ${type}`)
        return type
      }
    }

    log.warn('No supported audio mime type found')
    return null
  }

  async #requestMicrophonePermission(): Promise<boolean> {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      stream.getTracks().forEach(track => track.stop())
      return true
    } catch {
      return false
    }
  }
}

// Singleton instance for global access
export const voiceRecorder = new VoiceRecorder()