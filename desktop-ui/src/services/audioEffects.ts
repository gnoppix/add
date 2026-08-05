/**
 * Audio Effect Player - Telephony Sound Effects
 * Handles ringtone, ringback, call accepted, call ended tones
 */
// Simple console-based logger
const log = {
  info: (...args: unknown[]) => console.log('[AudioEffects]', ...args),
  warn: (...args: unknown[]) => console.warn('[AudioEffects]', ...args),
  error: (...args: unknown[]) => console.error('[AudioEffects]', ...args),
  debug: (...args: unknown[]) => console.debug('[AudioEffects]', ...args),
}

export enum CallSoundType {
  IncomingRingtone = 'incoming_ringtone',
  OutgoingRingback = 'outgoing_ringback',
  CallAccepted = 'call_accepted',
  CallEnded = 'call_ended',
  CallRejected = 'call_rejected',
  CallBusy = 'call_busy',
}

// Web Audio API context for generating tones
let audioContext: AudioContext | null = null
const soundBuffers: Map<CallSoundType, AudioBuffer> = new Map()
const activeSources: Map<CallSoundType, AudioBufferSourceNode> = new Map()
const gainNodes: Map<CallSoundType, GainNode> = new Map()

function getAudioContext(): AudioContext {
  if (!audioContext && typeof window !== 'undefined' && window.AudioContext) {
    audioContext = new AudioContext()
  }
  if (!audioContext) {
    throw new Error('AudioContext not available')
  }
  return audioContext
}

async function initAudioContext(): Promise<void> {
  if (!audioContext) {
    audioContext = new AudioContext()
  }
  if (audioContext.state === 'suspended') {
    await audioContext.resume()
  }
}

/**
 * Generate ringback tone (classic 440Hz + 480Hz, 2s on / 4s off)
 */
function generateRingbackTone(): AudioBuffer {
  const ctx = getAudioContext()
  const duration = 6 // 2s on + 4s off
  const sampleRate = ctx.sampleRate
  const length = sampleRate * duration
  const buffer = ctx.createBuffer(1, length, sampleRate)
  const data = buffer.getChannelData(0)

  for (let i = 0; i < length; i++) {
    const t = i / sampleRate
    // 2s on, 4s off pattern
    const cyclePos = t % 6
    if (cyclePos < 2) {
      // 440Hz + 480Hz
      const envelope = Math.min(1, (i % (sampleRate * 2)) / (sampleRate * 0.01)) * 
                       Math.min(1, (sampleRate * 2 - (i % (sampleRate * 2))) / (sampleRate * 0.01))
      data[i] = (Math.sin(2 * Math.PI * 440 * t) + Math.sin(2 * Math.PI * 480 * t)) / 2 * envelope * 0.25
    } else {
      data[i] = 0
    }
  }

  return buffer
}

/**
 * Generate incoming ringtone (classic ring ring pattern)
 */
function generateIncomingRingtone(): AudioBuffer {
  const ctx = getAudioContext()
  const duration = 4 // 1s on, 3s off typical ring
  const sampleRate = ctx.sampleRate
  const length = sampleRate * duration
  const buffer = ctx.createBuffer(1, length, sampleRate)
  const data = buffer.getChannelData(0)

  for (let i = 0; i < length; i++) {
    const t = i / sampleRate
    // 1s on, 3s off pattern
    const cyclePos = t % 4
    if (cyclePos < 1) {
      // 440Hz + 480Hz (classic ring)
      const envelope = Math.min(1, (i % sampleRate) / (sampleRate * 0.01)) * 
                       Math.min(1, (sampleRate - (i % sampleRate)) / (sampleRate * 0.01))
      data[i] = (Math.sin(2 * Math.PI * 440 * t) + Math.sin(2 * Math.PI * 480 * t)) / 2 * envelope * 0.3
    } else {
      data[i] = 0
    }
  }

  return buffer
}

/**
 * Generate call accepted chime (ascending tone)
 */
function generateAcceptedTone(): AudioBuffer {
  const ctx = getAudioContext()
  const duration = 1
  const sampleRate = ctx.sampleRate
  const length = sampleRate * duration
  const buffer = ctx.createBuffer(1, length, sampleRate)
  const data = buffer.getChannelData(0)

  for (let i = 0; i < length; i++) {
    const t = i / sampleRate
    // Ascending frequency from 523Hz (C5) to 1046Hz (C6)
    const freq = 523 + (523 * t)
    const envelope = Math.min(1, i / (sampleRate * 0.01)) * Math.min(1, (length - i) / (sampleRate * 0.05))
    data[i] = Math.sin(2 * Math.PI * freq * t) * envelope * 0.3
  }

  return buffer
}

/**
 * Generate call ended tone (descending tone)
 */
function generateEndedTone(): AudioBuffer {
  const ctx = getAudioContext()
  const duration = 0.8
  const sampleRate = ctx.sampleRate
  const length = sampleRate * duration
  const buffer = ctx.createBuffer(1, length, sampleRate)
  const data = buffer.getChannelData(0)

  for (let i = 0; i < length; i++) {
    const t = i / sampleRate
    // Descending frequency from 880Hz to 440Hz
    const freq = 880 - (440 * t / duration)
    const envelope = Math.min(1, i / (sampleRate * 0.01)) * Math.min(1, (length - i) / (sampleRate * 0.1))
    data[i] = Math.sin(2 * Math.PI * freq * t) * envelope * 0.3
  }

  return buffer
}

/**
 * Generate busy signal (480Hz + 620Hz, 0.5s on / 0.5s off)
 */
function generateBusyTone(): AudioBuffer {
  const ctx = getAudioContext()
  const duration = 2 // 0.5s on / 0.5s off = 1s cycle, 2 cycles
  const sampleRate = ctx.sampleRate
  const length = sampleRate * duration
  const buffer = ctx.createBuffer(1, length, sampleRate)
  const data = buffer.getChannelData(0)

  for (let i = 0; i < length; i++) {
    const t = i / sampleRate
    const cyclePos = t % 1
    if (cyclePos < 0.5) {
      const envelope = Math.min(1, (i % (sampleRate * 0.5)) / (sampleRate * 0.01)) * 
                       Math.min(1, (sampleRate * 0.5 - (i % (sampleRate * 0.5))) / (sampleRate * 0.01))
      data[i] = (Math.sin(2 * Math.PI * 480 * t) + Math.sin(2 * Math.PI * 620 * t)) / 2 * envelope * 0.3
    } else {
      data[i] = 0
    }
  }

  return buffer
}

/**
 * Preload all sound buffers
 */
export async function preloadSounds(): Promise<void> {
  await initAudioContext()

  soundBuffers.set(CallSoundType.IncomingRingtone, generateIncomingRingtone())
  soundBuffers.set(CallSoundType.OutgoingRingback, generateRingbackTone())
  soundBuffers.set(CallSoundType.CallAccepted, generateAcceptedTone())
  soundBuffers.set(CallSoundType.CallEnded, generateEndedTone())
  soundBuffers.set(CallSoundType.CallRejected, generateEndedTone())
  soundBuffers.set(CallSoundType.CallBusy, generateBusyTone())

  log.info('All call sounds preloaded')
}

/**
 * Play a sound effect
 */
export async function playSound(type: CallSoundType, options: { loop?: boolean; volume?: number } = {}): Promise<void> {
  await initAudioContext()

  const buffer = soundBuffers.get(type)
  if (!buffer) {
    log.warn(`Sound buffer not found for ${type}`)
    return
  }

  // Stop existing sound of same type
  stopSound(type)

  const ctx = getAudioContext()
  const source = ctx.createBufferSource()
  const gainNode = ctx.createGain()

  source.buffer = buffer
  source.loop = options.loop ?? false
  gainNode.gain.value = options.volume ?? 1.0

  source.connect(gainNode)
  gainNode.connect(ctx.destination)

  activeSources.set(type, source)
  gainNodes.set(type, gainNode)

  source.onended = () => {
    activeSources.delete(type)
    gainNodes.delete(type)
  }

  source.start(0)
  log.debug(`Playing sound: ${type}`)
}

/**
 * Stop a sound effect
 */
export function stopSound(type: CallSoundType): void {
  const source = activeSources.get(type)
  if (source) {
    try {
      source.stop()
      source.onended = null
    } catch (e) {
      // Ignore errors
    }
    activeSources.delete(type)
    gainNodes.delete(type)
  }

  // Also stop any looping variant
  if (type === CallSoundType.OutgoingRingback || type === CallSoundType.IncomingRingtone) {
    // These are looped, ensure they're stopped
  }
}

/**
 * Stop all sounds
 */
export function stopAllSounds(): void {
  for (const entry of activeSources) {
    const source = entry[1]
    try {
      source.stop()
      source.onended = null
    } catch (e) {
      // Ignore
    }
  }
  activeSources.clear()
  gainNodes.clear()
}

/**
 * Set volume for a specific sound
 */
export function setSoundVolume(_type: CallSoundType, volume: number): void {
  const gainNode = gainNodes.get(_type)
  if (gainNode) {
    gainNode.gain.value = Math.max(0, Math.min(1, volume))
  }
}

/**
 * Convenience methods for call lifecycle
 */
export const callSounds = {
  playIncomingRingtone: () => playSound(CallSoundType.IncomingRingtone, { loop: true, volume: 0.5 }),
  playOutgoingRingback: () => playSound(CallSoundType.OutgoingRingback, { loop: true, volume: 0.4 }),
  playCallAccepted: () => playSound(CallSoundType.CallAccepted, { volume: 0.5 }),
  playCallEnded: () => playSound(CallSoundType.CallEnded, { volume: 0.5 }),
  playCallRejected: () => playSound(CallSoundType.CallRejected, { volume: 0.5 }),
  playCallBusy: () => playSound(CallSoundType.CallBusy, { loop: true, volume: 0.5 }),
  stopRingtone: () => stopSound(CallSoundType.IncomingRingtone),
  stopRingback: () => stopSound(CallSoundType.OutgoingRingback),
  stopAll: stopAllSounds,
}