/**
 * WebRTC Calling Service - P2P Voice Calling with Signaling
 * Handles peer connection, ICE candidates, SDP offer/answer exchange
 */

// Simple console-based logger
const log = {
  info: (...args: unknown[]) => console.log('[WebRTCCalling]', ...args),
  warn: (...args: unknown[]) => console.warn('[WebRTCCalling]', ...args),
  error: (...args: unknown[]) => console.error('[WebRTCCalling]', ...args),
  debug: (...args: unknown[]) => console.debug('[WebRTCCalling]', ...args),
}

// Types
export enum CallState {
  Idle = 'idle',
  Dialing = 'dialing',
  Ringing = 'ringing',
  Connecting = 'connecting',
  Active = 'active',
  Reconnecting = 'reconnecting',
  Ended = 'ended',
  Failed = 'failed',
}

export enum CallDirection {
  Outgoing = 'outgoing',
  Incoming = 'incoming',
}

export enum CallEndReason {
  LocalHangup = 'local_hangup',
  RemoteHangup = 'remote_hangup',
  RemoteDeclined = 'remote_declined',
  RemoteBusy = 'remote_busy',
  Timeout = 'timeout',
  NetworkError = 'network_error',
  MediaError = 'media_error',
  SignalingError = 'signaling_error',
}

export interface SignalingMessage {
  type: 'offer' | 'answer' | 'ice-candidate' | 'hangup' | 'busy' | 'reject' | 'accept'
  callId: string
  from: string
  to: string
  payload?: unknown
}

export interface CallConfig {
  stunServers: RTCIceServer[]
  turnServers: RTCIceServer[]
  audioConstraints: MediaTrackConstraints
}

export interface ActiveCall {
  callId: string
  peerId: string
  direction: CallDirection
  state: CallState
  startTime: Date | null
  peerConnection: RTCPeerConnection
  localStream: MediaStream | null
  remoteStream: MediaStream | null
  audioLevel: number
}

// Default STUN/TURN servers
const DEFAULT_ICE_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' },
  { urls: 'stun:stun3.l.google.com:19302' },
  { urls: 'stun:stun4.l.google.com:19302' },
]

// Audio constraints for high-quality voice
const AUDIO_CONSTRAINTS: MediaTrackConstraints = {
  echoCancellation: true,
  noiseSuppression: true,
  autoGainControl: true,
  sampleRate: 48000,
  channelCount: 1,
  sampleSize: 16,
}

class WebRTCCallingService {
  private peerConnections: Map<string, RTCPeerConnection> = new Map()
  private activeCalls: Map<string, ActiveCall> = new Map()
  private localStream: MediaStream | null = null
  private signalingCallbacks: Map<string, (msg: SignalingMessage) => void> = new Map()
  private callStateListeners: Map<string, (call: ActiveCall) => void> = new Map()
  private iceServers: RTCIceServer[] = DEFAULT_ICE_SERVERS
  private audioContext: AudioContext | null = null
  private audioAnalyser: AnalyserNode | null = null

  constructor() {
    this.setupAudioContext()
  }

  private setupAudioContext(): void {
    if (typeof window !== 'undefined' && window.AudioContext) {
      this.audioContext = new AudioContext()
    }
  }

  /**
   * Initialize the service with custom ICE servers
   */
  setIceServers(servers: RTCIceServer[]): void {
    this.iceServers = servers.length > 0 ? servers : DEFAULT_ICE_SERVERS
  }

  /**
   * Register a signaling transport callback
   * This should be called by the UI layer to send signaling messages over the existing encrypted transport
   */
  registerSignalingTransport(sendFn: (msg: SignalingMessage) => Promise<void>): void {
    this.signalingCallbacks.set('send', sendFn as (msg: SignalingMessage) => void)
  }

  /**
   * Register a callback for incoming signaling messages
   * Called by the main process when a signaling message arrives
   */
  onSignalingMessage(callback: (msg: SignalingMessage) => void): void {
    this.signalingCallbacks.set('receive', callback)
  }

  /**
   * Get or create local audio stream
   */
  async getLocalStream(): Promise<MediaStream> {
    if (this.localStream) {
      return this.localStream
    }

    try {
      this.localStream = await navigator.mediaDevices.getUserMedia({
        audio: AUDIO_CONSTRAINTS,
        video: false,
      })

      // Setup audio level monitoring
      this.setupAudioLevelMonitoring(this.localStream)

      log.info('Local audio stream acquired')
      return this.localStream
    } catch (err) {
      log.error('Failed to get local audio stream:', err)
      throw new Error('Microphone access denied or not available')
    }
  }

  private setupAudioLevelMonitoring(stream: MediaStream): void {
    if (!this.audioContext) return

    try {
      const source = this.audioContext.createMediaStreamSource(stream)
      this.audioAnalyser = this.audioContext.createAnalyser()
      this.audioAnalyser.fftSize = 256
      this.audioAnalyser.smoothingTimeConstant = 0.8
      source.connect(this.audioAnalyser)
    } catch (err) {
      log.warn('Failed to setup audio level monitoring:', err)
    }
  }

  getAudioLevel(): number {
    if (!this.audioAnalyser) return 0

    const dataArray = new Uint8Array(this.audioAnalyser.frequencyBinCount)
    this.audioAnalyser.getByteFrequencyData(dataArray)

    let sum = 0
    for (let i = 0; i < dataArray.length; i++) {
      sum += dataArray[i]
    }
    return sum / dataArray.length / 255 // Normalize to 0-1
  }

  /**
   * Initiate an outgoing call
   */
  async startCall(peerId: string): Promise<ActiveCall> {
    const callId = `call_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`
    
    log.info(`Starting call to ${peerId}`, { callId })

    const localStream = await this.getLocalStream()

    const peerConnection = this.createPeerConnection(callId, peerId)
    
    // Add local tracks
    localStream.getTracks().forEach(track => {
      peerConnection.addTrack(track, localStream!)
    })

    // Create offer
    const offer = await peerConnection.createOffer({
      offerToReceiveAudio: true,
      offerToReceiveVideo: false,
    })
    await peerConnection.setLocalDescription(offer)

    const call: ActiveCall = {
      callId,
      peerId,
      direction: CallDirection.Outgoing,
      state: CallState.Dialing,
      startTime: null,
      peerConnection,
      localStream,
      remoteStream: null,
      audioLevel: 0,
    }

    this.activeCalls.set(callId, call)
    this.notifyCallStateChange(call)

    // Send offer via signaling
    await this.sendSignalingMessage({
      type: 'offer',
      callId,
      from: '', // Will be filled by transport layer
      to: peerId,
      payload: offer,
    })

    // Start call timeout
    setTimeout(() => {
      const call = this.activeCalls.get(callId)
      if (call && call.state === CallState.Dialing) {
        this.endCall(callId, CallEndReason.Timeout)
      }
    }, 30000) // 30 second timeout

    return call
  }

  /**
   * Handle incoming call offer
   */
  async handleIncomingOffer(message: SignalingMessage): Promise<void> {
    const { callId, from, payload } = message
    const offer = payload as RTCSessionDescriptionInit

    log.info(`Incoming call from ${from}`, { callId })

    const localStream = await this.getLocalStream()
    const peerConnection = this.createPeerConnection(callId, from)

    localStream.getTracks().forEach(track => {
      peerConnection.addTrack(track, localStream)
    })

    await peerConnection.setRemoteDescription(new RTCSessionDescription(offer))

    const call: ActiveCall = {
      callId,
      peerId: from,
      direction: CallDirection.Incoming,
      state: CallState.Ringing,
      startTime: null,
      peerConnection,
      localStream,
      remoteStream: null,
      audioLevel: 0,
    }

    this.activeCalls.set(callId, call)
    this.notifyCallStateChange(call)

    // Notify UI of incoming call
    this.onIncomingCall?.(call)
  }

  /**
   * Handle incoming answer to our offer
   */
  async handleAnswer(message: SignalingMessage): Promise<void> {
    const { callId, payload } = message
    const answer = payload as RTCSessionDescriptionInit

    const call = this.activeCalls.get(callId)
    if (!call || !call.peerConnection) {
      log.warn('No active call for answer', { callId })
      return
    }

    await call.peerConnection.setRemoteDescription(new RTCSessionDescription(answer))
    call.state = CallState.Connecting
    this.notifyCallStateChange(call)
  }

  /**
   * Handle incoming ICE candidate
   */
  async handleIceCandidate(message: SignalingMessage): Promise<void> {
    const { callId, payload } = message
    const candidate = payload as RTCIceCandidateInit

    const call = this.activeCalls.get(callId)
    if (!call || !call.peerConnection) {
      log.warn('No active call for ICE candidate', { callId })
      return
    }

    try {
      await call.peerConnection.addIceCandidate(new RTCIceCandidate(candidate))
    } catch (err) {
      log.error('Failed to add ICE candidate:', err)
    }
  }

  /**
   * Handle incoming hangup
   */
  async handleHangup(message: SignalingMessage): Promise<void> {
    const { callId, payload } = message
    const reason = (payload as { reason?: CallEndReason })?.reason || CallEndReason.RemoteHangup

    this.endCall(callId, reason)
  }

  /**
   * Accept an incoming call
   */
  async acceptCall(callId: string): Promise<void> {
    const call = this.activeCalls.get(callId)
    if (!call || call.direction !== CallDirection.Incoming) {
      throw new Error('No incoming call to accept')
    }

    const peerConnection = call.peerConnection
    const answer = await peerConnection.createAnswer()
    await peerConnection.setLocalDescription(answer)

    call.state = CallState.Connecting
    this.notifyCallStateChange(call)

    await this.sendSignalingMessage({
      type: 'answer',
      callId,
      from: '', // Filled by transport
      to: call.peerId,
      payload: answer,
    })
  }

  /**
   * Reject an incoming call
   */
  async rejectCall(callId: string): Promise<void> {
    const call = this.activeCalls.get(callId)
    if (!call || call.direction !== CallDirection.Incoming) {
      throw new Error('No incoming call to reject')
    }

    await this.sendSignalingMessage({
      type: 'reject',
      callId,
      from: '',
      to: call.peerId,
    })

    this.endCall(callId, CallEndReason.RemoteDeclined)
  }

  /**
   * End active call
   */
  async endCall(callId: string, reason: CallEndReason = CallEndReason.LocalHangup): Promise<void> {
    const call = this.activeCalls.get(callId)
    if (!call) return

    log.info(`Ending call ${callId}`, { reason })

    // Send hangup signal if call was connected
    if (call.state === CallState.Active || call.state === CallState.Connecting) {
      await this.sendSignalingMessage({
        type: 'hangup',
        callId,
        from: '',
        to: call.peerId,
        payload: { reason },
      })
    }

    // Clean up peer connection
    call.peerConnection.close()
    this.peerConnections.delete(callId)

    // Stop local stream tracks only if no other calls
    if (this.activeCalls.size <= 1 && this.localStream) {
      this.localStream.getTracks().forEach(track => track.stop())
      this.localStream = null
    }

    call.state = CallState.Ended
    call.remoteStream = null
    this.notifyCallStateChange(call)

    // Clean up after delay to allow UI to show ended state
    setTimeout(() => {
      this.activeCalls.delete(callId)
      this.notifyCallStateChange({ ...call, state: CallState.Idle } as ActiveCall)
    }, 1000)
  }

  /**
   * Toggle mute
   */
  setMuted(muted: boolean): void {
    if (this.localStream) {
      this.localStream.getAudioTracks().forEach(track => {
        track.enabled = !muted
      })
    }
  }

  /**
   * Switch audio output device
   */
  async setAudioOutputDevice(deviceId: string): Promise<void> {
    const audioElements = document.querySelectorAll('audio')
    for (const audio of audioElements) {
      try {
        await (audio as HTMLAudioElement).setSinkId(deviceId)
      } catch (err) {
        log.warn('Failed to set audio output device:', err)
      }
    }
  }

  /**
   * Get available audio output devices
   */
  async getAudioOutputDevices(): Promise<MediaDeviceInfo[]> {
    const devices = await navigator.mediaDevices.enumerateDevices()
    return devices.filter(d => d.kind === 'audiooutput')
  }

  /**
   * Get available audio input devices
   */
  async getAudioInputDevices(): Promise<MediaDeviceInfo[]> {
    const devices = await navigator.mediaDevices.enumerateDevices()
    return devices.filter(d => d.kind === 'audioinput')
  }

  // Private methods

  private createPeerConnection(callId: string, peerId: string): RTCPeerConnection {
    const config: RTCConfiguration = {
      iceServers: this.iceServers,
      iceCandidatePoolSize: 10,
      bundlePolicy: 'max-bundle',
    }

    const pc = new RTCPeerConnection(config)

    pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.sendSignalingMessage({
          type: 'ice-candidate',
          callId,
          from: '',
          to: peerId,
          payload: event.candidate.toJSON(),
        })
      }
    }

    pc.ontrack = (event) => {
      const call = this.activeCalls.get(callId)
      if (call) {
        call.remoteStream = event.streams[0]
        this.setupAudioLevelMonitoring(event.streams[0])
        call.state = CallState.Active
        call.startTime = new Date()
        this.notifyCallStateChange(call)
      }
    }

    pc.onconnectionstatechange = () => {
      const call = this.activeCalls.get(callId)
      if (!call) return

      switch (pc.connectionState) {
        case 'connected':
          if (call.state !== CallState.Active) {
            call.state = CallState.Active
            call.startTime = new Date()
            this.notifyCallStateChange(call)
          }
          break
        case 'disconnected':
        case 'failed':
          if (call.state === CallState.Active) {
            call.state = CallState.Reconnecting
            this.notifyCallStateChange(call)
            // Try to restart ICE
            setTimeout(() => pc.restartIce(), 1000)
          }
          break
        case 'closed':
          this.endCall(callId, CallEndReason.NetworkError)
          break
      }
    }

    pc.oniceconnectionstatechange = () => {
      log.debug('ICE connection state:', pc.iceConnectionState)
    }

    this.peerConnections.set(callId, pc)
    return pc
  }

  private async sendSignalingMessage(message: SignalingMessage): Promise<void> {
    const sendFn = this.signalingCallbacks.get('send')
    if (sendFn) {
      try {
        await sendFn(message)
      } catch (err) {
        log.error('Failed to send signaling message:', err)
      }
    } else {
      log.warn('No signaling transport registered')
    }
  }

  private notifyCallStateChange(call: ActiveCall): void {
    // Update audio level for active calls
    if (call.state === CallState.Active) {
      call.audioLevel = this.getAudioLevel()
    }

    this.callStateListeners.forEach(listener => listener(call))
  }

  // Public API for UI

  onIncomingCall?: (call: ActiveCall) => void
  onCallStateChange?: (call: ActiveCall) => void

  subscribeToCallState(listener: (call: ActiveCall) => void): () => void {
    const id = Math.random().toString(36).slice(2)
    this.callStateListeners.set(id, listener)
    return () => this.callStateListeners.delete(id)
  }

  getActiveCalls(): ActiveCall[] {
    return Array.from(this.activeCalls.values())
  }

  getCall(callId: string): ActiveCall | undefined {
    return this.activeCalls.get(callId)
  }

  isInCall(): boolean {
    return Array.from(this.activeCalls.values()).some(
      c => c.state === CallState.Active || c.state === CallState.Connecting
    )
  }

  /**
   * Cleanup all resources
   */
  async destroy(): Promise<void> {
    // End all active calls
    for (const callId of this.activeCalls.keys()) {
      await this.endCall(callId, CallEndReason.LocalHangup)
    }

    // Stop local stream
    if (this.localStream) {
      this.localStream.getTracks().forEach(track => track.stop())
      this.localStream = null
    }

    // Close audio context
    if (this.audioContext) {
      await this.audioContext.close()
      this.audioContext = null
    }

    this.peerConnections.clear()
    this.activeCalls.clear()
    this.signalingCallbacks.clear()
    this.callStateListeners.clear()
  }
}

// Singleton instance
export const webRTCCalling = new WebRTCCallingService()