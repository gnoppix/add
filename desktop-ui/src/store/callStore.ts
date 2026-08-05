/**
 * Call Store - State management for P2P voice calls
 */

import { create } from 'zustand'
import { webRTCCalling, type ActiveCall, type SignalingMessage, CallState } from '../services/webRTCCalling'
import { callSounds } from '../services/audioEffects'

interface CallStore {
  // State
  calls: Map<string, ActiveCall>
  incomingCall: ActiveCall | null
  isInCall: boolean
  currentCallId: string | null
  muted: boolean
  audioOutputDevice: string | null
  availableOutputDevices: MediaDeviceInfo[]
  availableInputDevices: MediaDeviceInfo[]

  // Actions
  initialize: () => Promise<void>
  startCall: (peerId: string) => Promise<void>
  acceptCall: (callId: string) => Promise<void>
  rejectCall: (callId: string) => Promise<void>
  endCall: (callId: string) => Promise<void>
  toggleMute: () => void
  setAudioOutputDevice: (deviceId: string) => Promise<void>
  refreshAudioDevices: () => Promise<void>
  handleSignalingMessage: (message: SignalingMessage) => Promise<void>
  updateCallState: (call: ActiveCall) => void
  setIncomingCall: (call: ActiveCall) => void
  
  // Getters
  getActiveCall: () => ActiveCall | null | undefined
  getCall: (callId: string) => ActiveCall | undefined
  getCallDuration: (callId: string) => number
}

// Call the webRTC service to set up signaling
function setupSignalingTransport(sendFn: (msg: SignalingMessage) => Promise<void>) {
  webRTCCalling.registerSignalingTransport(sendFn)
  webRTCCalling.onSignalingMessage((msg) => {
    useCallStore.getState().handleSignalingMessage(msg)
  })
}

// Listen for call state changes
webRTCCalling.onCallStateChange = (call) => {
  useCallStore.getState().updateCallState(call)
}

webRTCCalling.onIncomingCall = (call) => {
  useCallStore.getState().setIncomingCall(call)
}

export const useCallStore = create<CallStore>((set, get) => ({
  calls: new Map(),
  incomingCall: null,
  isInCall: false,
  currentCallId: null,
  muted: false,
  audioOutputDevice: null,
  availableOutputDevices: [],
  availableInputDevices: [],

  initialize: async () => {
    try {
      // Request microphone permission on init
      await webRTCCalling.getLocalStream()
      
      // Preload sounds
      const { preloadSounds } = await import('../services/audioEffects')
      await preloadSounds()
      
      // Load audio devices
      const [outputDevices, inputDevices] = await Promise.all([
        webRTCCalling.getAudioOutputDevices(),
        webRTCCalling.getAudioInputDevices(),
      ])
      
      set({
        availableOutputDevices: outputDevices,
        availableInputDevices: inputDevices,
      })
      
      // Set default audio output device
      if (outputDevices.length > 0) {
        set({ audioOutputDevice: outputDevices[0].deviceId })
      }
    } catch (err) {
      console.error('[CallStore] Failed to initialize:', err)
    }
  },

  startCall: async (peerId: string) => {
    try {
      // Play ringback tone
      callSounds.playOutgoingRingback()
      
      const call = await webRTCCalling.startCall(peerId)
      
      set(state => {
        const newCalls = new Map(state.calls)
        newCalls.set(call.callId, call)
        return {
          calls: newCalls,
          currentCallId: call.callId,
          isInCall: true,
        }
      })
    } catch (err) {
      console.error('[CallStore] Failed to start call:', err)
      callSounds.stopRingback()
      callSounds.playCallEnded()
      throw err
    }
  },

  acceptCall: async (callId: string) => {
    try {
      // Stop ringtone
      callSounds.stopRingtone()
      callSounds.playCallAccepted()
      
      await webRTCCalling.acceptCall(callId)
      
      set(state => {
        const newCalls = new Map(state.calls)
        const call = newCalls.get(callId)
        if (call) {
          newCalls.set(callId, { ...call, state: CallState.Connecting })
        }
        return {
          calls: newCalls,
          incomingCall: null,
          currentCallId: callId,
          isInCall: true,
        }
      })
    } catch (err) {
      console.error('[CallStore] Failed to accept call:', err)
      callSounds.playCallEnded()
      throw err
    }
  },

  rejectCall: async (callId: string) => {
    try {
      callSounds.stopRingtone()
      callSounds.playCallRejected()
      
      await webRTCCalling.rejectCall(callId)
      
      set(state => {
        const newCalls = new Map(state.calls)
        newCalls.delete(callId)
        return {
          calls: newCalls,
          incomingCall: state.incomingCall?.callId === callId ? null : state.incomingCall,
        }
      })
    } catch (err) {
      console.error('[CallStore] Failed to reject call:', err)
      throw err
    }
  },

  endCall: async (callId: string) => {
    try {
      callSounds.stopRingback()
      callSounds.stopRingtone()
      callSounds.playCallEnded()
      
      await webRTCCalling.endCall(callId)
      
      set(state => {
        const newCalls = new Map(state.calls)
        newCalls.delete(callId)
        return {
          calls: newCalls,
          currentCallId: state.currentCallId === callId ? null : state.currentCallId,
          isInCall: newCalls.size > 0,
        }
      })
    } catch (err) {
      console.error('[CallStore] Failed to end call:', err)
      throw err
    }
  },

  toggleMute: () => {
    const newMuted = !get().muted
    webRTCCalling.setMuted(newMuted)
    set({ muted: newMuted })
  },

  setAudioOutputDevice: async (deviceId: string) => {
    await webRTCCalling.setAudioOutputDevice(deviceId)
    set({ audioOutputDevice: deviceId })
  },

  refreshAudioDevices: async () => {
    const [outputDevices, inputDevices] = await Promise.all([
      webRTCCalling.getAudioOutputDevices(),
      webRTCCalling.getAudioInputDevices(),
    ])
    set({ availableOutputDevices: outputDevices, availableInputDevices: inputDevices })
  },

  handleSignalingMessage: async (message: SignalingMessage) => {
    const { type } = message
    
    switch (type) {
      case 'offer':
        await webRTCCalling.handleIncomingOffer(message)
        break
      case 'answer':
        await webRTCCalling.handleAnswer(message)
        break
      case 'ice-candidate':
        await webRTCCalling.handleIceCandidate(message)
        break
      case 'hangup':
        await webRTCCalling.handleHangup(message)
        break
      case 'reject':
        // Remote rejected our call
        {
          const callId = message.callId
          callSounds.stopRingback()
          callSounds.playCallRejected()
          set(state => {
            const newCalls = new Map(state.calls)
            newCalls.delete(callId)
            return {
              calls: newCalls,
              currentCallId: state.currentCallId === callId ? null : state.currentCallId,
              isInCall: newCalls.size > 0,
            }
          })
        }
        break
      case 'busy':
        // Remote is busy
        callSounds.stopRingback()
        callSounds.playCallBusy()
        break
      case 'accept':
        // Remote accepted our call
        callSounds.stopRingback()
        callSounds.playCallAccepted()
        break
    }
  },

  // Internal state updates
  updateCallState: (call: ActiveCall) => {
    set(state => {
      const newCalls = new Map(state.calls)
      newCalls.set(call.callId, call)
      return {
        calls: newCalls,
        isInCall: Array.from(newCalls.values()).some(
          c => c.state === 'active' || c.state === 'connecting'
        ),
      }
    })
  },

  setIncomingCall: (call: ActiveCall) => {
    set(state => {
      const newCalls = new Map(state.calls)
      newCalls.set(call.callId, call)
      return {
        calls: newCalls,
        incomingCall: call,
        currentCallId: call.callId,
      }
    })
    // Play ringtone
    callSounds.playIncomingRingtone()
  },

  // Getters
  getActiveCall: () => {
    const state = get()
    if (state.currentCallId) {
      return state.calls.get(state.currentCallId)
    }
    return Array.from(state.calls.values()).find(
      c => c.state === 'active' || c.state === 'connecting'
    ) || null
  },

  getCall: (callId: string) => {
    return get().calls.get(callId)
  },

  getCallDuration: (callId: string) => {
    const call = get().calls.get(callId)
    if (!call || !call.startTime) return 0
    return Date.now() - call.startTime.getTime()
  },
}))

// Export the signaling transport setter for use in App.tsx
export { setupSignalingTransport, webRTCCalling }