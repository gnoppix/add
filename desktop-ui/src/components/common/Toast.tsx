/**
 * Toast - Simple toast notification system
 */

import { useState, useCallback, type JSX, createContext, useContext, type ReactNode } from 'react'

export type ToastType = 
  | 'info' 
  | 'success' 
  | 'warning' 
  | 'error' 
  | 'microphone-permission'

export interface Toast {
  id: string
  type: ToastType
  message: string
  duration?: number // ms, default 5000
}

interface ToastContextValue {
  toasts: Toast[]
  showToast: (toast: Omit<Toast, 'id'>) => void
  hideToast: (id: string) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

export function ToastProvider({ children }: { children: ReactNode }): JSX.Element {
  const [toasts, setToasts] = useState<Toast[]>([])

  const showToast = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).slice(2, 9)
    const newToast = { ...toast, id }
    setToasts(prev => [...prev, newToast])
    
    // Auto-hide after duration
    if (toast.duration !== 0) {
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== id))
      }, toast.duration ?? 5000)
    }
  }, [])

  const hideToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ toasts, showToast, hideToast }}>
      {children}
      <ToastContainer toasts={toasts} onHide={hideToast} />
    </ToastContext.Provider>
  )
}

function ToastContainer({ toasts, onHide }: { toasts: Toast[]; onHide: (id: string) => void }): JSX.Element {
  return (
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
      {toasts.map(toast => (
        <ToastItem key={toast.id} toast={toast} onClose={onHide} />
      ))}
    </div>
  )
}

function ToastItem({ toast, onClose }: { toast: Toast; onClose: (id: string) => void }): JSX.Element {
  const getStyles = () => {
    switch (toast.type) {
      case 'success':
        return 'bg-green-600 text-white'
      case 'warning':
        return 'bg-yellow-600 text-white'
      case 'error':
        return 'bg-red-600 text-white'
      case 'microphone-permission':
        return 'bg-orange-600 text-white'
      default:
        return 'bg-blue-600 text-white'
    }
  }

  const getIcon = () => {
    switch (toast.type) {
      case 'success':
        return (
          <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
          </svg>
        )
      case 'warning':
        return (
          <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
        )
      case 'error':
        return (
          <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
        )
      case 'microphone-permission':
        return (
          <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
            <path d="M17 9.344V4.656A3.656 3.656 0 0013.344 1H6.656A3.656 3.656 0 003 4.656v10.688A3.656 3.656 0 006.656 19h6.688a3.656 3.656 0 003.656-3.656V9.344zM6.656 2a2.656 2.656 0 00-2.656 2.656v10.688a2.656 2.656 0 002.656 2.656h6.688a2.656 2.656 0 002.656-2.656V4.656a2.656 2.656 0 00-2.656-2.656H6.656zm0 16.656V4.656a1.656 1.656 0 011.656-1.656h6.688a1.656 1.656 0 011.656 1.656v10.688a1.656 1.656 0 01-1.656 1.656H6.656zm6.344-2.005a1 1 0 10-2 0v1a1 1 0 102 0v-1zm0-9a1 1 0 10-2 0v6a1 1 0 102 0V4z" />
          </svg>
        )
      default:
        return (
          <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
        )
    }
  }

  return (
    <div
      className={`flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg min-w-[280px] max-w-md pointer-events-auto animate-slide-in ${getStyles()}`}
      role="alert"
      aria-live="polite"
    >
      {getIcon()}
      <p className="flex-1 text-sm">{toast.message}</p>
      <button
        onClick={() => onClose(toast.id)}
        className="flex-shrink-0 p-1 rounded hover:bg-white/20 transition-colors"
        aria-label="Dismiss"
      >
        <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
          <path d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" />
        </svg>
      </button>
    </div>
  )
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context
}

// Helper function for microphone permission errors
export function showMicrophonePermissionToast(showToast: (toast: Omit<Toast, 'id'>) => void) {
  showToast({
    type: 'microphone-permission',
    message: 'Microphone access denied. Please allow microphone permission in your browser settings to record voice messages.',
    duration: 10000,
  })
}