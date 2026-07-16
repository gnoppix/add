/**
 *-------------------------------------------------------------------------------
 * Vault Unlock Dialog — TPM PIN or Passphrase entry
 *-------------------------------------------------------------------------------
 */

import { useState } from 'react'
import { useChatStore } from '../../store/chatStore'

interface VaultUnlockDialogProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
  hasTpm: boolean // Set true if system has TPM, false for passphrase mode
}

function VaultUnlockDialog({ isOpen, onClose, onSuccess, hasTpm }: VaultUnlockDialogProps) {
  const [pin, setPin] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isUnlocking, setIsUnlocking] = useState(false)

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsUnlocking(true)

    try {
      const api = window.addAPI
      if (!api) throw new Error('API not available')

      if (hasTpm && pin.length !== 6) {
        throw new Error('TPM PIN must be exactly 6 digits')
      }
      if (!hasTpm && password.length < 16) {
        throw new Error('Passphrase must be at least 16 characters')
      }

      await api.unlock({ pin: pin || undefined, password: password || undefined })
      onSuccess()
      setPin('')
      setPassword('')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setIsUnlocking(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="w-full max-w-sm rounded-lg bg-white p-6 dark:bg-gray-800">
        <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">
          {hasTpm ? 'Enter TPM PIN' : 'Enter Passphrase'}
        </h2>
        <form onSubmit={handleSubmit}>
          {hasTpm ? (
            <input
              type="password"
              inputMode="numeric"
              maxLength={6}
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))}
              placeholder="6-digit PIN"
              className="mb-4 w-full rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
              autoFocus
              required
            />
          ) : (
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="16-character passphrase"
              className="mb-4 w-full rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
              autoFocus
              required
            />
          )}
          {error && (
            <p className="mb-3 text-sm text-red-500">{error}</p>
          )}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={isUnlocking}
              className="flex-1 rounded border border-gray-300 px-4 py-2 dark:border-gray-600"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isUnlocking}
              className="flex-1 rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {isUnlocking ? 'Unlocking...' : 'Unlock'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default VaultUnlockDialog