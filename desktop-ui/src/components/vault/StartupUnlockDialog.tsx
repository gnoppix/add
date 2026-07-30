/**
 * Startup Unlock Dialog — DB passphrase entry at application start.
 * The passphrase is stored in main-process memory only (never persisted to disk).
 * Cleared on app exit.
 */

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useChatStore } from '../../store/chatStore'

interface StartupUnlockDialogProps {
  onUnlock: () => void
}

export function StartupUnlockDialog({ onUnlock }: StartupUnlockDialogProps) {
  const [passphrase, setPassphrase] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isUnlocking, setIsUnlocking] = useState(false)
  const { submitPassphrase } = useChatStore()
  const { t } = useTranslation()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsUnlocking(true)
    console.log('[StartupUnlockDialog] Submitting passphrase...')

    try {
      const result = await submitPassphrase(passphrase)
      console.log('[StartupUnlockDialog] submitPassphrase result:', result)
      setPassphrase('')
      onUnlock()
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.error('[StartupUnlockDialog] submitPassphrase error:', msg)
      setError(msg)
    } finally {
      setIsUnlocking(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded-lg bg-white p-6 dark:bg-gray-800">
        <h2 className="mb-4 text-lg font-semibold text-gray-900 dark:text-white">
          {t('ui.unlock.loginWithPassword')}
        </h2>
        <p className="mb-4 text-sm text-gray-600 dark:text-gray-400">
          {t('ui.unlock.enterPassphraseDesc')}
        </p>
        {error && <p className="mb-4 text-sm text-red-500">{error}</p>}
        <form onSubmit={handleSubmit}>
          <input
            type="password"
            value={passphrase}
            onChange={e => setPassphrase(e.target.value)}
            placeholder={t('ui.unlock.yourPassphrase')}
            className="mb-4 w-full rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
            autoFocus
            required
            disabled={isUnlocking}
          />
          <button
            type="submit"
            disabled={isUnlocking || passphrase.length === 0}
            className="w-full rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isUnlocking ? 'Unlocking...' : 'Unlock'}
          </button>
        </form>
      </div>
    </div>
  )
}
