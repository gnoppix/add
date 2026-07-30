/**
 * Create Identity Dialog — Modern onboarding flow for first-time users.
 * Support for passphrase vault creation.
 */

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { getEvaAPI } from '../../store/chatStore'

interface CreateIdentityDialogProps {
  onCreated: () => void
}

export function CreateIdentityDialog({ onCreated }: CreateIdentityDialogProps) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isCreating, setIsCreating] = useState(false)
  const { t } = useTranslation()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsCreating(true)

    try {
      const api = getEvaAPI()
      if (!api) throw new Error('Add API not available')

      if (password.length < 16)
        throw new Error(
          t('ui.createIdentity.passphraseMinLength', 'Passphrase must be at least 16 characters')
        )
      if (password !== confirm)
        throw new Error(t('ui.createIdentity.passphraseMismatch', 'Passphrases do not match'))
      // Validate complexity: upper, lower, digit, special
      if (
        !/[A-Z]/.test(password) ||
        !/[a-z]/.test(password) ||
        !/[0-9]/.test(password) ||
        !/[^A-Za-z0-9]/.test(password)
      ) {
        throw new Error(
          t(
            'ui.createIdentity.passphraseComplexity',
            'Passphrase must contain upper, lower, digit, and special character'
          )
        )
      }
      await api.init({ password })
      onCreated()
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setIsCreating(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-md rounded-lg bg-white p-6 dark:bg-gray-800">
        <h2 className="mb-2 text-lg font-semibold text-gray-900 dark:text-white">
          {t('ui.createIdentity.title')}
        </h2>
        <p className="mb-6 text-sm text-gray-600 dark:text-gray-400">
          {t('ui.createIdentity.subtitle')}
        </p>

        {error && <p className="mb-4 text-sm text-red-500">{error}</p>}

        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              {t('ui.createIdentity.passwordLabel')}
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder={t('ui.createIdentity.passwordPlaceholder')}
              minLength={16}
              className="w-full rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
              autoFocus
              required
              disabled={isCreating}
              aria-describedby="password-hint"
            />
            <p id="password-hint" className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {t('ui.createIdentity.passwordHint')}
            </p>
          </div>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              {t('ui.createIdentity.confirmLabel')}
            </label>
            <input
              type="password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              placeholder={t('ui.createIdentity.confirmPlaceholder')}
              className="w-full rounded border border-gray-300 px-3 py-2 dark:border-gray-600 dark:bg-gray-700"
              required
              disabled={isCreating}
            />
          </div>

          {error && <p className="mb-4 text-sm text-red-500">{error}</p>}

          <button
            type="submit"
            disabled={isCreating || password.length < 16 || password !== confirm}
            className="w-full rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isCreating ? t('ui.createIdentity.creating') : t('ui.createIdentity.create')}
          </button>
        </form>
      </div>
    </div>
  )
}
