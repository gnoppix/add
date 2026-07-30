/**
 * Backup Settings - Backup and restore ~/.add directory
 */
import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'

interface BackupItem {
  name: string
  path: string
  size: number
  mtime: string
}

interface BackupSettingsProps {
  onClose: () => void
}

export default function BackupSettings({ onClose }: BackupSettingsProps) {
  const { t } = useTranslation()
  const [backups, setBackups] = useState<BackupItem[]>([])
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState<string>('')
  const [messageType, setMessageType] = useState<'success' | 'error' | ''>('')
  const [showConfirm, setShowConfirm] = useState<string | null>(null)
  const [actionType, setActionType] = useState<'restore' | 'delete' | null>(null)

  useEffect(() => {
    loadBackups()
  }, [])

  const loadBackups = async () => {
    setLoading(true)
    try {
      const api = window.addAPI
      if (!api) {
        setMessage(t('ui.backup.loadError') + ': API not available')
        setMessageType('error')
        return
      }
      const result = await api.listBackups()
      if (result.success) {
        setBackups(result.backups || [])
      } else {
        setMessage(t('ui.backup.loadError') + ': ' + result.error)
        setMessageType('error')
      }
    } catch (err) {
      setMessage(
        t('ui.backup.loadError') + ': ' + (err instanceof Error ? err.message : String(err))
      )
      setMessageType('error')
    } finally {
      setLoading(false)
    }
  }

  const handleBackup = async () => {
    setLoading(true)
    setMessage('')
    try {
      const result = await window.addAPI.backup()
      if (result.success) {
        setMessage(t('ui.backup.created') + ' ' + result.backupName)
        setMessageType('success')
        loadBackups()
      } else {
        setMessage(t('ui.backup.createError') + ': ' + result.error)
        setMessageType('error')
      }
    } catch (err) {
      setMessage(
        t('ui.backup.createError') + ': ' + (err instanceof Error ? err.message : String(err))
      )
      setMessageType('error')
    } finally {
      setLoading(false)
    }
  }

  const handleRestore = async (backupName: string) => {
    setShowConfirm(backupName)
    setActionType('restore')
  }

  const handleDelete = async (backupName: string) => {
    setShowConfirm(backupName)
    setActionType('delete')
  }

  const confirmAction = async () => {
    if (!showConfirm) return

    setLoading(true)
    setMessage('')

    try {
      if (actionType === 'restore') {
        const result = await window.addAPI.restore(showConfirm)
        if (result.success) {
          setMessage(t('ui.backup.restored') + ' ' + showConfirm)
          setMessageType('success')
          loadBackups()
        } else {
          setMessage(t('ui.backup.restoreError') + ': ' + result.error)
          setMessageType('error')
        }
      } else if (actionType === 'delete') {
        const result = await window.addAPI.deleteBackup(showConfirm)
        if (result.success) {
          setMessage(t('ui.backup.deleted') + ' ' + showConfirm)
          setMessageType('success')
          loadBackups()
        } else {
          setMessage(t('ui.backup.deleteError') + ': ' + result.error)
          setMessageType('error')
        }
      }
    } catch (err) {
      setMessage(
        (actionType === 'restore' ? t('ui.backup.restoreError') : t('ui.backup.deleteError')) +
          ': ' +
          (err instanceof Error ? err.message : String(err))
      )
      setMessageType('error')
    } finally {
      setLoading(false)
      setShowConfirm(null)
      setActionType(null)
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr)
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString()
  }

  return (
    <div className="w-96 rounded-lg bg-white p-6 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold">{t('ui.settings.backupSettings')}</h2>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600" aria-label="Close">
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      </div>

      {message && (
        <div
          className={`mb-4 rounded p-2 text-xs ${
            messageType === 'success' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
          }`}
        >
          {message}
        </div>
      )}

      <div className="space-y-3">
        <div className="border-b pb-3">
          <p className="font-medium mb-2">{t('ui.backup.create')}</p>
          <button
            onClick={handleBackup}
            disabled={loading}
            className="w-full rounded bg-primary-500 px-3 py-1.5 text-sm text-white hover:bg-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? t('ui.backup.creating') : t('ui.backup.createBtn')}
          </button>
          <p className="mt-1 text-xs text-gray-500">{t('ui.backup.createDesc')}</p>
        </div>

        <div className="border-b pb-3">
          <h3 className="font-medium mb-2">{t('ui.backup.availableBackups')}</h3>
          {loading ? (
            <div className="text-center py-4 text-sm text-gray-500">{t('ui.backup.loading')}</div>
          ) : backups.length === 0 ? (
            <div className="py-4 text-center text-sm text-gray-500">{t('ui.backup.noBackups')}</div>
          ) : (
            <div className="max-h-60 overflow-y-auto space-y-2">
              {backups.map(backup => (
                <div
                  key={backup.name}
                  className="flex items-center justify-between p-2 rounded border bg-gray-50"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{backup.name}</p>
                    <p className="text-xs text-gray-500">
                      {formatDate(backup.mtime)} • {formatSize(backup.size)}
                    </p>
                  </div>
                  <div className="flex gap-1 ml-2">
                    <button
                      onClick={() => handleRestore(backup.name)}
                      disabled={loading}
                      className="rounded bg-green-500 px-2 py-1 text-xs text-white hover:bg-green-600 disabled:opacity-50"
                    >
                      {t('ui.backup.restore')}
                    </button>
                    <button
                      onClick={() => handleDelete(backup.name)}
                      disabled={loading}
                      className="rounded bg-red-500 px-2 py-1 text-xs text-white hover:bg-red-600 disabled:opacity-50"
                    >
                      {t('ui.backup.delete')}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="border-t pt-3">
          <p className="text-xs text-gray-500 text-center mb-2">{t('ui.backup.maxBackups')}</p>
          <p className="text-xs text-gray-500 text-center">{t('ui.backup.autoCleanup')}</p>
        </div>

        {/* Confirmation Modal */}
        {showConfirm && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="w-96 rounded-lg bg-white p-6 shadow-xl">
              <h3 className="mb-4 text-lg font-semibold">
                {actionType === 'restore'
                  ? t('ui.backup.confirmRestore')
                  : t('ui.backup.confirmDelete')}
              </h3>
              <p className="mb-4 text-sm text-gray-600">
                {actionType === 'restore'
                  ? t('ui.backup.confirmRestoreDesc') + ' ' + showConfirm
                  : t('ui.backup.confirmDeleteDesc') + ' ' + showConfirm}
              </p>
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => {
                    setShowConfirm(null)
                    setActionType(null)
                  }}
                  className="rounded bg-gray-100 px-3 py-1.5 text-sm hover:bg-gray-200"
                >
                  {t('ui.common.cancel')}
                </button>
                <button
                  onClick={confirmAction}
                  disabled={loading}
                  className={`rounded px-3 py-1.5 text-sm ${
                    actionType === 'restore'
                      ? 'bg-green-500 text-white hover:bg-green-600'
                      : 'bg-red-500 text-white hover:bg-red-600'
                  } disabled:opacity-50`}
                >
                  {loading
                    ? t('ui.common.loading')
                    : actionType === 'restore'
                      ? t('ui.backup.restore')
                      : t('ui.backup.delete')}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
