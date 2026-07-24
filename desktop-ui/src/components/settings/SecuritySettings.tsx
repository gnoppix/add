/**
 *-------------------------------------------------------------------------------
 * Security Settings - Self-destruct threshold configuration
 *-------------------------------------------------------------------------------
 */

import { useTranslation } from 'react-i18next'
import { useSettingsStore } from '../../store/settingsStore'

interface SecuritySettingsProps {
  onClose?: () => void
}

export default function SecuritySettings({ onClose }: SecuritySettingsProps) {
  const { security, setSelfDestructEnabled, setSelfDestructThreshold } = useSettingsStore()
  const { t } = useTranslation()

  return (
    <div className="p-4">
      <h2 className="mb-4 text-lg font-semibold">
        {t('ui.settings.securitySettings')}
      </h2>
      
      <div className="mb-4">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={security.selfDestructEnabled}
            onChange={(e) => setSelfDestructEnabled(e.target.checked)}
            className="h-4 w-4"
          />
          {t('ui.settings.enableSelfDestruct')}
        </label>
      </div>

      {security.selfDestructEnabled && (
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">
            {t('ui.settings.failedAttemptsBeforeWipe')}
          </label>
          <select
            value={security.selfDestructThreshold}
            onChange={(e) => setSelfDestructThreshold(Number(e.target.value))}
            className="w-full rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700"
          >
            <option value={3}>{t('ui.settings.attempts', { count: 3 })}</option>
            <option value={5}>{t('ui.settings.attempts', { count: 5 })}</option>
            <option value={7}>{t('ui.settings.attempts', { count: 7 })}</option>
            <option value={10}>{t('ui.settings.attempts', { count: 10 })}</option>
            <option value={15}>{t('ui.settings.attempts', { count: 15 })}</option>
            <option value={20}>{t('ui.settings.attempts', { count: 20 })}</option>
          </select>
          <p className="mt-1 text-xs text-gray-500">
            {t('ui.settings.afterWrongEntriesWiped')}
          </p>
        </div>
      )}

      {onClose && (
        <button
          onClick={onClose}
          className="mt-4 rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
        >
          {t('ui.sidebar.close')}
        </button>
      )}
    </div>
  )
}