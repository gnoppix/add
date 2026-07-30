/**
 *-------------------------------------------------------------------------------
 * UI Settings - Auto-start listener configuration
 *-------------------------------------------------------------------------------
 */

import { useTranslation } from 'react-i18next'
import { useSettingsStore } from '../../store/settingsStore'

interface UISettingsProps {
  onClose?: () => void
}

export default function UISettings({ onClose }: UISettingsProps) {
  const { ui, setAutoStartListener } = useSettingsStore()
  const { t } = useTranslation()

  return (
    <div className="p-4">
      <h2 className="mb-4 text-lg font-semibold">{t('ui.settings.uiSettings')}</h2>

      <div className="mb-4">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={ui.autoStartListener}
            onChange={e => setAutoStartListener(e.target.checked)}
            className="h-4 w-4"
          />
          {t('ui.settings.autoStartListener')}
        </label>
        <p className="mt-1 text-xs text-gray-500">{t('ui.settings.autoStartListenerDesc')}</p>
      </div>

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
