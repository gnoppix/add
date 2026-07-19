/**
 *-------------------------------------------------------------------------------
 * Security Settings - Self-destruct threshold configuration
 *-------------------------------------------------------------------------------
 */

import { useSettingsStore } from '../../store/settingsStore'

interface SecuritySettingsProps {
  onClose?: () => void
}

export default function SecuritySettings({ onClose }: SecuritySettingsProps) {
  const { security, setSelfDestructEnabled, setSelfDestructThreshold } = useSettingsStore()

  return (
    <div className="p-4">
      <h2 className="mb-4 text-lg font-semibold">Security Settings</h2>
      
      <div className="mb-4">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={security.selfDestructEnabled}
            onChange={(e) => setSelfDestructEnabled(e.target.checked)}
            className="h-4 w-4"
          />
          Enable self-destruct after failed unlock attempts
        </label>
      </div>

      {security.selfDestructEnabled && (
        <div className="mb-4">
          <label className="block text-sm font-medium mb-1">
            Failed attempts before wipe
          </label>
          <select
            value={security.selfDestructThreshold}
            onChange={(e) => setSelfDestructThreshold(Number(e.target.value))}
            className="w-full rounded border border-gray-300 px-2 py-1 dark:border-gray-600 dark:bg-gray-700"
          >
            <option value={3}>3 attempts</option>
            <option value={5}>5 attempts</option>
            <option value={7}>7 attempts</option>
            <option value={10}>10 attempts (default)</option>
            <option value={15}>15 attempts</option>
            <option value={20}>20 attempts</option>
          </select>
          <p className="mt-1 text-xs text-gray-500">
            After this many wrong PIN/password entries, all identity data will be wiped.
          </p>
        </div>
      )}

      {onClose && (
        <button
          onClick={onClose}
          className="mt-4 rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
        >
          Close
        </button>
      )}
    </div>
  )
}