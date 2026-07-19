/**
 *-------------------------------------------------------------------------------
 * Name: Gnoppix Linux - Services
 * Architecture: all
 * Date: 2002-2026 by Gnoppix Linux
 * Author: Andreas Mueller
 * Website: https://www.gnoppix.com
 * Licence: Business Source License (BSL / BUSL)
 * You can use the code for free if your company or organisation doesn't have more than 2 people.
 *-------------------------------------------------------------------------------
 */

/** Empty state placeholder when no conversation is selected */
function EmptyState() {
  return (
    <div className="flex h-full flex-col items-center justify-center bg-light-background dark:bg-dark-background">
      <div className="mb-4 h-24 w-24 rounded-full bg-gray-100 dark:bg-gray-800" />
      <h2 className="mb-2 text-lg font-medium text-gray-900 dark:text-white">
        Select a conversation to start messaging
      </h2>
      <p className="text-sm text-gray-500 dark:text-gray-400">
        Choose from your conversations on the left or start a new one
      </p>
    </div>
  )
}

export default EmptyState
