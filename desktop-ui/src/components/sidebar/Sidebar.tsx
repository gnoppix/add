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

/** Sidebar container component */
import SidebarHeader from './SidebarHeader'
import SearchBar from './SearchBar'
import ConversationList from './ConversationList'

function Sidebar() {
  return (
    <aside className="flex h-full w-[30%] min-w-[280px] max-w-[400px] flex-col border-r border-gray-200 dark:border-gray-700 bg-white dark:bg-dark-sidebar">
      <SidebarHeader />
      <SearchBar />
      <ConversationList />
    </aside>
  )
}

export default Sidebar