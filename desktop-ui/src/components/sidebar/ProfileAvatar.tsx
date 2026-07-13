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

import { useRef } from 'react'
import { useProfileStore } from '../../store/profileStore'
import { useChatStore } from '../../store/chatStore'
import { generateIdenticon } from '../../lib/identicon'

export default function ProfileAvatar({ size = 32 }: { size?: number }) {
  const { avatarUrl, setAvatar } = useProfileStore()
  const { myId } = useChatStore()
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (e) => {
      if (e.target?.result) {
        setAvatar(e.target.result as string)
      }
    }
    reader.readAsDataURL(file)
  }

  const handleClick = () => {
    fileInputRef.current?.click()
  }

  const sizeClasses = {
    32: 'w-8 h-8',
    40: 'w-10 h-10',
    48: 'w-12 h-12',
  }[size] || 'w-8 h-8'

  return (
    <div className="relative inline-block">
      <button
        onClick={handleClick}
        className={`${sizeClasses} flex items-center justify-center rounded-full bg-primary-500 text-white overflow-hidden transition-opacity hover:opacity-80`}
        aria-label="Change profile picture"
        title={avatarUrl ? 'Change profile picture' : 'Add profile picture'}
      >
        {avatarUrl ? (
          <img src={avatarUrl} alt="Profile" className="w-full h-full object-cover" />
        ) : myId ? (
          <img src={generateIdenticon(myId)} alt="Profile" className="w-full h-full object-cover" />
        ) : (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14v7m-3 0h6" />
          </svg>
        )}
      </button>
      
      {myId && (
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity">
          {myId}
        </div>
      )}

      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        onChange={handleFileSelect}
        className="hidden"
      />
    </div>
  )
}