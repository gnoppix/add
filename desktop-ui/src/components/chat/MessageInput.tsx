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

/** Message input bar with multi-line support, emoji picker, TTL picker, and action buttons */
import { useState, useRef, useEffect } from 'react'
import { useChatStore } from '../../store/chatStore'
import { MAX_ATTACHMENT_BYTES } from '../../types'
import { fileToBase64, encodeAttachment, formatBytes, MAX_ATTACHMENT_LABEL, downscaleImageDataUrl } from '../../lib/attachment'
import { EmojiImg, emojiToUrl } from '../common/EmojiImg'
import { StickerImg } from '../common/StickerImg'
// Only emoji that actually have a Moetwemoji GIF asset — every entry here is
// guaranteed to render as an animated sticker (L2). Replaces the old hardcoded
// EMOJI_CATEGORIES enum whose entries could silently fall back to Unicode.
import rawEmojiCategories from '../../emoji/filtered_categories.json'
const EMOJI_CATEGORIES = rawEmojiCategories as unknown as Record<string, string[]>
// Generic sticker pack (non-codepoint files, e.g. Telegram-style webp).
import STICKER_PACK from '../../emoji/sticker_pack.json'
const STICKERS = STICKER_PACK as string[]

// Free Unicode emojis (no copyright issues) organized by category
function MessageInput() {
  const [message, setMessage] = useState('')
  const [showEmojiPicker, setShowEmojiPicker] = useState(false)
  const [showTtlPicker, setShowTtlPicker] = useState(false)
  const [selectedTtl, setSelectedTtl] = useState<string | null>(null)
  const [activeEmojiCategory, setActiveEmojiCategory] = useState('Base Stickers')
  const [showStickerTab, setShowStickerTab] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const emojiPickerRef = useRef<HTMLDivElement>(null)
  const ttlPickerRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [attachError, setAttachError] = useState<string | null>(null)
  const [attachBusy, setAttachBusy] = useState(false)
  // Staged attachment awaiting confirmation (preview before send).
  const [pending, setPending] = useState<{ name: string; mime: string; size: number; data: string } | null>(null)
  const { activeConversationId, sendMessage } = useChatStore()

  // Open the native file picker when the paper-clip is clicked.
  const handleAttachClick = () => {
    if (attachBusy || !activeConversationId) return
    setAttachError(null)
    fileInputRef.current?.click()
  }

  // Read the chosen file, enforce the 2 MB cap, and stage it for preview.
  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    // Always reset so selecting the same file again re-triggers change.
    if (e.target.value !== null) e.target.value = ''
    if (!file || !activeConversationId) return

    if (file.size > MAX_ATTACHMENT_BYTES) {
      setAttachError(
        `File too large (${formatBytes(file.size)}). Maximum is ${MAX_ATTACHMENT_LABEL}.`
      )
      return
    }

    setAttachBusy(true)
    try {
      const data = await fileToBase64(file)
      // Stage the attachment and show a preview; the user confirms with send.
      setPending({
        name: file.name,
        mime: file.type || 'application/octet-stream',
        size: file.size,
        data,
      })
      setAttachError(null)
    } catch {
      setAttachError('Could not read the selected file.')
    } finally {
      setAttachBusy(false)
    }
  }

  // Send the staged attachment.
  const sendPending = async () => {
    if (!pending || !activeConversationId) return
    const envelope = encodeAttachment({
      name: pending.name,
      mime: pending.mime,
      size: pending.size,
      data: pending.data,
    })
    setPending(null)
    resetTextareaHeight()
    sendMessage(envelope,
      selectedTtl && selectedTtl !== 'none' ? selectedTtl : undefined)
  }

  const cancelPending = () => {
    setPending(null)
    setAttachError(null)
  }

  // TTL options: hours, days
  const TTL_OPTIONS = [
    { label: '2 hours', value: '2h' },
    { label: '12 hours', value: '12h' },
    { label: '24 hours', value: '24h' },
    { label: '48 hours', value: '48h' },
    { label: '5 days', value: '5d' },
    { label: '7 days', value: '7d' },
    { label: '14 days', value: '14d' },
    { label: 'No auto-destruct', value: 'none' },
  ]

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!activeConversationId) return
    // If an attachment is staged, the send button / Enter dispatches it.
    if (pending) {
      await sendPending()
      return
    }
    if (!message.trim()) return

    const msg = message.trim()
    setMessage('') // Clear BEFORE awaiting send to show immediate clearing
    resetTextareaHeight()
    sendMessage(
      msg,
      selectedTtl && selectedTtl !== 'none' ? (selectedTtl as string) : undefined
    )
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  const resetTextareaHeight = () => {
    const el = textareaRef.current
    if (el) {
      el.style.height = 'auto'
    }
  }

  // Handle click outside to close emoji picker
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (emojiPickerRef.current && !emojiPickerRef.current.contains(event.target as Node)) {
        setShowEmojiPicker(false)
      }
      if (ttlPickerRef.current && !ttlPickerRef.current.contains(event.target as Node)) {
        setShowTtlPicker(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Insert emoji at cursor position (only used for mixed text+emoji input)
  const insertEmoji = (emoji: string) => {
    const textarea = textareaRef.current
    if (!textarea) return

    const start = textarea.selectionStart
    const end = textarea.selectionEnd
    const newMessage = message.slice(0, start) + emoji + message.slice(end)
    setMessage(newMessage)
    
    // Move cursor after inserted emoji
    setTimeout(() => {
      textarea.focus()
      textarea.setSelectionRange(start + emoji.length, start + emoji.length)
    }, 0)
  }

  // Send an emoji as an animated sticker immediately (no ASCII in prompt)
  const sendEmojiSticker = (emoji: string) => {
    if (!activeConversationId) return
    const url = emojiToUrl(emoji)
    if (!url) {
      // No GIF asset — fall back to inserting the character into the prompt
      insertEmoji(emoji)
      return
    }
    sendMessage(emoji)
    setShowEmojiPicker(false)
  }

  // Send a generic pack sticker (e.g. a webp) as an inline image attachment.
  // The bytes are read from the bundled asset via the preload (works in both
  // dev and packaged modes) and shipped through the existing attachment
  // envelope so the peer renders it too. Stickers are downscaled first so they
  // stay under MAX_ATTACHMENT_BYTES (the 51 webp are ~3 MB each).
  const sendSticker = async (filename: string) => {
    if (!activeConversationId) return
    const api = window.addAPI
    const dataUrl = api?.readAsset?.(`emoji/gif/${filename}`)
    if (!dataUrl) return
    const scaled = await downscaleImageDataUrl(dataUrl)
    const [meta, b64] = scaled.split(',')
    const mime = meta.replace('data:', '').replace(';base64', '') || 'image/webp'
    const envelope = encodeAttachment({
      name: filename.replace(/\.[^.]+$/, '.webp'),
      mime,
      size: Math.ceil((b64.length * 3) / 4),
      data: b64,
    })
    setShowEmojiPicker(false)
    sendMessage(envelope, selectedTtl && selectedTtl !== 'none' ? selectedTtl : undefined)
  }

  // Auto-resize textarea
  useEffect(() => {
    const el = textareaRef.current
    if (el) {
      el.style.height = 'auto'
      el.style.height = Math.min(el.scrollHeight, 120) + 'px'
    }
  }, [message])

  const emojis: string[] = EMOJI_CATEGORIES[activeEmojiCategory] || []

  return (
    <div className="border-t border-gray-200 bg-white p-3">
      {/* Staged attachment preview (shown before send) */}
      {pending && (
        <div className="mb-2 flex items-center gap-3 rounded-lg border border-gray-200 bg-gray-50 p-2">
          {pending.mime.startsWith('image/') ? (
            <img
              src={`data:${pending.mime};base64,${pending.data}`}
              alt={pending.name}
              className="h-14 w-14 rounded object-cover"
            />
          ) : (
            <div className="flex h-14 w-14 items-center justify-center rounded bg-gray-200 text-gray-500">
              <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828L17 9.828a4 4 0 10-5.657-5.657L6.586 10.172" />
              </svg>
            </div>
          )}
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-medium text-gray-800">{pending.name}</div>
            <div className="text-xs text-gray-500">{formatBytes(pending.size)}</div>
          </div>
          <button
            type="button"
            onClick={cancelPending}
            className="flex h-7 w-7 items-center justify-center rounded-full text-gray-500 transition-colors hover:bg-gray-200"
            aria-label="Cancel attachment"
          >
            <svg className="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}
      <form onSubmit={handleSubmit} className="flex items-end gap-2 relative">
        {/* Attachment button */}
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          onChange={handleFileChange}
          disabled={!activeConversationId || attachBusy}
        />
        <button
          type="button"
          onClick={handleAttachClick}
          disabled={!activeConversationId || attachBusy}
          title={attachBusy ? 'Sending attachment…' : `Attach file (max ${MAX_ATTACHMENT_LABEL})`}
          aria-label="Attach file"
          className="flex h-8 w-8 items-center justify-center rounded-full text-gray-600 transition-colors hover:bg-gray-100 disabled:opacity-40"
        >
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828L17 9.828a4 4 0 10-5.657-5.657L6.586 10.172"
            />
          </svg>
        </button>

        {attachError && (
          <div className="absolute bottom-full left-0 mb-2 w-full max-w-sm rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 shadow-lg z-50">
            {attachError}
          </div>
        )}

        {/* Text input */}
        <textarea
          ref={textareaRef}
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type a message..."
          className="flex-1 resize-none rounded-lg border border-gray-200 bg-gray-50 py-2 pl-3 pr-10 text-sm outline-none focus:border-primary-500 max-h-30 min-h-[36px]"
          rows={1}
          disabled={!activeConversationId}
        />

        {/* Emoji picker button */}
        <button
          type="button"
          onClick={() => setShowEmojiPicker(!showEmojiPicker)}
          className="flex h-8 w-8 items-center justify-center rounded-full text-gray-600 transition-colors hover:bg-gray-100"
          aria-label="Add emoji"
        >
          <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
            <circle cx="12" cy="12" r="10" />
            <path d="M8 12a4 4 0 118 0c0 1.5-.8 2.5-2 3l-2 1-2-1c-1.2-.5-2-1.5-2-3z" />
          </svg>
        </button>

        {/* TTL picker button */}
        <button
          type="button"
          onClick={() => setShowTtlPicker(!showTtlPicker)}
          className={`flex h-8 w-8 items-center justify-center rounded-full transition-colors ${
            selectedTtl && selectedTtl !== 'none'
              ? 'bg-primary-100 text-primary-700'
              : 'text-gray-600 hover:bg-gray-100'
          }`}
          aria-label="Set auto-destruct timer"
          title={selectedTtl && selectedTtl !== 'none' ? `Auto-destruct: ${selectedTtl}` : 'Set auto-destruct timer'}
        >
          <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/>
          </svg>
        </button>

        {/* Emoji Picker Dropdown */}
        {showEmojiPicker && (
          <div
            ref={emojiPickerRef}
            className="absolute bottom-full left-12 mb-2 w-80 max-h-60 overflow-y-auto rounded-lg border bg-white shadow-lg z-50"
          >
            {/* Top-level tabs: emoji categories vs the sticker pack */}
            <div className="flex border-b border-gray-200 overflow-x-auto px-2 py-1">
              <button
                type="button"
                onClick={() => setShowStickerTab(false)}
                className={`whitespace-nowrap px-2 py-1 text-xs rounded transition-colors ${
                  !showStickerTab ? 'bg-primary-100 text-primary-700' : 'text-gray-600 hover:bg-gray-100'
                }`}
              >
                Emoji
              </button>
              {STICKERS.length > 0 && (
                <button
                  type="button"
                  onClick={() => setShowStickerTab(true)}
                  className={`whitespace-nowrap px-2 py-1 text-xs rounded transition-colors ${
                    showStickerTab ? 'bg-primary-100 text-primary-700' : 'text-gray-600 hover:bg-gray-100'
                  }`}
                >
                  Stickers ({STICKERS.length})
                </button>
              )}
            </div>

            {showStickerTab ? (
              /* Sticker pack grid */
              <div className="p-2 grid grid-cols-4 gap-1">
                {STICKERS.map((filename) => (
                  <button
                    key={filename}
                    type="button"
                    onClick={() => sendSticker(filename)}
                    className="w-16 h-16 rounded hover:bg-gray-100 transition-colors flex items-center justify-center"
                    aria-label={filename}
                  >
                    <StickerImg filename={filename} size={56} />
                  </button>
                ))}
              </div>
            ) : (
              <>
                {/* Category tabs */}
                <div className="flex border-b border-gray-200 overflow-x-auto px-2 py-1">
                  {Object.keys(EMOJI_CATEGORIES).map((category) => (
                    <button
                      key={category}
                      type="button"
                      onClick={() => setActiveEmojiCategory(category)}
                      className={`whitespace-nowrap px-2 py-1 text-xs rounded transition-colors ${
                        activeEmojiCategory === category
                          ? 'bg-primary-100 text-primary-700'
                          : 'text-gray-600 hover:bg-gray-100'
                      }`}
                    >
                      {category}
                    </button>
                  ))}
                </div>

                {/* Emoji grid */}
                <div className="p-2 grid grid-cols-8 gap-1">
                  {emojis.map((emoji, index) => (
                    <button
                      key={`${activeEmojiCategory}-${index}`}
                      type="button"
                      onClick={() => sendEmojiSticker(emoji)}
                      className="w-8 h-8 rounded hover:bg-gray-100 transition-colors flex items-center justify-center"
                      aria-label={emoji}
                    >
                      <EmojiImg emoji={emoji} size={22} />
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        {/* TTL Picker Dropdown */}
        {showTtlPicker && (
          <div
            ref={ttlPickerRef}
            className="absolute bottom-full left-4 mb-2 w-44 rounded-lg border bg-white shadow-lg z-50"
          >
            <div className="p-2">
              {TTL_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => {
                    setSelectedTtl(option.value === 'none' ? null : option.value)
                    setShowTtlPicker(false)
                  }}
                  className={`w-full text-left px-3 py-2 text-sm rounded transition-colors ${
                    selectedTtl === option.value || (option.value === 'none' && !selectedTtl)
                      ? 'bg-primary-100 text-primary-700'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Voice note placeholder */}
        <button
          type="button"
          className="flex h-8 w-8 items-center justify-center rounded-full text-gray-600 transition-colors hover:bg-gray-100"
          aria-label="Record voice note"
        >
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m0 0a7 7 0 0114 0M12 4v4m0 0l-2-2m2 2l2-2"
            />
          </svg>
        </button>
      </form>
    </div>
  )
}

export default MessageInput
