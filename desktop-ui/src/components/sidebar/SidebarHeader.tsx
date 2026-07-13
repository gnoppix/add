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

/** Sidebar Header with profile avatar, compose button, and settings */
import { useState, useEffect } from 'react'
import { useChatStore } from '../../store/chatStore'
import ThemeToggle from './ThemeToggle'
import ProfileAvatar from './ProfileAvatar'

interface AddContactForm {
  nullId: string
  fingerprint: string
  alias: string
}

function SidebarHeader() {
  const [showSettingsModal, setShowSettingsModal] = useState(false)
  const [showAddContact, setShowAddContact] = useState(false)
  const [errorMessage, setErrorMessage] = useState('')
  const [passwdMessage, setPasswdMessage] = useState('')
  const [listenRunning, setListenRunning] = useState(false)
  const [contactForm, setContactForm] = useState<AddContactForm>({
    nullId: '',
    fingerprint: '',
    alias: '',
  })
  const {
    initialize,
    myId,
    myFingerprint,
    isAuthenticated,
    loadContacts,
    addConversation,
  } = useChatStore()

  useEffect(() => {
    initialize()
  }, [initialize])

  const handleInit = async () => {
    const api = window.addAPI
    if (!api) {
      setErrorMessage('IPC API not available - is the CLI configured? Set ADD_CLI_PATH')
      return
    }
    try {
      await api.init()
      initialize()
      setErrorMessage('')
    } catch (err) {
      setErrorMessage(`Init failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  const handleRegister = async () => {
    const api = window.addAPI
    if (api) {
      try {
        await api.register()
        setShowSettingsModal(false)
      } catch (err) {
        console.error('Register failed:', err)
      }
    }
  }

  const handleRegisterAll = async () => {
    const api = window.addAPI
    if (api) {
      try {
        await api.registerAllBootstraps()
        setShowSettingsModal(false)
      } catch (err) {
        console.error('Register All failed:', err)
      }
    }
  }

  const handleCheckRegister = async () => {
    const api = window.addAPI
    if (api) {
      try {
        await api.checkRegister()
      } catch (err) {
        console.error('Check Register failed:', err)
      }
    }
  }

  const checkListenStatus = async () => {
    const api = window.addAPI
    if (api) {
      try {
        const status = await api.listenStatus()
        setListenRunning(status.running)
      } catch (err) {
        console.error('Check listen status failed:', err)
      }
    }
  }

  const handleStartListen = async () => {
    const api = window.addAPI
    if (!api) {
      setErrorMessage('IPC API not available - is the CLI configured? Set ADD_CLI_PATH')
      return
    }
    try {
      await api.startListen()
      setListenRunning(true)
      setErrorMessage('')
    } catch (err) {
      setErrorMessage(`Start listen failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  const handleStopListen = async () => {
    const api = window.addAPI
    if (!api) {
      setErrorMessage('IPC API not available - is the CLI configured? Set ADD_CLI_PATH')
      return
    }
    try {
      await api.stopListen()
      setListenRunning(false)
      setErrorMessage('')
    } catch (err) {
      setErrorMessage(`Stop listen failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  const handleRestartListen = async () => {
    const api = window.addAPI
    if (!api) {
      setErrorMessage('IPC API not available - is the CLI configured? Set ADD_CLI_PATH')
      return
    }
    try {
      await api.restartListen()
      setListenRunning(true)
      setErrorMessage('')
    } catch (err) {
      setErrorMessage(`Restart listen failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  // Check listen status on mount
  useEffect(() => {
    checkListenStatus()
  }, [])

  const handleAddContact = async () => {
    const api = window.addAPI
    if (!api || !contactForm.nullId || !contactForm.fingerprint) return

    try {
      await api.addContact(contactForm.nullId, contactForm.fingerprint)
      if (contactForm.alias) {
        await api.alias(contactForm.alias, contactForm.nullId)
      }
      // Add to local state
      addConversation({
        id: contactForm.nullId,
        name: contactForm.alias || contactForm.nullId,
        fingerprint: contactForm.fingerprint,
        avatarUrl: `https://i.pravatar.cc/150?u=${contactForm.nullId}`,
        lastMessage: '',
        lastMessageTimestamp: new Date(),
        unreadCount: 0,
        isOnline: false,
        isGroup: false,
      })
      setContactForm({ nullId: '', fingerprint: '', alias: '' })
      setShowAddContact(false)
      setErrorMessage('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      console.error('Add contact failed:', msg)
      setErrorMessage(`Add contact failed: ${msg}`)
    }
  }

  const handlePasswd = async () => {
    const api = window.addAPI
    if (!api) {
      setPasswdMessage('IPC API not available')
      return
    }
    if (!confirm('Change GPG key passphrase? You will be prompted in the terminal.')) return

    try {
      await api.passwd()
      setPasswdMessage('Passphrase changed successfully')
      setTimeout(() => setPasswdMessage(''), 3000)
    } catch (err) {
      setPasswdMessage(`Failed: ${err instanceof Error ? err.message : String(err)}`)
    }
  }

  return (
    <header className="flex h-14 items-center justify-between border-b border-gray-200 px-3">
      {/* Left: User Profile Avatar */}
      <ProfileAvatar />

      {/* Right: Action buttons */}
      <div className="flex items-center gap-1">
        {/* New Message / Compose Button */}
        <button
          onClick={() => {
            setShowAddContact(true)
            setErrorMessage('')
          }}
          className="flex h-8 w-8 items-center justify-center rounded-full text-gray-600 transition-colors hover:bg-gray-100"
          aria-label="New Message"
          title="Add Contact"
        >
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
        </button>

        {/* Settings Gear Icon */}
        <button
          onClick={() => setShowSettingsModal(true)}
          className="flex h-8 w-8 items-center justify-center rounded-full text-gray-600 transition-colors hover:bg-gray-100"
          aria-label="Settings"
        >
          <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.446-1.756 2.942-1.756 2.396 0l-.864 3.993a2 2 0 00.97 1.068l3.993.864c1.756.446 1.756 2.942 0 2.396l-3.993-.864a2 2 0 00-1.068-.97l-.864-3.993z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 2 0 11-6 0 3 2 0 016 0z" />
          </svg>
        </button>

        {/* Theme Toggle */}
        <ThemeToggle />
      </div>

      {/* Settings Modal */}
      {showSettingsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-96 rounded-lg bg-white p-6 shadow-xl">
            <h2 className="mb-4 text-lg font-semibold">Settings</h2>

            <div className="space-y-3 text-sm">
              {/* Error Message */}
              {errorMessage && (
                <div className="rounded bg-red-100 p-2 text-xs text-red-700">
                  {errorMessage}
                </div>
              )}

              <div className="border-b pb-3">
                <p className="font-medium">Identity</p>
                <div className="text-xs font-mono text-gray-700 space-y-1 mt-1">
                  {isAuthenticated ? (
                    <>
                      <p>Null ID: <span className="font-mono">{myId}</span></p>
                      <p>Fingerprint: <span className="font-mono">{myFingerprint}</span></p>
                    </>
                  ) : (
                    <p>Not initialized</p>
                  )}
                </div>
                {!isAuthenticated && (
                  <button
                    onClick={handleInit}
                    className="mt-1 rounded bg-primary-500 px-2 py-0.5 text-xs text-white hover:bg-primary-600"
                  >
                    Initialize Identity
                  </button>
                )}
                {isAuthenticated && (
                  <>
                    <button
                      onClick={handleRegister}
                      className="mt-1 ml-2 rounded bg-gray-100 px-2 py-0.5 text-xs hover:bg-gray-200"
                    >
                      Register
                    </button>
                    <button
                      onClick={handleRegisterAll}
                      className="mt-1 ml-2 rounded bg-gray-100 px-2 py-0.5 text-xs hover:bg-gray-200"
                    >
                      Register All
                    </button>
                    <button
                      onClick={handleCheckRegister}
                      className="mt-1 ml-2 rounded bg-gray-100 px-2 py-0.5 text-xs hover:bg-gray-200"
                    >
                      Check Register
                    </button>
                  </>
                )}
              </div>

              <div className="border-b pb-3">
                <p className="font-medium">Connection</p>
                <div className="flex flex-col gap-1 mt-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-gray-600">P2P Listener</span>
                    <span
                      id="listen-status"
                      className={`px-1.5 py-0.5 rounded text-xs ${
                        listenRunning
                          ? 'bg-green-100 text-green-700'
                          : 'bg-red-100 text-red-700'
                      }`}
                    >
                      {listenRunning ? 'Running' : 'Stopped'}
                    </span>
                  </div>
                  <div className="flex gap-1">
                    <button
                      onClick={handleStartListen}
                      disabled={listenRunning}
                      className="flex-1 rounded bg-primary-500 px-2 py-0.5 text-xs text-white hover:bg-primary-600 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Start Listener
                    </button>
                    <button
                      onClick={handleStopListen}
                      disabled={!listenRunning}
                      className="flex-1 rounded bg-red-500 px-2 py-0.5 text-xs text-white hover:bg-red-600 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Stop Listener
                    </button>
                    <button
                      onClick={handleRestartListen}
                      disabled={!listenRunning}
                      className="flex-1 rounded bg-yellow-500 px-2 py-0.5 text-xs text-white hover:bg-yellow-600 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Restart
                    </button>
                  </div>
                </div>
                <button
                  onClick={() => {
                    loadContacts()
                    setShowSettingsModal(false)
                  }}
                  className="ml-2 rounded bg-gray-100 px-2 py-0.5 text-xs hover:bg-gray-200"
                >
                  Load Contacts
                </button>
              </div>

              {/* Security: Change Passphrase */}
              {isAuthenticated && (
                <div className="border-t pt-3">
                  <p className="font-medium">Security</p>
                  {passwdMessage && (
                    <p className="mt-1 text-xs text-green-600">{passwdMessage}</p>
                  )}
                  <button
                    onClick={handlePasswd}
                    className="mt-1 rounded bg-primary-500 px-2 py-0.5 text-xs text-white hover:bg-primary-600"
                  >
                    Change GPG Key Passphrase
                  </button>
                </div>
              )}
            </div>

            <button
              onClick={() => setShowSettingsModal(false)}
              className="mt-4 ml-auto block rounded bg-gray-100 px-3 py-1 text-sm hover:bg-gray-200"
            >
              Close
            </button>
          </div>
        </div>
      )}

      {/* Add Contact Modal */}
      {showAddContact && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-80 rounded-lg bg-white p-6 shadow-xl">
            <h2 className="mb-4 text-lg font-semibold">Add Contact</h2>

            {errorMessage && (
              <div className="mb-3 rounded bg-red-100 p-2 text-xs text-red-700">
                {errorMessage}
              </div>
            )}

            <div className="space-y-3">
              <input
                type="text"
                placeholder="Null ID (NN-XXXX-XXXX)"
                value={contactForm.nullId}
                onChange={(e) => setContactForm({ ...contactForm, nullId: e.target.value })}
                className="w-full rounded border px-2 py-1 text-sm"
              />
              <input
                type="text"
                placeholder="Fingerprint"
                value={contactForm.fingerprint}
                onChange={(e) => setContactForm({ ...contactForm, fingerprint: e.target.value })}
                className="w-full rounded border px-2 py-1 text-sm"
              />
              <input
                type="text"
                placeholder="Alias (optional)"
                value={contactForm.alias}
                onChange={(e) => setContactForm({ ...contactForm, alias: e.target.value })}
                className="w-full rounded border px-2 py-1 text-sm"
              />
            </div>

            <div className="mt-4 flex justify-end gap-2">
              <button
                onClick={() => setShowAddContact(false)}
                className="rounded bg-gray-100 px-3 py-1 text-sm hover:bg-gray-200"
              >
                Cancel
              </button>
              <button
                onClick={handleAddContact}
                className="rounded bg-primary-500 px-3 py-1 text-sm text-white hover:bg-primary-600"
              >
                Add
              </button>
            </div>
          </div>
        </div>
      )}
    </header>
  )
}

export default SidebarHeader