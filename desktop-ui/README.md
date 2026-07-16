# Add Desktop

Cross-platform desktop messaging application built with Electron, React, and TypeScript.

## Features

- **Split-pane layout** (Signal-inspired):
  - Sidebar: 30% width with conversation list, search, and profile header
  - Chat pane: 70% width with message history and input
- **Zustand** state management
- **Tailwind CSS** styling
- **TypeScript** strict typing

## Project Structure

```
desktop-ui/
├── electron/
│   ├── main.js           # Electron main process (1280x800 window, minWidth:800)
│   └── preload.js        # Context isolation bridge
├── src/
│   ├── components/
│   │   ├── sidebar/
│   │   │   ├── Sidebar.tsx         # 30% width container, min-w-280
│   │   │   ├── SidebarHeader.tsx   # Avatar + compose/settings buttons
│   │   │   ├── SearchBar.tsx       # Conversation search/filter
│   │   │   ├── ConversationList.tsx # Scrollable list with auto-height
│   │   │   └── ConversationRow.tsx  # Avatar, name, last msg, timestamp, badge
│   │   └── chat/
│   │       ├── ChatPane.tsx        # 70% width container
│   │       ├── EmptyState.tsx      # Placeholder when no chat selected
│   │       ├── ChatHeader.tsx      # Contact name, status, menu dropdown
│   │       ├── MessageList.tsx     # Grouped messages, auto-scroll to bottom
│   │       ├── MessageBubble.tsx   # Sent/received styling + status indicators
│   │       └── MessageInput.tsx    # Textarea (Shift+Enter=newline, Enter=send)
│   ├── store/chatStore.ts   # Zustand: conversations, messages, search, actions
│   ├── types/index.ts       # Message, Conversation, MessageStatus interfaces
│   ├── i18n/index.ts        # i18next: English/German/Spanish/Japanese/French
│   ├── App.tsx              # Split-pane layout with theme init
│   ├── main.tsx             # React entry
│   └── index.css            # Tailwind directives
├── dist/                  # React build output (gitignored)
├── dist-electron/         # Electron packaged app (gitignored)
├── package.json
├── tsconfig.json
├── vite.config.ts
└── tailwind.config.js
```

## State Management

Zustand store with selectors:

```typescript
// Access state
const { activeConversationId, conversations, searchQuery } = useChatStore()

// Actions
setActiveConversation(id)
addMessage(conversationId, message)
addConversation(conversation)
setSearchQuery(query)
```

## Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Development

```bash
# Install dependencies
npm install

# Run dev server (Vite + Electron)
npm run dev

# Run only React dev server
npm run dev:react

# Run only Electron (after React build)
npm run dev:electron
```

### Build for Production

```bash
# Build React + Electron installer
npm run build

# Or build React only
npm run build:react

# Build Electron package
npm run build:electron
```

## Key UI Behaviors

| Component | Behavior |
|-----------|----------|
| Sidebar | Fixed 30% width, min 280px, max 400px, contains ThemeToggle button |
| ChatPane | Fixed 70% width, min 400px |
| MessageInput | Multi-line expand, Shift+Enter=newline, Enter=send, TTL picker (clock icon), emoji picker (😊) |
| MessageList | Auto-scrolls to bottom on new messages |
| ConversationRow | Shows unread badge when unreadCount > 0 |

## Dark/Light Theme

Click the moon (🌙) / sun (☀️) icon in the sidebar header to cycle themes:

- **System** (default) — Follows OS preference (`prefers-color-scheme`)
- **Light mode**: Background #F2F2F7, sidebar #FFFFFF, bubbles #007AFF (sent) / #E9E9EB (received)
- **Dark mode**: Background #121212, sidebar #1E1E1E, bubbles #0A84FF (sent) / #2C2C2E (received)

Theme preference persists across app restarts via `localStorage`. Use `setCustomColors()` to personalize colors.

See [THEMES.md](THEMES.md) for a complete guide on creating custom themes.

## Internationalization (i18n)

The UI supports 5 languages via i18next:

- English (en), German (de), Spanish (es), Japanese (ja), French (fr)
- Automatic detection: localStorage → navigator
- Usage: `t('ui.sidebar.settings')`, `t('ui.chat.typeMessage')`

Strings are in `src/i18n/index.ts`. Add new languages by extending the `resources` object.

## Development Notes

- Vite dev server runs on port 5173
- Electron loads from Vite dev server in development
- Production loads from `dist/index.html`

## Security Settings

The vault unlock dialog includes anti-bruteforce protection:

- **Self-destruct counter**: Tracks failed unlock attempts in `~/.add/failed_attempts.json`
- **Threshold**: Configurable 3-20 attempts (default: 10) via Settings → Security
- **Warning**: Banner appears at 7+ failed attempts
- **Wipe action**: At threshold, all `~/.add/` data is deleted (vault, keys, messages)

Access Settings via the sidebar header menu to configure the self-destruct threshold.