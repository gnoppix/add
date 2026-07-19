# Adding a New Language to Add Desktop UI

This guide explains how to add a new language to the Add internationalization system.

## Overview

Add uses `i18next` with `react-i18next` for localization. Languages are structured as JSON translation objects with support for:
- Dynamic placeholders (`{{variable}}`) - preserved exactly as-is
- Plural forms (`one`, `other`, etc.) - added per language needs
- Nested structure matching UI component organization

## File Location

`desktop-ui/src/i18n/index.ts`

## Steps to Add a New Language

1. **Add the language code to `resources` object**

```typescript
const resources = {
  en: { /* existing */ },
  de: { /* existing */ },
  // ... existing languages
  [NEW_LANG_CODE]: {
    translation: {
      ui: {
        sidebar: {
          settings: '...',
          newMessage: '...',
          addContact: '...',
          initialize: '...',
          register: '...',
          registerAll: '...',
          checkRegister: '...',
          loadContacts: '...',
          connection: '...',
          p2pListener: '...',
          running: '...',
          stopped: '...',
          startListener: '...',
          stopListener: '...',
          restart: '...',
          identity: '...',
          close: '...',
        },
        chat: {
          online: '...',
          offline: '...',
          typeMessage: '...',
          sendMessage: '...',
          ttl: '...',
          emoji: '...',
          noConversation: '...',
        },
        ttl: {
          title: '...',
          off: '...',
          hours2: '...',
          hours12: '...',
          hours24: '...',
          hours48: '...',
          days5: '...',
          days7: '...',
          days14: '...',
        },
        emoji: {
          title: '...',
          categories: {
            smileys: '...',
            gestures: '...',
            objects: '...',
            symbols: '...',
            flags: '...',
          },
        },
        errors: {
          ipcNotAvailable: '...',
          initFailed: '...',
          startListenFailed: '...',
          stopListenFailed: '...',
          restartListenFailed: '...',
        },
      },
    },
  },
}
```

2. **Required Keys (Must Translate)**

All UI strings under `ui` must be translated. Keep translations concise (10-12 chars max for buttons/headers).

## Translation Tips

- **UI constraints**: Keep translations short (buttons: 10-12 chars max)
- **Technical terms**: Keep "TTL", "P2P", "E2E" as-is (industry standard)
- **Icons as fallback**: Emoji like 😊, 🕒 are universal
- **Gender-aware languages**: If adding Arabic, Russian, etc., add context variants

## Custom Theme Colors API

To set custom theme colors programmatically:

```typescript
import { useThemeStore } from './store/themeStore'

// Set custom colors (merges with defaults)
useThemeStore.getState().setCustomColors({
  primary: '#FF6B6B',      // Accent color
  background: '#1A1A2E',  // Main background
})

// Reset to defaults
useThemeStore.getState().resetCustomColors()

// Get current theme state
const theme = useThemeStore.getState().theme // 'system' | 'light' | 'dark'
const systemPrefersDark = useThemeStore.getState().systemPrefersDark
```

CSS variables `--color-primary`, `--color-background`, etc. are applied to `:root`.

## Testing

1. Run `npm run dev:react` to start dev server
2. Open http://localhost:5173
3. Change browser language or set `localStorage.lang = '[code]'` in console
4. Verify all UI strings display correctly

## Pluralization Support

For languages with complex plural forms (Arabic, Russian, Polish), extend:

```typescript
unreadCount: {
  zero: '{{count}} umpapilizi',
  one: 'Umumpapilizi 1',
  other: 'Umumpapilizi {{count}}'
}
```

## Pull Request

1. Fork the repo
2. Add translation to `src/i18n/index.ts`
3. Update `README.md` language list
4. Run `npm run lint` to verify syntax
5. Submit PR with language name in title

---

**Last updated**: 2026-07-07
**Maintained by**: Add team