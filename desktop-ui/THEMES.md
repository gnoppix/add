# Building Custom Themes for Add Desktop UI

This guide explains how to create and distribute custom themes for the Add desktop UI.

## Overview

Add's theme system uses CSS custom properties (variables) applied to `:root`. Themes can be created by:
1. Defining a set of CSS variables
2. Applying them via the `setCustomColors()` API
3. Distributing as a simple JSON file

## Theme Architecture

### CSS Custom Properties

The following variables are available for theming:

```css
:root {
  --color-primary: #007AFF;        /* Accent color (buttons, links) */
  --color-secondary: #8E8E93;      /* Secondary text, borders */
  --color-background: #F2F2F7;     /* Main window background */
  --color-sidebar: #FFFFFF;        /* Sidebar background */
  --color-bubble-sent: #007AFF;    /* Sent message bubble */
  --color-bubble-received: #E9E9EB; /* Received message bubble */
  --color-text: #000000;           /* Primary text */
  --color-text-secondary: #6D6D70; /* Secondary text */
}
```

### Theme Modes

- **Light mode** - Uses light color palette
- **Dark mode** - Uses dark color palette (`.dark` class on `<html>`)
- **System** - Follows OS preference (`prefers-color-scheme`)

When dark mode is active, dark palette values are used as defaults, then overridden by any custom colors.

## Creating a Theme

### 1. Define Your Colors

Create a JSON object with your color values:

```json
{
  "name": "Ocean",
  "author": "Your Name",
  "description": "Calm blue ocean theme",
  "colors": {
    "primary": "#006994",
    "secondary": "#5A8DA8",
    "background": "#E0F2F1",
    "sidebar": "#FFFFFF",
    "bubbleSent": "#006994",
    "bubbleReceived": "#B2DFDB",
    "text": "#004D40",
    "textSecondary": "#00695C"
  }
}
```

### 2. Apply Theme via API

In the browser console or via a theme manager component:

```typescript
import { useThemeStore } from './store/themeStore'

// Apply theme
useThemeStore.getState().setCustomColors({
  primary: '#006994',
  background: '#E0F2F1',
  // ... other colors
})

// Reset to defaults
useThemeStore.getState().resetCustomColors()
```

### 3. Theme Persistence

Custom colors are automatically saved to `localStorage` under `theme-storage.customColors` and persist across restarts.

## Distributing Themes

### As JSON File

Save as `ocean-theme.json`:

```json
{
  "name": "Ocean",
  "author": "Your Name",
  "version": "1.0.0",
  "colors": {
    "primary": "#006994",
    "secondary": "#5A8DA8",
    "background": "#E0F2F1",
    "sidebar": "#FFFFFF",
    "bubbleSent": "#006994",
    "bubbleReceived": "#B2DFDB",
    "text": "#004D40",
    "textSecondary": "#00695C"
  }
}
```

### Loading a Theme File

```typescript
async function loadTheme(url: string) {
  const response = await fetch(url)
  const theme = await response.json()
  useThemeStore.getState().setCustomColors(theme.colors)
}

// Usage
loadTheme('https://example.com/themes/ocean-theme.json')
```

## Example Themes

### Dark Purple
```json
{
  "name": "Dark Purple",
  "colors": {
    "primary": "#BB86FC",
    "secondary": "#9B7BD8",
    "background": "#121212",
    "sidebar": "#1E1E1E",
    "bubbleSent": "#BB86FC",
    "bubbleReceived": "#2C2C2E",
    "text": "#FFFFFF",
    "textSecondary": "#AEAEB2"
  }
}
```

### High Contrast
```json
{
  "name": "High Contrast",
  "colors": {
    "primary": "#00FF00",
    "secondary": "#FFFF00",
    "background": "#000000",
    "sidebar": "#111111",
    "bubbleSent": "#00FF00",
    "bubbleReceived": "#333333",
    "text": "#FFFFFF",
    "textSecondary": "#CCCCCC"
  }
}
```

### Solarized Light
```json
{
  "name": "Solarized Light",
  "colors": {
    "primary": "#268BD2",
    "secondary": "#586E75",
    "background": "#FDF6E3",
    "sidebar": "#EEE8D5",
    "bubbleSent": "#268BD2",
    "bubbleReceived": "#EEE8D5",
    "text": "#073642",
    "textSecondary": "#586E75"
  }
}
```

## Creating a Theme Manager Component

```tsx
// src/components/sidebar/ThemeManager.tsx
import { useState } from 'react'
import { useThemeStore } from '../../store/themeStore'

const PRESET_THEMES = [
  { name: 'Default', colors: undefined },
  { name: 'Ocean', colors: { primary: '#006994', background: '#E0F2F1', ... } },
  { name: 'Dark Purple', colors: { primary: '#BB86FC', background: '#121212', ... } },
  // ...
]

export default function ThemeManager() {
  const { customColors, setCustomColors, resetCustomColors } = useThemeStore()
  const [file, setFile] = useState<File | null>(null)

  return (
    <div className="p-4 space-y-4">
      <h3 className="font-semibold">Theme Manager</h3>
      
      <div className="space-y-2">
        {PRESET_THEMES.map((theme) => (
          <button
            key={theme.name}
            onClick={() => theme.colors ? setCustomColors(theme.colors) : resetCustomColors()}
            className="w-full text-left p-2 rounded border hover:bg-gray-100"
          >
            {theme.name} {customColors === theme.colors && '✓'}
          </button>
        ))}
      </div>

      <div className="border-t pt-4">
        <label className="block text-sm mb-2">Import Theme JSON</label>
        <input
          type="file"
          accept=".json"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
          className="w-full text-sm"
        />
        {file && (
          <button
            onClick={async () => {
              const text = await file.text()
              const theme = JSON.parse(text)
              setCustomColors(theme.colors)
            }}
            className="mt-2 rounded bg-primary-500 px-3 py-1 text-sm text-white"
          >
            Apply Theme
          </button>
        )}
      </div>

      {customColors && (
        <button
          onClick={resetCustomColors}
          className="w-full rounded bg-red-500 px-3 py-1 text-sm text-white"
        >
          Reset to Default
        </button>
      )}
    </div>
  )
}
```

## Theme Validation

Validate theme files before applying:

```typescript
interface ThemeColors {
  primary: string
  secondary: string
  background: string
  sidebar: string
  bubbleSent: string
  bubbleReceived: string
  text: string
  textSecondary: string
}

function validateTheme(obj: unknown): obj is { colors: ThemeColors } {
  if (!obj || typeof obj !== 'object') return false
  const theme = obj as Record<string, unknown>
  if (!theme.colors || typeof theme.colors !== 'object') return false
  
  const required: (keyof ThemeColors)[] = [
    'primary', 'secondary', 'background', 'sidebar',
    'bubbleSent', 'bubbleReceived', 'text', 'textSecondary'
  ]
  
  return required.every(key => 
    typeof theme.colors[key] === 'string' && /^#[0-9A-Fa-f]{6}$/.test(theme.colors[key] as string)
  )
}
```

## Best Practices

1. **Test both light and dark modes** - Colors should work in both
2. **Maintain contrast ratios** - WCAG AA minimum 4.5:1 for text
3. **Use semantic colors** - Don't just pick random colors; consider meaning (primary = actions, background = canvas, etc.)
4. **Keep it simple** - 8 colors is the full palette; most themes only need to override 3-4
5. **Preview before distributing** - Test in the actual UI

## Sharing Themes

1. Fork the Add repo
2. Add theme JSON to `desktop-ui/themes/` (create directory)
3. Update `desktop-ui/themes/index.json` with theme metadata
4. Submit PR

Themes can also be hosted anywhere and loaded via URL using the `loadTheme()` function above.

---

**Last updated**: 2026-07-07
**Maintained by**: Add team