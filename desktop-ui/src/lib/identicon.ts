/**
 *-------------------------------------------------------------------------------
 * Deterministic Initials avatar generator - privacy-preserving letter avatars
 * Renders 1-2 large letters centered on a colored background
 * Deterministic: same seed = same colors + initials
 *-------------------------------------------------------------------------------
 */

// Extract initials from null_id (format: NN-XXXX-XXXX or plain string)
function getInitials(seed: string): string {
  // For null_id format like NN-UFtv-8fHu, extract the distinctive parts
  const clean = seed.replace(/[Nn][Nn]-/i, '').replace(/-/g, '')
  if (clean.length >= 4) {
    // Take first and last significant chars: "UFtv" -> "U" + "v" = "Uv"
    return (clean[0] + clean[clean.length - 1]).toUpperCase()
  }
  // Fallback to first 2 chars
  return clean.slice(0, 2).toUpperCase()
}

// Color palette - distinct, accessible colors
const COLORS = [
  '#3B82F6', '#8B5CF6', '#EC4899', '#EF4444',
  '#F97316', '#F59E0B', '#10B981', '#06B6D4',
  '#6366F1', '#84CC16', '#14B8A6', '#F43F5E',
]

// Simple hash for deterministic color selection
function hashCode(str: string): number {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash
  }
  return Math.abs(hash)
}

// Generate SVG initials avatar: large letters centered on colored background
export function generateInitialsAvatar(seed: string, size: number = 40): string {
  if (!seed) return ''
  
  const initials = getInitials(seed)
  const hash = hashCode(seed)
  const bgColor = COLORS[hash % COLORS.length]
  const textColor = '#FFFFFF' // White for contrast
  
  // SVG with centered initials
  const svg = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}">
  <rect width="${size}" height="${size}" fill="${bgColor}"/>
  <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle"
        font-family="system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif"
        font-weight="600" font-size="${size * 0.45}" fill="${textColor}">
    ${initials}
  </text>
</svg>`
  
  return `data:image/svg+xml;base64,${btoa(svg)}`
}