/**
 *-------------------------------------------------------------------------------
 * Deterministic Initials avatar generator — privacy-preserving letter avatars
 * Renders 1-2 large letters on a generated gradient background.
 * Deterministic: same seed => same gradient + initials. No network, no PII.
 *-------------------------------------------------------------------------------
 */

// Extract initials from null_id (format: NN-XXXX-XXXX or plain string)
function getInitials(seed: string): string {
  const clean = seed.replace(/[Nn][Nn]-/i, '').replace(/-/g, '')
  if (clean.length >= 4) {
    // first + last significant chars: "UFtv" -> "U" + "v" = "Uv"
    return (clean[0] + clean[clean.length - 1]).toUpperCase()
  }
  return clean.slice(0, 2).toUpperCase()
}

// Distinct, accessible 2-stop gradient palette (HSL pairs: [from, to])
const GRADIENTS: [string, string][] = [
  ['#6366F1', '#8B5CF6'], // indigo -> violet
  ['#EC4899', '#F43F5E'], // pink -> rose
  ['#F97316', '#F59E0B'], // orange -> amber
  ['#10B981', '#06B6D4'], // emerald -> cyan
  ['#3B82F6', '#06B6D4'], // blue -> cyan
  ['#8B5CF6', '#EC4899'], // violet -> pink
  ['#14B8A6', '#22C55E'], // teal -> green
  ['#EF4444', '#F97316'], // red -> orange
  ['#6366F1', '#3B82F6'], // indigo -> blue
  '#F43F5E', '#8B5CF6'  , // rose -> violet
  ['#06B6D4', '#3B82F6'], // cyan -> blue
  '#84CC16', '#10B981'  , // lime -> emerald
]

// Simple 32-bit hash for deterministic selection
function hashCode(str: string): number {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash
  }
  return Math.abs(hash)
}

/**
 * Generate an SVG initials avatar with a modern diagonal gradient.
 * @param seed  null_id or any stable string
 * @param size  output size in px (square)
 * @param rounded  if true => rounded-square (squircle), else circle
 */
export function generateInitialsAvatar(
  seed: string,
  size: number = 40,
  rounded = true,
): string {
  if (!seed) return ''

  const initials = getInitials(seed)
  const hash = hashCode(seed)
  const [c1, c2] = GRADIENTS[hash % GRADIENTS.length]
  const gid = `g${hash % 9999}`
  const radius = rounded ? Math.round(size * 0.28) : size / 2
  const fontSize = Math.round(size * 0.42)

  const svg = `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}">
  <defs>
    <linearGradient id="${gid}" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${c1}"/>
      <stop offset="100%" stop-color="${c2}"/>
    </linearGradient>
  </defs>
  <rect width="${size}" height="${size}" rx="${radius}" ry="${radius}" fill="url(#${gid})"/>
  <text x="50%" y="50%" dominant-baseline="central" text-anchor="middle"
        font-family="system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif"
        font-weight="700" font-size="${fontSize}" letter-spacing="${-size * 0.02}"
        fill="#FFFFFF" fill-opacity="0.96">${initials}</text>
</svg>`

  return `data:image/svg+xml;base64,${btoa(svg.trim())}`
}
