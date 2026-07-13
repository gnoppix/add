/**
 *-------------------------------------------------------------------------------
 * Deterministic identicon generator - no network requests, privacy-preserving
 * Generates unique colored SVG avatars from null_id strings
 *-------------------------------------------------------------------------------
 */

// Simple hash function for deterministic color selection
function hashCode(str: string): number {
  let hash = 0
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i)
    hash = ((hash << 5) - hash) + char
    hash = hash & hash // Convert to 32-bit integer
  }
  return Math.abs(hash)
}

// Color palette - distinct, accessible colors
const COLORS = [
  '#3B82F6', // blue
  '#8B5CF6', // violet
  '#EC4899', // pink
  '#EF4444', // red
  '#F97316', // orange
  '#F59E0B', // amber
  '#10B981', // emerald
  '#06B6D4', // cyan
  '#6366F1', // indigo
  '#84CC16', // lime
]

// Seed-based random for pattern generation
function seededRandom(seed: number) {
  const x = Math.sin(seed) * 10000
  return x - Math.floor(x)
}

// Generate SVG identicon path - 3x3 grid with center+corner symmetry
function generatePath(seed: string, bgColor: string, fgColor: string): string {
  const cells: boolean[] = []
  // 9 cells in 3x3 grid
  for (let i = 0; i < 9; i++) {
    cells.push(seededRandom(hashCode(seed + i)) > 0.5)
  }
  
  // Symmetry: cells[i] = cells[8-i] for center+corner symmetry
  const symmetric = [
    cells[0], cells[1], cells[2],
    cells[3], cells[4], cells[3],
    cells[5], cells[1], cells[5],
  ]
  
  const path: string[] = []
  const size = 20
  const cellSize = size / 3
  const strokeWidth = 2
  
  for (let row = 0; row < 3; row++) {
    for (let col = 0; col < 3; col++) {
      const idx = row * 3 + col
      if (symmetric[idx]) {
        const x = col * cellSize + strokeWidth/2
        const y = row * cellSize + strokeWidth/2
        path.push(`M ${x} ${y}h ${cellSize-strokeWidth}v ${cellSize-strokeWidth}h ${-(cellSize-strokeWidth)}v ${-(cellSize-strokeWidth)}z`)
      }
    }
  }
  
  return `data:image/svg+xml;base64,${btoa(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}">
      <rect width="${size}" height="${size}" fill="${bgColor}"/>
      <path d="${path.join('')}" fill="${fgColor}"/>
    </svg>
  `)}`
}

export function generateIdenticon(nullId: string): string {
  if (!nullId) return ''
  
  const hash = hashCode(nullId)
  const bgColor = COLORS[hash % COLORS.length]
  // Use different hue for foreground
  const fgColor = COLORS[(hash + Math.floor(COLORS.length/2)) % COLORS.length]
  
  return generatePath(nullId, bgColor, fgColor)
}