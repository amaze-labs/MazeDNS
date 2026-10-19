// fileToAvatar turns a picked image file into a small square JPEG for upload:
// centre-cropped, resized to 128×128 and encoded at quality 0.85 (5–10 KB),
// so the server only ever receives the small result. Returns raw base64.
export async function fileToAvatar(file: File, size = 128): Promise<string> {
  if (!file.type.startsWith('image/')) throw new Error('Pick an image file (JPEG, PNG, WebP…).')
  const url = URL.createObjectURL(file)
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const i = new Image()
      i.onload = () => resolve(i)
      i.onerror = () => reject(new Error('That file couldn’t be read as an image.'))
      i.src = url
    })
    const side = Math.min(img.naturalWidth, img.naturalHeight)
    if (!side) throw new Error('That image is empty.')
    const canvas = document.createElement('canvas')
    canvas.width = canvas.height = size
    const ctx = canvas.getContext('2d')
    if (!ctx) throw new Error('This browser can’t resize images.')
    ctx.fillStyle = '#fff' // transparent pixels would turn black in a JPEG
    ctx.fillRect(0, 0, size, size)
    ctx.imageSmoothingQuality = 'high'
    ctx.drawImage(img, (img.naturalWidth - side) / 2, (img.naturalHeight - side) / 2, side, side, 0, 0, size, size)
    return canvas.toDataURL('image/jpeg', 0.85).split(',')[1]
  } finally {
    URL.revokeObjectURL(url)
  }
}
