// Spinner is the app-wide circular loading indicator. Use it anywhere data is
// loading or refreshing for a consistent look.
export default function Spinner({ size = 16, label }: { size?: number; label?: string }) {
  return (
    <span className="spinner-wrap">
      <span className="spinner" style={{ width: size, height: size }} aria-label={label || 'Loading'} role="status" />
      {label && <span className="spinner-label">{label}</span>}
    </span>
  )
}
