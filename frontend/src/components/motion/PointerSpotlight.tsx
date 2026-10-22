export default function PointerSpotlight({ className = '' }: { className?: string }) {
  return <span className={`pointer-spotlight${className ? ` ${className}` : ''}`} aria-hidden="true" />;
}
