interface SkeletonProps {
  lines?: number;
  label?: string;
  className?: string;
}

export default function Skeleton({
  lines = 3,
  label = 'Loading content',
  className = '',
}: SkeletonProps) {
  return (
    <div
      className={`skeleton-table${className ? ` ${className}` : ''}`}
      role="status"
      aria-label={label}
      aria-busy="true"
    >
      {Array.from({ length: lines }, (_, index) => (
        <span key={index} className="skeleton skeleton-line" aria-hidden="true" />
      ))}
    </div>
  );
}
