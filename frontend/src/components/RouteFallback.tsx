import { ShieldIcon } from './Icons';

export default function RouteFallback() {
  return (
    <div className="route-loader" role="status" aria-live="polite">
      <span className="sr-only">Loading page…</span>
      <span className="route-loader-mark" aria-hidden="true">
        <ShieldIcon width={22} height={22} />
      </span>
      <span className="skeleton route-loader-bar" aria-hidden="true" />
      <span className="skeleton route-loader-bar" aria-hidden="true" />
      <span className="skeleton route-loader-bar" aria-hidden="true" />
    </div>
  );
}
