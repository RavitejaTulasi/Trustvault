import { Link } from 'react-router-dom';
import { FolderIcon } from '../components/Icons';

export default function NotFoundPage() {
  return (
    <main className="not-found-page">
      <div className="not-found-card">
        <span className="not-found-mark" aria-hidden="true">
          <FolderIcon width={26} height={26} />
        </span>
        <h1 className="not-found-title">404 — Page not found</h1>
        <p className="not-found-copy">
          We couldn&apos;t find the page you&apos;re looking for. Check the address or
          return to a known destination.
        </p>
        <div className="not-found-actions">
          <Link to="/login" className="btn btn-primary">
            Go to sign in
          </Link>
          <Link to="/" className="btn btn-secondary">
            Back to home
          </Link>
        </div>
      </div>
    </main>
  );
}
