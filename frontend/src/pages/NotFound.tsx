import { Link } from 'react-router-dom';

export default function NotFoundPage() {
  return (
    <main className="not-found">
      <h2>404 — Page not found</h2>
      <p>We couldn&apos;t find the page you&apos;re looking for.</p>
      <Link to="/login">Go to sign in</Link>
    </main>
  );
}
