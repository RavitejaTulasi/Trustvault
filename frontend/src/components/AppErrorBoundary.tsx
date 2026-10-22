import { Component } from 'react';
import type { ReactNode } from 'react';
import { ShieldAlertIcon } from './Icons';

interface AppErrorBoundaryProps {
  children: ReactNode;
}

interface AppErrorBoundaryState {
  hasError: boolean;
}

export default class AppErrorBoundary extends Component<
  AppErrorBoundaryProps,
  AppErrorBoundaryState
> {
  state: AppErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { hasError: true };
  }

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <main className="app-error">
        <section className="app-error-card" aria-labelledby="app-error-title">
          <span className="app-error-mark" aria-hidden="true">
            <ShieldAlertIcon width={28} height={28} />
          </span>
          <p className="eyebrow">Interface error</p>
          <h1 id="app-error-title" className="app-error-title">
            This page could not be displayed.
          </h1>
          <p className="app-error-copy">
            Your session and stored documents are unaffected. Reload the workspace, or
            return to the overview and try again.
          </p>
          <div className="app-error-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => window.location.reload()}
            >
              Reload workspace
            </button>
            <a className="btn btn-secondary" href="/">
              Back to overview
            </a>
          </div>
        </section>
      </main>
    );
  }
}
