import { lazy, Suspense, useEffect, useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import AppErrorBoundary from './components/AppErrorBoundary';
import RouteFallback from './components/RouteFallback';
import { getMe } from './auth';
import type { UserResponse } from './types';

const AccessSharing = lazy(() => import('./pages/AccessSharing'));
const Activity = lazy(() => import('./pages/Activity'));
const AdminUsers = lazy(() => import('./pages/AdminUsers'));
const ChangePasswordPage = lazy(() => import('./pages/ChangePassword'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const DocumentDetail = lazy(() => import('./pages/DocumentDetail'));
const Documents = lazy(() => import('./pages/Documents'));
const LandingPage = lazy(() => import('./pages/Landing'));
const LoginPage = lazy(() => import('./pages/Login'));
const NotFoundPage = lazy(() => import('./pages/NotFound'));
const RegisterPage = lazy(() => import('./pages/Register'));
const Settings = lazy(() => import('./pages/Settings'));
const SharedWithMe = lazy(() => import('./pages/SharedWithMe'));

/**
 * `/` is the workspace overview for a signed-in session and the public
 * landing page for anonymous visitors. The session is resolved once here so
 * the overview renders without a second session round-trip.
 */
function HomeRoute() {
  const [state, setState] = useState<'checking' | 'public' | 'signed-in'>('checking');
  const [user, setUser] = useState<UserResponse | null>(null);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((session) => {
        if (cancelled) {
          return;
        }
        setUser(session);
        setState(session ? 'signed-in' : 'public');
      })
      .catch(() => {
        if (!cancelled) {
          setState('public');
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (state === 'checking') {
    return <RouteFallback />;
  }
  if (state === 'signed-in' && user) {
    if (user.must_change_password) {
      return <Navigate to="/change-password" replace />;
    }
    return <Dashboard initialUser={user} />;
  }
  return <LandingPage />;
}

function RoutedContent() {
  const location = useLocation();

  return (
    <AppErrorBoundary key={location.pathname}>
      <Suspense fallback={<RouteFallback />}>
        <Routes>
          <Route path="/" element={<HomeRoute />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
          <Route path="/change-password" element={<ChangePasswordPage />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/documents" element={<Documents />} />
          <Route path="/documents/:id" element={<DocumentDetail />} />
          <Route path="/shared" element={<SharedWithMe />} />
          <Route path="/access" element={<AccessSharing />} />
          <Route path="/admin/audit" element={<Activity />} />
          <Route path="/activity" element={<Activity />} />
          <Route path="/admin/users" element={<AdminUsers />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </Suspense>
    </AppErrorBoundary>
  );
}

export default function Root() {
  return (
    <BrowserRouter>
      <RoutedContent />
    </BrowserRouter>
  );
}
