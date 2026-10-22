import { useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { register } from '../auth';
import { ApiError, NetworkError } from '../api';
import {
  ChevronLeftIcon,
  EyeIcon,
  EyeOffIcon,
  ShieldIcon,
} from '../components/Icons';
import InteractiveSurface from '../components/motion/InteractiveSurface';
import MagneticButton from '../components/motion/MagneticButton';

const PASSWORD_RULES = [
  { label: '12+ characters', test: (value: string) => value.length >= 12 },
  { label: 'Uppercase', test: (value: string) => /[A-Z]/.test(value) },
  { label: 'Lowercase', test: (value: string) => /[a-z]/.test(value) },
  { label: 'Number', test: (value: string) => /\d/.test(value) },
  {
    label: 'Symbol',
    test: (value: string) =>
      value.split('').some((char) => "!@#$%^&*()_+-=[]{}|;':\",./<>?".includes(char)),
  },
];

export default function RegisterPage() {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  const rulesMet = PASSWORD_RULES.map((rule) => rule.test(password));
  const passwordValid = rulesMet.every(Boolean);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);

    if (fullName.trim().length < 2) {
      setError('Enter your full name (at least 2 characters).');
      return;
    }
    if (!passwordValid) {
      setError('Choose a password that meets every requirement below.');
      return;
    }
    if (password !== confirmPassword) {
      setError('The passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      await register(fullName.trim(), email.trim(), password);
      navigate('/', { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail);
      } else if (err instanceof NetworkError) {
        setError(err.message);
      } else {
        setError('Registration failed. Please try again.');
      }
      setSubmitting(false);
    }
  };

  return (
    <div className="auth-layout">
      <section className="auth-brand" aria-label="About TrustVault">
        <div className="auth-brand-inner">
          <Link to="/" className="brand" aria-label="TrustVault home">
            <span className="brand-mark">
              <ShieldIcon width={22} height={22} />
            </span>
            <span className="brand-copy">
              <span className="brand-name">TrustVault</span>
              <span className="brand-tagline">Secure documents</span>
            </span>
          </Link>
          <span className="auth-kicker">Private by default</span>
          <h1 className="auth-headline">Begin with a private room.</h1>
          <p className="auth-subhead">
            New accounts are created as viewers. Owners decide which documents you can
            access and whether you can edit them.
          </p>
          <div className="auth-feature-list">
            <div className="auth-feature">
              <span className="auth-feature-icon">
                <ShieldIcon width={17} height={17} />
              </span>
              <div>
                <p className="auth-feature-title">No elevated access by default</p>
                <p className="auth-feature-copy">
                  Registration can never assign owner or administrator roles.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <main className="auth-panel">
        <InteractiveSurface className="auth-card">
          <Link to="/" className="auth-back">
            <ChevronLeftIcon width={13} height={13} />
            Back to home
          </Link>

          <div className="auth-card-brand">
            <span className="brand">
              <span className="brand-mark">
                <ShieldIcon width={22} height={22} />
              </span>
              <span className="brand-copy">
                <span className="brand-name">TrustVault</span>
                <span className="brand-tagline">Secure documents</span>
              </span>
            </span>
          </div>

          <header className="auth-card-header">
            <p className="eyebrow">Create account</p>
            <h1 className="auth-title">Create your workspace.</h1>
            <p className="auth-subtitle">
              Your account starts with viewer access. An owner can share documents with you.
            </p>
          </header>

          {error && (
            <div role="alert" className="alert alert-error">
              {error}
            </div>
          )}

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="field">
              <label htmlFor="register-name">Full name</label>
              <input
                id="register-name"
                className="input"
                type="text"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                autoComplete="name"
                placeholder="Ada Lovelace"
                maxLength={255}
                required
              />
            </div>

            <div className="field">
              <label htmlFor="register-email">Email</label>
              <input
                id="register-email"
                className="input"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                placeholder="you@example.com"
                required
              />
            </div>

            <div className="field">
              <label htmlFor="register-password">Password</label>
              <div className="input-wrap">
                <input
                  id="register-password"
                  className="input"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={128}
                  placeholder="Create a strong password"
                  required
                />
                <button
                  type="button"
                  className="input-action"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  aria-pressed={showPassword}
                  onClick={() => setShowPassword((visible) => !visible)}
                >
                  {showPassword ? (
                    <EyeOffIcon width={18} height={18} />
                  ) : (
                    <EyeIcon width={18} height={18} />
                  )}
                </button>
              </div>
              <div className="password-strength" aria-label="Password requirements">
                {PASSWORD_RULES.map((rule, index) => (
                  <span
                    key={rule.label}
                    className={`strength-pill${rulesMet[index] ? ' is-met' : ''}`}
                  >
                    {rulesMet[index] ? '✓ ' : ''}
                    {rule.label}
                  </span>
                ))}
              </div>
            </div>

            <div className="field">
              <label htmlFor="register-confirm">Confirm password</label>
              <input
                id="register-confirm"
                className="input"
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                placeholder="Repeat your password"
                required
              />
            </div>

            <MagneticButton type="submit" className="btn btn-primary btn-block" disabled={submitting}>
              {submitting ? 'Creating account.' : 'Create account'}
            </MagneticButton>
          </form>

          <p className="auth-alt">
            Already have an account? <Link to="/login">Sign in</Link>
          </p>

          <p className="auth-concept-note">
            Two-factor verification is a proposed UI concept, not enabled in this build.{' '}
            <Link to="/#two-factor">View the proposed flow</Link>.
          </p>
        </InteractiveSurface>
      </main>
    </div>
  );
}
