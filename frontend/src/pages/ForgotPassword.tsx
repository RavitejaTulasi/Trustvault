import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  confirmPasswordReset,
  getMe,
  requestPasswordReset,
  verifyPasswordResetOtp,
} from '../auth';
import {
  BadgeCheckIcon,
  ChevronLeftIcon,
  EyeIcon,
  EyeOffIcon,
  LockIcon,
  ShieldIcon,
} from '../components/Icons';
import InteractiveSurface from '../components/motion/InteractiveSurface';
import MagneticButton from '../components/motion/MagneticButton';
import { describeError } from '../lib/format';

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

type Step = 'email' | 'code' | 'password' | 'done';

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>('email');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Recovery codes belong to the login surface only. Signed-in users change
  // their password from Settings, where the current password is required.
  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((session) => {
        if (session && !cancelled) {
          navigate(session.must_change_password ? '/change-password' : '/', {
            replace: true,
          });
        }
      })
      .catch(() => {
        // A failed session check must not block an anonymous recovery attempt.
      });
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  const rulesMet = PASSWORD_RULES.map((rule) => rule.test(password));
  const passwordValid = rulesMet.every(Boolean);

  const normalizedEmail = () => email.trim().toLowerCase();

  const handleRequest = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await requestPasswordReset(normalizedEmail());
      setNotice(
        'If an account exists for this email, a 6-digit code has been sent. It expires in 15 minutes.',
      );
      setCode('');
      setStep('code');
    } catch (err) {
      setError(describeError(err, 'Could not send a reset code'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleResend = async () => {
    setError(null);
    setSubmitting(true);
    try {
      await requestPasswordReset(normalizedEmail());
      setCode('');
      setNotice(
        'A new code has been sent. Any earlier code is no longer valid.',
      );
    } catch (err) {
      setError(describeError(err, 'Could not send a new code'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleVerify = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    if (!/^\d{6}$/.test(code)) {
      setError('Enter the 6-digit code from your email.');
      return;
    }
    setSubmitting(true);
    try {
      await verifyPasswordResetOtp(normalizedEmail(), code);
      setNotice(null);
      setStep('password');
    } catch (err) {
      setError(describeError(err, 'Could not verify the code'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleConfirm = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    if (!passwordValid) {
      setError('Choose a password that meets every requirement.');
      return;
    }
    if (password !== confirmPassword) {
      setError('The passwords do not match.');
      return;
    }
    setSubmitting(true);
    try {
      await confirmPasswordReset(normalizedEmail(), code, password);
      setNotice(null);
      setStep('done');
    } catch (err) {
      setError(describeError(err, 'Could not reset your password'));
    } finally {
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
          <span className="auth-kicker">Recover access</span>
          <h1 className="auth-headline">Confirm it is really you.</h1>
          <p className="auth-subhead">
            A one-time code verifies your email before the password can be replaced.
            Signed-in members change their password from Settings instead.
          </p>
          <div className="auth-feature-list">
            <div className="auth-feature">
              <span className="auth-feature-icon">
                <LockIcon width={17} height={17} />
              </span>
              <div>
                <p className="auth-feature-title">Login-page recovery only</p>
                <p className="auth-feature-copy">
                  Account settings require your current password; administrators can
                  reset passwords from user management.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <main className="auth-panel">
        <InteractiveSurface className="auth-card">
          <Link to="/login" className="auth-back">
            <ChevronLeftIcon width={13} height={13} />
            Back to sign in
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
            <p className="eyebrow">
              Password recovery
              {step !== 'done' && ` · Step ${
                step === 'email' ? 1 : step === 'code' ? 2 : 3
              } of 3`}
            </p>
            <h1 className="auth-title">
              {step === 'email' && 'Reset your password.'}
              {step === 'code' && 'Enter the one-time code.'}
              {step === 'password' && 'Choose a new password.'}
              {step === 'done' && 'Password reset.'}
            </h1>
            <p className="auth-subtitle">
              {step === 'email' &&
                'Enter the email tied to your workspace account to receive a one-time code.'}
              {step === 'code' && (
                <>
                  Sent to <strong>{email.trim().toLowerCase()}</strong>. The code expires
                  in 15 minutes.
                </>
              )}
              {step === 'password' &&
                'The code is verified. Choose a password you have not used before.'}
              {step === 'done' && (
                <>
                  Your password was updated. Sign in as{' '}
                  <strong>{email.trim().toLowerCase()}</strong> with the new password.
                </>
              )}
            </p>
          </header>

          {error && (
            <div role="alert" className="alert alert-error">
              {error}
            </div>
          )}

          {step === 'email' && (
            <form className="auth-form" onSubmit={handleRequest}>
              <div className="field">
                <label htmlFor="reset-email">Email</label>
                <input
                  id="reset-email"
                  className="input"
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                  autoComplete="email"
                  placeholder="you@example.com"
                  autoFocus
                />
              </div>
              <MagneticButton
                type="submit"
                className="btn btn-primary btn-block"
                disabled={submitting}
              >
                {submitting ? 'Sending code.' : 'Send one-time code'}
              </MagneticButton>
            </form>
          )}

          {step === 'code' && (
            <>
              {notice && (
                <div role="status" className="notice notice-success">
                  {notice}
                </div>
              )}
              <form className="auth-form" onSubmit={handleVerify}>
                <div className="field">
                  <label htmlFor="reset-code">One-time code</label>
                  <input
                    id="reset-code"
                    className="input"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength={6}
                    value={code}
                    onChange={(event) =>
                      setCode(event.target.value.replace(/\D/g, '').slice(0, 6))
                    }
                    required
                    autoComplete="one-time-code"
                    placeholder="000000"
                    autoFocus
                  />
                  <p className="field-hint">
                    In this deployment the code is printed in the backend console.
                  </p>
                </div>
                <MagneticButton
                  type="submit"
                  className="btn btn-primary btn-block"
                  disabled={submitting}
                >
                  {submitting ? 'Verifying.' : 'Verify code'}
                </MagneticButton>
                <p className="auth-alt">
                  Did not receive it?{' '}
                  <button
                    type="button"
                    className="auth-link-button"
                    onClick={() => void handleResend()}
                    disabled={submitting}
                  >
                    Send a new code
                  </button>
                </p>
              </form>
            </>
          )}

          {step === 'password' && (
            <form className="auth-form" onSubmit={handleConfirm}>
              <div className="field">
                <label htmlFor="reset-password">New password</label>
                <div className="input-wrap">
                  <input
                    id="reset-password"
                    className="input"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    required
                    minLength={12}
                    maxLength={128}
                    autoComplete="new-password"
                    autoFocus
                  />
                  <button
                    type="button"
                    className="input-action"
                    aria-label={showPassword ? 'Hide passwords' : 'Show passwords'}
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
                      {rulesMet[index] ? 'Met: ' : ''}
                      {rule.label}
                    </span>
                  ))}
                </div>
              </div>
              <div className="field">
                <label htmlFor="reset-confirm">Confirm new password</label>
                <input
                  id="reset-confirm"
                  className="input"
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  required
                  autoComplete="new-password"
                />
              </div>
              <MagneticButton
                type="submit"
                className="btn btn-primary btn-block"
                disabled={submitting}
              >
                {submitting ? 'Resetting.' : 'Reset password'}
              </MagneticButton>
            </form>
          )}

          {step === 'done' && (
            <>
              <div className="auth-feature">
                <span className="auth-feature-icon">
                  <BadgeCheckIcon width={18} height={18} />
                </span>
                <div>
                  <h2 className="section-title">Password updated</h2>
                  <p className="section-copy">
                    Every other session was signed out. Use the new password the next
                    time you sign in.
                  </p>
                </div>
              </div>
              <div className="form-actions">
                <Link to="/login" className="btn btn-primary btn-block">
                  Go to sign in
                </Link>
              </div>
            </>
          )}

          <p className="auth-concept-note">
            Recovery codes are single-use, expire after 15 minutes, and are invalidated
            after five incorrect attempts.
          </p>
        </InteractiveSurface>
      </main>
    </div>
  );
}
