import { useEffect, useRef, useState } from 'react';
import type { ComponentType, ReactNode, SVGProps } from 'react';
import { Link } from 'react-router-dom';
import {
  AnimatePresence,
  motion,
  useMotionValue,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
} from 'motion/react';
import {
  ActivityIcon,
  ArrowRightIcon,
  BadgeCheckIcon,
  CheckIcon,
  ClockIcon,
  CloseIcon,
  FileIcon,
  KeyIcon,
  LockIcon,
  MenuIcon,
  ShieldIcon,
  UsersIcon,
} from '../components/Icons';
import Reveal from '../components/motion/Reveal';
import { useLandingGsap } from '../hooks/useLandingGsap';
import { usePointerMotion } from '../hooks/usePointerMotion';
import { EASE_OUT, fadeUp, stagger } from '../lib/motion';
import '../landing.css';

type IconComponent = ComponentType<SVGProps<SVGSVGElement>>;

interface VaultSceneProps {
  active: boolean;
  onReady: () => void;
}

type VaultSceneComponent = ComponentType<VaultSceneProps>;

function supportsWebGL() {
  try {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('webgl2') ?? canvas.getContext('webgl');
    if (!context) {
      return false;
    }
    context.getExtension('WEBGL_lose_context')?.loseContext();
    return true;
  } catch {
    return false;
  }
}

function PointerCard({ className, children }: { className: string; children: ReactNode }) {
  const ref = usePointerMotion<HTMLElement>({ tilt: 2.2, shift: 3 });
  return (
    <article ref={ref} className={`lp-pointer ${className}`}>
      {children}
    </article>
  );
}

const CURRENT_YEAR = new Date().getFullYear();

const NAV_LINKS = [
  { label: 'Access', href: '#access' },
  { label: 'Audit', href: '#audit' },
  { label: 'Workflow', href: '#workflow' },
];

const MARQUEE_ITEMS = [
  'Owner-scoped storage',
  'Explicit grants',
  'Revocable access',
  'Tamper-evident audit trail',
  'HttpOnly sessions',
  'CSRF-checked writes',
  'Argon2id password hashing',
  'Role-aware navigation',
];

const ACCESS_POINTS: { title: string; copy: string; icon: IconComponent }[] = [
  {
    title: 'Ownership is not a preference',
    copy: 'Documents are written with an owner. Every request resolves access against that record before anything else happens.',
    icon: LockIcon,
  },
  {
    title: 'Grants are deliberate',
    copy: 'Sharing names a recipient and a capability. There is no public link, no inherited folder permission, and no ambient access.',
    icon: KeyIcon,
  },
  {
    title: 'Revocation wins',
    copy: 'Withdrawing a grant is immediate. Access is re-checked at request time rather than cached at the edge of the interface.',
    icon: ShieldIcon,
  },
];

const GRANTS = [
  { initials: 'AL', name: 'Ada Lovelace', email: 'owner', scope: 'Owner', tone: 'owner' },
  { initials: 'GH', name: 'Grace Hopper', email: 'grace@team.example', scope: 'Edit', tone: 'edit' },
  { initials: 'KH', name: 'Katherine Johnson', email: 'kj@team.example', scope: 'Read', tone: 'read' },
];

const CHAIN_ENTRIES = [
  { seq: '0007', action: 'Grant revoked', actor: 'owner · ada', hash: '8f31c0a2' },
  { seq: '0006', action: 'Document viewed', actor: 'viewer · grace', hash: '4d90be17' },
  { seq: '0005', action: 'Share granted', actor: 'owner · ada', hash: 'b6e2f409' },
  { seq: '0004', action: 'Document uploaded', actor: 'owner · ada', hash: '17aa6c83' },
];

const WORKFLOW = [
  {
    title: 'Store',
    copy: 'Files land in private storage with generated identifiers. The public file name never becomes a path.',
    meta: 'PRIVATE / SERVER',
  },
  {
    title: 'Scope',
    copy: 'Each request resolves the owner, the grant, and the action before a document is opened.',
    meta: 'CHECK / EVERY CALL',
  },
  {
    title: 'Share',
    copy: 'A grant is explicit, narrow, and reversible. Revoking it removes the capability on the next request.',
    meta: 'EXPLICIT / REVOCABLE',
  },
  {
    title: 'Prove',
    copy: 'Important actions are appended to a hash-chained audit trail that owners and administrators can verify locally.',
    meta: 'APPEND / VERIFY',
  },
];

const AUDIT_NOTES: { title: string; copy: string; icon: IconComponent }[] = [
  {
    title: 'Append-only by construction',
    copy: 'Each entry carries the hash of the entry before it. Rewriting history breaks the chain instead of hiding it.',
    icon: ActivityIcon,
  },
  {
    title: 'Verify in the open',
    copy: 'Owners and administrators can run a local verification pass and see the chain head and its entry count.',
    icon: BadgeCheckIcon,
  },
  {
    title: 'Honest boundaries',
    copy: 'Independent checkpoint anchoring requires an external anchor store. Until that is configured, verification remains local.',
    icon: ClockIcon,
  },
];

const HERO_FACTS = ['Owner-scoped storage', 'Explicit grants', 'Tamper-evident audit'];

function BrandMark() {
  return (
    <span className="lp-brand-mark" aria-hidden="true">
      <ShieldIcon width={19} height={19} />
    </span>
  );
}

function VaultArtifact() {
  const reduceMotion = useReducedMotion();
  const ref = useRef<HTMLDivElement>(null);
  const [sceneEligible, setSceneEligible] = useState(false);
  const [sceneInView, setSceneInView] = useState(false);
  const [pageVisible, setPageVisible] = useState(true);
  const [Scene, setScene] = useState<VaultSceneComponent | null>(null);
  const [sceneReady, setSceneReady] = useState(false);
  const pointerX = useMotionValue(0);
  const pointerY = useMotionValue(0);
  const springX = useSpring(pointerX, { stiffness: 70, damping: 18, mass: 0.8 });
  const springY = useSpring(pointerY, { stiffness: 70, damping: 18, mass: 0.8 });
  const rotateY = useTransform(springX, [-1, 1], [-8, 8]);
  const rotateX = useTransform(springY, [-1, 1], [6, -6]);
  const glowX = useTransform(springX, [-1, 1], ['34%', '66%']);
  const glowY = useTransform(springY, [-1, 1], ['40%', '60%']);

  const sceneAllowed = sceneEligible && !reduceMotion;

  useEffect(() => {
    if (reduceMotion || typeof window.matchMedia !== 'function' || !supportsWebGL()) {
      return;
    }

    const query = window.matchMedia('(min-width: 900px) and (pointer: fine)');
    const update = () => setSceneEligible(query.matches);
    update();
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, [reduceMotion]);

  useEffect(() => {
    const node = ref.current;
    if (!sceneAllowed || !node || typeof IntersectionObserver === 'undefined') {
      setSceneInView(sceneAllowed);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => setSceneInView(entry?.isIntersecting ?? false),
      { rootMargin: '180px 0px' },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [sceneAllowed]);

  useEffect(() => {
    const onVisibilityChange = () =>
      setPageVisible(document.visibilityState === 'visible');
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, []);

  useEffect(() => {
    if (!sceneAllowed || !sceneInView || Scene) {
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void import('../components/landing/VaultScene')
        .then((module) => {
          if (!cancelled) {
            setScene(() => module.default);
          }
        })
        .catch(() => undefined);
    }, 320);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [Scene, sceneAllowed, sceneInView]);

  const onPointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    if (reduceMotion || !ref.current) {
      return;
    }
    const rect = ref.current.getBoundingClientRect();
    pointerX.set(((event.clientX - rect.left) / rect.width - 0.5) * 2);
    pointerY.set(((event.clientY - rect.top) / rect.height - 0.5) * 2);
  };

  const resetPointer = () => {
    pointerX.set(0);
    pointerY.set(0);
  };

  return (
    <motion.div
      ref={ref}
      className={`lp-artifact${sceneReady ? ' lp-artifact-3d' : ''}`}
      onPointerMove={onPointerMove}
      onPointerLeave={resetPointer}
      role="img"
      aria-label="Illustrative vault visualization showing owner-scoped access and a verified local audit chain"
      initial={reduceMotion ? false : { opacity: 0, y: 26 }}
      animate={reduceMotion ? undefined : { opacity: 1, y: 0 }}
      transition={{ duration: 0.9, ease: EASE_OUT, delay: 0.15 }}
    >
      <span className="lp-crosshair lp-crosshair-tl" aria-hidden="true" />
      <span className="lp-crosshair lp-crosshair-tr" aria-hidden="true" />
      <span className="lp-crosshair lp-crosshair-bl" aria-hidden="true" />
      <span className="lp-crosshair lp-crosshair-br" aria-hidden="true" />
      <span className="lp-artifact-code" aria-hidden="true">
        VAULT / 01
      </span>

      <motion.span
        className="lp-artifact-glow"
        aria-hidden="true"
        style={{ left: glowX, top: glowY }}
      />

      {sceneAllowed && Scene && (
        <Scene
          active={sceneInView && pageVisible}
          onReady={() => setSceneReady(true)}
        />
      )}

      <motion.div
        className="lp-vault"
        style={{ rotateX, rotateY, transformPerspective: 1100 }}
        aria-hidden="true"
      >
        <span className="lp-vault-orbit lp-vault-orbit-a" />
        <span className="lp-vault-orbit lp-vault-orbit-b" />
        <span className="lp-vault-plate" />
        <div className="lp-vault-door">
          <span className="lp-vault-ticks" />
          <span className="lp-vault-ring" />
          <span className="lp-vault-bolt lp-vault-bolt-1" />
          <span className="lp-vault-bolt lp-vault-bolt-2" />
          <span className="lp-vault-bolt lp-vault-bolt-3" />
          <span className="lp-vault-bolt lp-vault-bolt-4" />
          <span className="lp-vault-core">
            <LockIcon width={34} height={34} />
          </span>
        </div>
      </motion.div>

      <div className="lp-chip lp-chip-owner" aria-hidden="true">
        <span>Owner</span>
        <strong>Ada L.</strong>
      </div>
      <div className="lp-chip lp-chip-grant" aria-hidden="true">
        <span>Grant</span>
        <strong>Read</strong>
      </div>
      <div className="lp-chip lp-chip-audit" aria-hidden="true">
        <span>Audit</span>
        <strong>Sealed</strong>
      </div>

      <div className="lp-artifact-foot" aria-hidden="true">
        <span>LOCAL CHAIN / 0007</span>
        <span className="lp-artifact-signal">VERIFIED</span>
      </div>
    </motion.div>
  );
}

function Header() {
  const [open, setOpen] = useState(false);
  const reduceMotion = useReducedMotion();

  return (
    <header className="lp-header">
      <div className="lp-shell lp-header-inner">
        <Link to="/" className="lp-brand" aria-label="TrustVault home">
          <BrandMark />
          <span className="lp-brand-copy">
            <span className="lp-brand-name">TrustVault</span>
            <span className="lp-brand-tag">Private document workspace</span>
          </span>
        </Link>

        <nav className="lp-nav" aria-label="Landing">
          {NAV_LINKS.map((link) => (
            <a key={link.href} href={link.href} className="lp-nav-link">
              {link.label}
            </a>
          ))}
        </nav>

        <div className="lp-header-actions">
          <Link to="/login" className="lp-sign-in">
            Sign in
          </Link>
          <Link to="/register" className="lp-button lp-button-compact">
            Create a vault
            <ArrowRightIcon width={15} height={15} />
          </Link>
          <button
            type="button"
            className="lp-menu-button"
            aria-label={open ? 'Close menu' : 'Open menu'}
            aria-expanded={open}
            aria-controls="lp-mobile-nav"
            onClick={() => setOpen((value) => !value)}
          >
            {open ? <CloseIcon /> : <MenuIcon />}
          </button>
        </div>
      </div>

      <AnimatePresence>
        {open && (
          <motion.div
            id="lp-mobile-nav"
            className="lp-mobile-nav"
            initial={reduceMotion ? false : { opacity: 0, y: -8 }}
            animate={reduceMotion ? undefined : { opacity: 1, y: 0 }}
            exit={reduceMotion ? undefined : { opacity: 0, y: -8 }}
            transition={{ duration: 0.2, ease: EASE_OUT }}
          >
            {NAV_LINKS.map((link) => (
              <a
                key={link.href}
                href={link.href}
                className="lp-mobile-link"
                onClick={() => setOpen(false)}
              >
                {link.label}
                <ArrowRightIcon width={15} height={15} />
              </a>
            ))}
            <div className="lp-mobile-actions">
              <Link to="/login" className="lp-link" onClick={() => setOpen(false)}>
                Sign in
              </Link>
              <Link to="/register" className="lp-button" onClick={() => setOpen(false)}>
                Create a vault
              </Link>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}

export default function Landing() {
  const reduceMotion = useReducedMotion();
  const rootRef = useRef<HTMLDivElement>(null);
  const heroRef = usePointerMotion<HTMLElement>({ tilt: 0, shift: 0 });
  const { scrollYProgress } = useScroll();
  const progress = useSpring(scrollYProgress, {
    stiffness: 140,
    damping: 30,
    restDelta: 0.001,
  });
  useLandingGsap(rootRef, !reduceMotion);

  return (
    <div ref={rootRef} className="lp">
      <a className="skip-link" href="#lp-main">
        Skip to content
      </a>
      <motion.span
        className="lp-progress"
        style={{ scaleX: reduceMotion ? 1 : progress }}
        aria-hidden="true"
      />

      <Header />

      <main id="lp-main">
        <section ref={heroRef} className="lp-hero" aria-labelledby="lp-hero-title">
          <span className="lp-hero-spotlight" aria-hidden="true" />
          <div className="lp-shell lp-hero-grid">
            <motion.div
              className="lp-hero-copy"
              variants={stagger(0.09, 0.1)}
              initial={reduceMotion ? false : 'hidden'}
              animate={reduceMotion ? undefined : 'show'}
            >
              <motion.p className="lp-kicker" variants={fadeUp}>
                <span className="lp-kicker-dot" aria-hidden="true" />
                Private infrastructure for sensitive files
              </motion.p>
              <motion.h1 id="lp-hero-title" className="lp-title" variants={fadeUp}>
                <span className="lp-title-line">Keep what matters.</span>
                <span className="lp-title-line lp-title-accent">Out of reach.</span>
              </motion.h1>
              <motion.p className="lp-lede" variants={fadeUp}>
                TrustVault is a private document workspace built around ownership. Explicit grants,
                revocable access, and a tamper-evident record of every consequential action.
              </motion.p>
              <motion.div className="lp-hero-actions" variants={fadeUp}>
                <Link to="/register" className="lp-button lp-button-lg">
                  Create your vault
                  <ArrowRightIcon width={16} height={16} />
                </Link>
                <a href="#access" className="lp-button lp-button-quiet lp-button-lg">
                  Inspect the controls
                </a>
              </motion.div>
              <motion.ul className="lp-hero-facts" variants={fadeUp}>
                {HERO_FACTS.map((fact) => (
                  <li key={fact}>
                    <span className="lp-fact-tick" aria-hidden="true" />
                    {fact}
                  </li>
                ))}
              </motion.ul>
            </motion.div>

            <div className="lp-hero-visual">
              <div className="lp-artifact-parallax">
                <VaultArtifact />
              </div>
              <span className="lp-hero-side-label" aria-hidden="true">
                ACCESS / CONTROL / RECORD
              </span>
            </div>
          </div>
        </section>

        <div className="lp-strip" aria-hidden="true">
          <div className="lp-strip-track">
            {[...MARQUEE_ITEMS, ...MARQUEE_ITEMS].map((item, index) => (
              <span key={`${item}-${index}`} className="lp-strip-item">
                {item}
                <span className="lp-strip-cross">+</span>
              </span>
            ))}
          </div>
        </div>

        <section id="access" className="lp-section" aria-labelledby="lp-access-title">
          <div className="lp-shell">
            <div className="lp-section-head">
              <Reveal>
                <p className="lp-index">
                  <span>01</span> Access
                </p>
              </Reveal>
              <Reveal delay={0.05}>
                <h2 id="lp-access-title" className="lp-h2">
                  Sharing is a decision,
                  <br />
                  not a default.
                </h2>
              </Reveal>
              <Reveal delay={0.1}>
                <p className="lp-lede lp-lede-narrow">
                  There is no discoverable feed and no public URL. A document is visible because
                  someone with authority chose to make it visible.
                </p>
              </Reveal>
            </div>

            <div className="lp-access-grid">
              <div className="lp-access-points">
                {ACCESS_POINTS.map((point, index) => {
                  const Icon = point.icon;
                  return (
                    <Reveal key={point.title} delay={index * 0.07}>
                      <PointerCard className="lp-access-point">
                        <span className="lp-access-icon" aria-hidden="true">
                          <Icon width={18} height={18} />
                        </span>
                        <div>
                          <h3 className="lp-h3">{point.title}</h3>
                          <p className="lp-body">{point.copy}</p>
                        </div>
                      </PointerCard>
                    </Reveal>
                  );
                })}
              </div>

              <Reveal delay={0.12} className="lp-access-reveal">
                <div className="lp-console">
                  <div className="lp-console-chrome">
                    <span className="lp-console-dots" aria-hidden="true">
                      <i />
                      <i />
                      <i />
                    </span>
                    <code>access_matrix.sec</code>
                    <span className="lp-console-badge">Illustrative</span>
                  </div>

                  <div className="lp-console-head">
                    <span className="lp-console-file" aria-hidden="true">
                      <FileIcon width={18} height={18} />
                    </span>
                    <div>
                      <p className="lp-console-title">Identity &amp; travel</p>
                      <p className="lp-console-meta">Owner: Ada Lovelace · 2.4 MB · PDF</p>
                    </div>
                    <span className="lp-console-lock" aria-hidden="true">
                      <LockIcon width={15} height={15} />
                    </span>
                  </div>

                  <ul className="lp-grant-list">
                    {GRANTS.map((grant) => (
                      <li key={grant.email} className="lp-grant">
                        <span className={`lp-grant-avatar lp-grant-avatar-${grant.tone}`}>
                          {grant.initials}
                        </span>
                        <span className="lp-grant-copy">
                          <span className="lp-grant-name">{grant.name}</span>
                          <span className="lp-grant-email">{grant.email}</span>
                        </span>
                        <span className={`lp-grant-scope lp-grant-scope-${grant.tone}`}>
                          {grant.scope}
                        </span>
                      </li>
                    ))}
                  </ul>

                  <div className="lp-console-foot">
                    <span className="lp-console-signal" aria-hidden="true" />
                    Access resolved per request
                    <span className="lp-console-foot-code">POLICY / OWNER+GRANT</span>
                  </div>
                </div>
              </Reveal>
            </div>
          </div>
        </section>

        <section id="audit" className="lp-section lp-section-audit" aria-labelledby="lp-audit-title">
          <div className="lp-shell">
            <div className="lp-audit-head">
              <div>
                <Reveal>
                  <p className="lp-index">
                    <span>02</span> Audit
                  </p>
                </Reveal>
                <Reveal delay={0.05}>
                  <h2 id="lp-audit-title" className="lp-h2">
                    Every change
                    <br />
                    leaves a mark.
                  </h2>
                </Reveal>
              </div>
              <Reveal delay={0.1}>
                <p className="lp-lede lp-lede-narrow">
                  The audit trail is a hash chain, not a feed of friendly messages. Each entry
                  commits to the one before it, so silent edits break verification.
                </p>
              </Reveal>
            </div>

            <div className="lp-audit-grid">
              <Reveal className="lp-chain-reveal">
                <div className="lp-console lp-chain-console">
                  <div className="lp-console-chrome">
                    <span className="lp-console-dots" aria-hidden="true">
                      <i />
                      <i />
                      <i />
                    </span>
                    <code>audit_chain.log</code>
                    <span className="lp-console-badge lp-console-badge-ok">Chain valid</span>
                  </div>

                  <span className="lp-audit-scan" aria-hidden="true" />

                  <ol className="lp-chain">
                    {CHAIN_ENTRIES.map((entry, index) => (
                      <motion.li
                        key={entry.seq}
                        className="lp-chain-entry"
                        initial={reduceMotion ? false : { opacity: 0, x: -10 }}
                        whileInView={reduceMotion ? undefined : { opacity: 1, x: 0 }}
                        viewport={{ once: true, amount: 0.5 }}
                        transition={{ duration: 0.4, ease: EASE_OUT, delay: index * 0.08 }}
                      >
                        <span className="lp-chain-node" aria-hidden="true">
                          <CheckIcon width={12} height={12} />
                        </span>
                        <span className="lp-chain-seq">{entry.seq}</span>
                        <span className="lp-chain-copy">
                          <span className="lp-chain-action">{entry.action}</span>
                          <span className="lp-chain-actor">{entry.actor}</span>
                        </span>
                        <code className="lp-chain-hash">{entry.hash}</code>
                      </motion.li>
                    ))}
                  </ol>

                  <div className="lp-console-foot">
                    <span className="lp-console-signal" aria-hidden="true" />
                    Local verification only
                    <span className="lp-console-foot-code">SHA-256 / LINKED</span>
                  </div>
                </div>
              </Reveal>

              <div className="lp-audit-notes">
                {AUDIT_NOTES.map((note, index) => {
                  const Icon = note.icon;
                  return (
                    <Reveal key={note.title} delay={index * 0.07}>
                      <PointerCard className="lp-audit-note">
                        <span className="lp-audit-note-icon" aria-hidden="true">
                          <Icon width={17} height={17} />
                        </span>
                        <div>
                          <h3 className="lp-h3">{note.title}</h3>
                          <p className="lp-body">{note.copy}</p>
                        </div>
                      </PointerCard>
                    </Reveal>
                  );
                })}
              </div>
            </div>
          </div>
        </section>

        <section id="workflow" className="lp-section lp-section-workflow" aria-labelledby="lp-workflow-title">
          <div className="lp-shell lp-workflow-grid">
            <div className="lp-workflow-intro">
              <Reveal>
                <p className="lp-index">
                  <span>03</span> Workflow
                </p>
              </Reveal>
              <Reveal delay={0.05}>
                <h2 id="lp-workflow-title" className="lp-h2">
                  Private to shared,
                  <br />
                  in four moves.
                </h2>
              </Reveal>
              <Reveal delay={0.1}>
                <p className="lp-lede lp-lede-narrow">
                  A short path with no shortcuts. Each step leaves evidence you can inspect later.
                </p>
              </Reveal>
              <Reveal delay={0.15}>
                <Link to="/register" className="lp-button lp-button-quiet">
                  Open a workspace
                  <ArrowRightIcon width={15} height={15} />
                </Link>
              </Reveal>
            </div>

            <ol className="lp-steps">
              {WORKFLOW.map((step, index) => (
                <Reveal key={step.title} delay={index * 0.05}>
                  <li className="lp-step">
                    <span className="lp-step-number" aria-hidden="true">
                      {String(index + 1).padStart(2, '0')}
                    </span>
                    <div className="lp-step-copy">
                      <div className="lp-step-top">
                        <h3 className="lp-h3">{step.title}</h3>
                        <span className="lp-step-meta">{step.meta}</span>
                      </div>
                      <p className="lp-body">{step.copy}</p>
                    </div>
                  </li>
                </Reveal>
              ))}
            </ol>
          </div>
        </section>

        <section className="lp-cta" aria-labelledby="lp-cta-title">
          <div className="lp-cta-grid" aria-hidden="true" />
          <motion.div
            className="lp-shell lp-cta-inner"
            initial={reduceMotion ? false : { opacity: 0, y: 20 }}
            whileInView={reduceMotion ? undefined : { opacity: 1, y: 0 }}
            viewport={{ once: true, amount: 0.4 }}
            transition={{ duration: 0.7, ease: EASE_OUT }}
          >
            <span className="lp-cta-mark" aria-hidden="true">
              <UsersIcon width={22} height={22} />
            </span>
            <h2 id="lp-cta-title" className="lp-cta-title">
              Put the important things
              <br />
              behind a decision.
            </h2>
            <p className="lp-lede lp-lede-narrow">
              Create a private workspace, invite only the people who need it, and keep the record.
            </p>
            <div className="lp-cta-actions">
              <Link to="/register" className="lp-button lp-button-lg">
                Create your vault
                <ArrowRightIcon width={16} height={16} />
              </Link>
              <Link to="/login" className="lp-button lp-button-quiet lp-button-lg">
                Sign in
              </Link>
            </div>
          </motion.div>
        </section>
      </main>

      <footer className="lp-footer">
        <div className="lp-shell lp-footer-inner">
          <div className="lp-footer-brand">
            <Link to="/" className="lp-brand" aria-label="TrustVault home">
              <BrandMark />
              <span className="lp-brand-copy">
                <span className="lp-brand-name">TrustVault</span>
                <span className="lp-brand-tag">Private document workspace</span>
              </span>
            </Link>
            <p className="lp-footer-note">
              A local-first document workspace for people who treat access as a decision.
            </p>
          </div>

          <div className="lp-footer-links">
            <div>
              <p className="lp-footer-label">Product</p>
              <a href="#access">Access</a>
              <a href="#audit">Audit</a>
              <a href="#workflow">Workflow</a>
            </div>
            <div>
              <p className="lp-footer-label">Workspace</p>
              <Link to="/login">Sign in</Link>
              <Link to="/register">Create account</Link>
            </div>
          </div>
        </div>
        <div className="lp-shell lp-footer-bottom">
          <span>© {CURRENT_YEAR} TrustVault</span>
          <span className="lp-footer-code">LOCAL BUILD / SECURITY-FIRST</span>
        </div>
      </footer>
    </div>
  );
}
