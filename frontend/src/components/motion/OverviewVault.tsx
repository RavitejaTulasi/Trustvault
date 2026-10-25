import { useEffect, useRef, useState, type ComponentType } from 'react';
import { useReducedMotion } from 'motion/react';
import { ShieldIcon } from '../Icons';

interface VaultSceneProps {
  active: boolean;
  onReady: () => void;
  className?: string;
  cameraPosition?: [number, number, number];
  cameraFov?: number;
  vaultScale?: number;
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

export default function OverviewVault() {
  const hostRef = useRef<HTMLDivElement>(null);
  const reduceMotion = useReducedMotion();
  const [eligible, setEligible] = useState(false);
  const [inView, setInView] = useState(false);
  const [pageVisible, setPageVisible] = useState(true);
  const [Scene, setScene] = useState<VaultSceneComponent | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (typeof window.matchMedia !== 'function') {
      return;
    }

    const query = window.matchMedia('(min-width: 600px) and (pointer: fine)');
    const sceneSupported = !reduceMotion && supportsWebGL();
    const update = () => setEligible(sceneSupported && query.matches);
    update();
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, [reduceMotion]);

  useEffect(() => {
    const node = hostRef.current;
    if (!eligible || !node || typeof IntersectionObserver === 'undefined') {
      setInView(eligible);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => setInView(entry?.isIntersecting ?? false),
      { rootMargin: '160px 0px' },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [eligible]);

  useEffect(() => {
    const onVisibilityChange = () =>
      setPageVisible(document.visibilityState === 'visible');
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => document.removeEventListener('visibilitychange', onVisibilityChange);
  }, []);

  useEffect(() => {
    if (!eligible || !inView || !pageVisible || Scene) {
      return;
    }
    let cancelled = false;
    void import('../landing/VaultScene')
      .then((module) => {
        if (!cancelled) {
          setScene(() => module.default);
        }
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
    };
  }, [Scene, eligible, inView, pageVisible]);

  const showScene = eligible && !reduceMotion;

  return (
    <div
      ref={hostRef}
      className={`ov-artifact${ready && showScene ? ' ov-artifact-3d' : ''}`}
      aria-hidden="true"
    >
      <span className="ov-crosshair ov-crosshair-tl" aria-hidden="true" />
      <span className="ov-crosshair ov-crosshair-tr" aria-hidden="true" />
      <span className="ov-crosshair ov-crosshair-bl" aria-hidden="true" />
      <span className="ov-crosshair ov-crosshair-br" aria-hidden="true" />
      <span className="ov-artifact-code" aria-hidden="true">
        VAULT / 01
      </span>

      <span className="ov-artifact-glow" aria-hidden="true" />

      <div className="ov-vault-fallback">
        <span className="vault-orbit vault-orbit-1" />
        <span className="vault-orbit vault-orbit-2" />
        <span className="vault-orbit vault-orbit-3" />
        <span className="vault-node vault-node-1" />
        <span className="vault-node vault-node-2" />
        <span className="vault-node vault-node-3" />
        <span className="vault-core">
          <ShieldIcon />
        </span>
      </div>

      {showScene && Scene && (
        <Scene
          active={inView && pageVisible}
          onReady={() => setReady(true)}
          className="ov-vault-scene"
          cameraPosition={[0, 0, 6.1]}
          cameraFov={42}
          vaultScale={1.2}
        />
      )}

      <div className="ov-chip ov-chip-owner" aria-hidden="true">
        <span>Owner</span>
        <strong>Session</strong>
      </div>
      <div className="ov-chip ov-chip-grant" aria-hidden="true">
        <span>Grant</span>
        <strong>Explicit</strong>
      </div>
      <div className="ov-chip ov-chip-audit" aria-hidden="true">
        <span>Audit</span>
        <strong>Verified</strong>
      </div>

      <div className="ov-artifact-foot" aria-hidden="true">
        <span>LOCAL CHAIN / 0007</span>
        <span className="ov-artifact-signal">SECURE</span>
      </div>
    </div>
  );
}
