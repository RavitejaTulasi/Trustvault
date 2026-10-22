import { useEffect } from 'react';

const INTERACTIVE_SURFACE = [
  '[data-pointer-surface]',
  '.btn',
  '.icon-btn',
  '.menu-trigger',
  '.nav-link',
  '.tab',
  '.command-option',
  '.panel',
  '.card-tilt',
  '.summary-strip',
  '.audit-verify',
  '.checkpoint-panel',
  '.access-panel',
  '.user-card',
  '.quick-action',
  '.toast-close',
  '.back-button',
  '.auth-back',
  '.lp-button',
  '.lp-nav-link',
  '.lp-sign-in',
  '.lp-menu-button',
  '.lp-mobile-link',
].join(',');

/**
 * One document-level pointer controller. It updates CSS custom properties in a
 * rAF callback and never triggers React renders. Coarse pointers and
 * reduced-motion users get no pointer layer at all.
 */
export function useGlobalPointer(): void {
  useEffect(() => {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
      return;
    }
    if (typeof window.matchMedia !== 'function') {
      return;
    }

    const root = document.documentElement;
    const finePointer = window.matchMedia('(pointer: fine)');
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

    let frame = 0;
    let pointerX = 0;
    let pointerY = 0;
    let activeSurface: HTMLElement | null = null;

    const setSurface = (surface: HTMLElement | null) => {
      if (activeSurface === surface) {
        return;
      }
      if (activeSurface) {
        delete activeSurface.dataset.pointer;
        activeSurface.style.removeProperty('--pm-x');
        activeSurface.style.removeProperty('--pm-y');
        activeSurface.style.removeProperty('--pm-nx');
        activeSurface.style.removeProperty('--pm-ny');
      }
      activeSurface = surface;
      if (activeSurface) {
        activeSurface.dataset.pointer = 'active';
      }
    };

    const paint = () => {
      frame = 0;
      root.style.setProperty('--pointer-x', `${pointerX.toFixed(1)}px`);
      root.style.setProperty('--pointer-y', `${pointerY.toFixed(1)}px`);
      root.style.setProperty(
        '--pointer-nx',
        (pointerX / Math.max(1, window.innerWidth)).toFixed(3),
      );
      root.style.setProperty(
        '--pointer-ny',
        (pointerY / Math.max(1, window.innerHeight)).toFixed(3),
      );

      if (!activeSurface) {
        return;
      }
      const rect = activeSurface.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) {
        return;
      }
      const localX = Math.min(1, Math.max(0, (pointerX - rect.left) / rect.width));
      const localY = Math.min(1, Math.max(0, (pointerY - rect.top) / rect.height));
      activeSurface.style.setProperty('--pm-x', `${(localX * 100).toFixed(2)}%`);
      activeSurface.style.setProperty('--pm-y', `${(localY * 100).toFixed(2)}%`);
      activeSurface.style.setProperty('--pm-nx', (localX * 2 - 1).toFixed(3));
      activeSurface.style.setProperty('--pm-ny', (localY * 2 - 1).toFixed(3));
    };

    const onPointerMove = (event: PointerEvent) => {
      if (event.pointerType === 'touch') {
        return;
      }
      pointerX = event.clientX;
      pointerY = event.clientY;
      const target = event.target;
      const surface =
        target instanceof Element
          ? target.closest<HTMLElement>(INTERACTIVE_SURFACE)
          : null;
      setSurface(surface);
      root.dataset.pointerFx = 'on';
      if (frame === 0) {
        frame = window.requestAnimationFrame(paint);
      }
    };

    const reset = () => {
      if (frame !== 0) {
        window.cancelAnimationFrame(frame);
        frame = 0;
      }
      setSurface(null);
      delete root.dataset.pointerFx;
      root.style.setProperty('--pointer-x', '50vw');
      root.style.setProperty('--pointer-y', '50vh');
    };

    const syncCapability = () => {
      if (!finePointer.matches || reduceMotion.matches) {
        reset();
      }
    };

    if (!finePointer.matches || reduceMotion.matches) {
      return;
    }

    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('blur', reset);
    document.addEventListener('pointerleave', reset);
    document.addEventListener('visibilitychange', syncCapability);
    finePointer.addEventListener('change', syncCapability);
    reduceMotion.addEventListener('change', syncCapability);

    return () => {
      if (frame !== 0) {
        window.cancelAnimationFrame(frame);
      }
      setSurface(null);
      delete root.dataset.pointerFx;
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('blur', reset);
      document.removeEventListener('pointerleave', reset);
      document.removeEventListener('visibilitychange', syncCapability);
      finePointer.removeEventListener('change', syncCapability);
      reduceMotion.removeEventListener('change', syncCapability);
    };
  }, []);
}
