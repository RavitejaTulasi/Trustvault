import { useEffect, useRef } from 'react';

interface PointerMotionOptions {
  tilt?: number;
  shift?: number;
}

export function usePointerMotion<T extends HTMLElement>({
  tilt = 2.4,
  shift = 3,
}: PointerMotionOptions = {}) {
  const ref = useRef<T>(null);

  useEffect(() => {
    const node = ref.current;
    if (!node || typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
      return;
    }

    const finePointer = window.matchMedia('(pointer: fine)');
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (!finePointer.matches || reduceMotion.matches) {
      return;
    }

    let frame = 0;
    let x = 0.5;
    let y = 0.5;

    const paint = () => {
      frame = 0;
      node.style.setProperty('--pm-x', `${(x * 100).toFixed(2)}%`);
      node.style.setProperty('--pm-y', `${(y * 100).toFixed(2)}%`);
      node.style.setProperty('--pm-tilt-x', `${((0.5 - y) * tilt).toFixed(2)}deg`);
      node.style.setProperty('--pm-tilt-y', `${((x - 0.5) * tilt).toFixed(2)}deg`);
      node.style.setProperty('--pm-shift-x', `${((x - 0.5) * shift).toFixed(2)}px`);
      node.style.setProperty('--pm-shift-y', `${((y - 0.5) * shift).toFixed(2)}px`);
    };

    const onPointerMove = (event: PointerEvent) => {
      if (event.pointerType === 'touch') {
        return;
      }
      const rect = node.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) {
        return;
      }
      x = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
      y = Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height));
      node.dataset.pointer = 'active';
      if (frame === 0) {
        frame = window.requestAnimationFrame(paint);
      }
    };

    const reset = () => {
      if (frame !== 0) {
        window.cancelAnimationFrame(frame);
        frame = 0;
      }
      x = 0.5;
      y = 0.5;
      delete node.dataset.pointer;
      paint();
    };

    const onCapabilityChange = () => {
      if (!finePointer.matches || reduceMotion.matches) {
        reset();
      }
    };

    node.addEventListener('pointermove', onPointerMove);
    node.addEventListener('pointerleave', reset);
    node.addEventListener('pointercancel', reset);
    node.addEventListener('blur', reset);
    finePointer.addEventListener('change', onCapabilityChange);
    reduceMotion.addEventListener('change', onCapabilityChange);

    return () => {
      if (frame !== 0) {
        window.cancelAnimationFrame(frame);
      }
      node.removeEventListener('pointermove', onPointerMove);
      node.removeEventListener('pointerleave', reset);
      node.removeEventListener('pointercancel', reset);
      node.removeEventListener('blur', reset);
      finePointer.removeEventListener('change', onCapabilityChange);
      reduceMotion.removeEventListener('change', onCapabilityChange);
    };
  }, [shift, tilt]);

  return ref;
}
