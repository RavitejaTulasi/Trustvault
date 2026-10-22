import { forwardRef } from 'react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { usePointerMotion } from '../../hooks/usePointerMotion';

interface MagneticButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  children: ReactNode;
  strength?: number;
}

const MagneticButton = forwardRef<HTMLButtonElement, MagneticButtonProps>(
  function MagneticButton(
    { children, className = '', strength = 6, type = 'button', ...rest },
    forwardedRef,
  ) {
    const ref = usePointerMotion<HTMLButtonElement>({ tilt: 0, shift: strength });

    return (
      <button
        {...rest}
        ref={(node) => {
          ref.current = node;
          if (typeof forwardedRef === 'function') {
            forwardedRef(node);
          } else if (forwardedRef) {
            forwardedRef.current = node;
          }
        }}
        type={type}
        className={`magnetic-button${className ? ` ${className}` : ''}`}
        data-pointer-surface
      >
        {children}
      </button>
    );
  },
);

export default MagneticButton;
