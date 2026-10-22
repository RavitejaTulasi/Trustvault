import type { HTMLAttributes, ReactNode } from 'react';
import { usePointerMotion } from '../../hooks/usePointerMotion';
import PointerSpotlight from './PointerSpotlight';

interface PointerTiltCardProps extends HTMLAttributes<HTMLElement> {
  children: ReactNode;
  className?: string;
  spotlight?: boolean;
  tilt?: number;
  shift?: number;
}

export default function PointerTiltCard({
  children,
  className = '',
  spotlight = true,
  tilt = 2.4,
  shift = 4,
  ...rest
}: PointerTiltCardProps) {
  const ref = usePointerMotion<HTMLElement>({ tilt, shift });
  return (
    <article
      {...rest}
      ref={ref}
      className={`motion-surface pointer-tilt-card${className ? ` ${className}` : ''}`}
      data-pointer-surface
    >
      {children}
      {spotlight && <PointerSpotlight />}
    </article>
  );
}
