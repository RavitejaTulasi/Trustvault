import type { HTMLAttributes, ReactNode } from 'react';
import { usePointerMotion } from '../../hooks/usePointerMotion';
import PointerSpotlight from './PointerSpotlight';

interface InteractiveSurfaceProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  className?: string;
  spotlight?: boolean;
  tilt?: number;
  shift?: number;
}

export default function InteractiveSurface({
  children,
  className = '',
  spotlight = true,
  tilt = 0,
  shift = 0,
  ...rest
}: InteractiveSurfaceProps) {
  const ref = usePointerMotion<HTMLDivElement>({ tilt, shift });
  return (
    <div
      {...rest}
      ref={ref}
      className={`motion-surface${className ? ` ${className}` : ''}`}
      data-pointer-surface
    >
      {children}
      {spotlight && <PointerSpotlight />}
    </div>
  );
}
