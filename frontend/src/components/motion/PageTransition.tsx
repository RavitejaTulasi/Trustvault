import type { ReactNode } from 'react';
import { motion, useReducedMotion } from 'motion/react';
import { EASE_OUT } from '../../lib/motion';

interface PageTransitionProps {
  children: ReactNode;
  className?: string;
}

export default function PageTransition({ children, className = '' }: PageTransitionProps) {
  const reduceMotion = useReducedMotion();

  return (
    <motion.div
      className={`page-transition${className ? ` ${className}` : ''}`}
      initial={reduceMotion ? false : { opacity: 0, y: 12 }}
      animate={reduceMotion ? undefined : { opacity: 1, y: 0 }}
      transition={{ duration: 0.36, ease: EASE_OUT }}
    >
      {children}
    </motion.div>
  );
}
