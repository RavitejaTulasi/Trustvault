import { forwardRef } from 'react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';

interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'aria-label'> {
  label: string;
  children: ReactNode;
}

const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, className = '', type = 'button', children, ...props },
  ref,
) {
  return (
    <button
      {...props}
      ref={ref}
      type={type}
      className={`icon-btn${className ? ` ${className}` : ''}`}
      aria-label={label}
      title={label}
    >
      {children}
    </button>
  );
});

export default IconButton;
