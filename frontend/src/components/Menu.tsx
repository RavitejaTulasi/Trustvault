import { useEffect, useId, useRef, useState } from 'react';
import type { ComponentType, KeyboardEvent, ReactNode, SVGProps } from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'motion/react';
import { ChevronDownIcon } from './Icons';

export interface MenuItem {
  id: string;
  label: string;
  icon?: ComponentType<SVGProps<SVGSVGElement>>;
  to?: string;
  onSelect?: () => void;
  danger?: boolean;
}

interface MenuProps {
  label: string;
  triggerLabel: string;
  trigger: ReactNode;
  items: MenuItem[];
  className?: string;
}

export default function Menu({
  label,
  triggerLabel,
  trigger,
  items,
  className = '',
}: MenuProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const menuId = useId();
  const reduceMotion = useReducedMotion();

  useEffect(() => {
    if (!open) {
      return;
    }
    menuRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();

    const onPointerDown = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('pointerdown', onPointerDown);
    return () => document.removeEventListener('pointerdown', onPointerDown);
  }, [open]);

  const closeAndFocusTrigger = () => {
    setOpen(false);
    triggerRef.current?.focus();
  };

  const onMenuKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeAndFocusTrigger();
      return;
    }
    if (event.key === 'Tab') {
      setOpen(false);
      return;
    }
    const focusable = Array.from(
      menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [],
    );
    if (focusable.length === 0) {
      return;
    }
    const currentIndex = focusable.findIndex((item) => item === document.activeElement);
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      focusable[(currentIndex + 1) % focusable.length]?.focus();
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      focusable[(currentIndex - 1 + focusable.length) % focusable.length]?.focus();
    } else if (event.key === 'Home') {
      event.preventDefault();
      focusable[0]?.focus();
    } else if (event.key === 'End') {
      event.preventDefault();
      focusable[focusable.length - 1]?.focus();
    }
  };

  return (
    <div className={`menu${className ? ` ${className}` : ''}`} ref={rootRef}>
      <button
        ref={triggerRef}
        type="button"
        className="menu-trigger"
        aria-label={triggerLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((value) => !value)}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown') {
            event.preventDefault();
            setOpen(true);
          }
        }}
      >
        {trigger}
        <ChevronDownIcon className="menu-chevron" width={14} height={14} />
      </button>

      {open && (
        <motion.div
          id={menuId}
          ref={menuRef}
          className="menu-panel"
          role="menu"
          aria-label={label}
          initial={reduceMotion ? false : { opacity: 0, y: -6, scale: 0.985 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
          onKeyDown={onMenuKeyDown}
        >
          {items.map((item) => {
            const Icon = item.icon;
            const content = (
              <>
                {Icon && <Icon />}
                <span>{item.label}</span>
              </>
            );
            const itemClass = `menu-item${item.danger ? ' menu-item-danger' : ''}`;

            return item.to ? (
              <Link
                key={item.id}
                to={item.to}
                role="menuitem"
                className={itemClass}
                onClick={() => setOpen(false)}
              >
                {content}
              </Link>
            ) : (
              <button
                key={item.id}
                type="button"
                role="menuitem"
                className={itemClass}
                onClick={() => {
                  setOpen(false);
                  item.onSelect?.();
                }}
              >
                {content}
              </button>
            );
          })}
        </motion.div>
      )}
    </div>
  );
}
