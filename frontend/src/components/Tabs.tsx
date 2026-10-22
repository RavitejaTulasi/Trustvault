import { useId } from 'react';
import type { KeyboardEvent } from 'react';
import { motion, useReducedMotion } from 'motion/react';

export interface TabItem {
  id: string;
  label: string;
  disabled?: boolean;
}

interface TabsProps {
  label: string;
  tabs: TabItem[];
  value: string;
  onChange: (id: string) => void;
}

export default function Tabs({ label, tabs, value, onChange }: TabsProps) {
  const baseId = useId();
  const reduceMotion = useReducedMotion();

  const handleKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const keys = ['ArrowRight', 'ArrowLeft', 'Home', 'End'];
    if (!keys.includes(event.key)) {
      return;
    }
    event.preventDefault();
    const buttons = Array.from(
      event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>(
        '[role="tab"]:not(:disabled)',
      ) ?? [],
    );
    if (buttons.length === 0) {
      return;
    }
    const index = buttons.findIndex((button) => button === document.activeElement);
    let nextIndex = index;
    if (event.key === 'ArrowRight') {
      nextIndex = (index + 1) % buttons.length;
    } else if (event.key === 'ArrowLeft') {
      nextIndex = (index - 1 + buttons.length) % buttons.length;
    } else if (event.key === 'Home') {
      nextIndex = 0;
    } else if (event.key === 'End') {
      nextIndex = buttons.length - 1;
    }
    const next = buttons[nextIndex];
    if (next) {
      next.focus();
      onChange(next.dataset.tabId ?? '');
    }
  };

  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          id={`${baseId}-${tab.id}`}
          type="button"
          role="tab"
          className="tab"
          data-tab-id={tab.id}
          aria-selected={value === tab.id}
          tabIndex={value === tab.id ? 0 : -1}
          disabled={tab.disabled}
          onClick={() => onChange(tab.id)}
          onKeyDown={handleKeyDown}
        >
          <span className="tab-label">{tab.label}</span>
          {value === tab.id && (
            <motion.span
              layoutId={`${baseId}-tab-indicator`}
              className="tab-indicator"
              initial={reduceMotion ? false : { opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ type: 'spring', stiffness: 460, damping: 38 }}
              aria-hidden="true"
            />
          )}
        </button>
      ))}
    </div>
  );
}
