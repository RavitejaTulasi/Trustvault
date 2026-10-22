import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { motion, useReducedMotion } from 'motion/react';
import { AlertIcon, CheckIcon, CloseIcon, InfoIcon } from './Icons';
import { ToastContext } from './useToast';
import type { ToastInput, ToastTone } from './useToast';

interface ToastRecord extends ToastInput {
  id: number;
  tone: ToastTone;
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastRecord[]>([]);
  const timersRef = useRef(new Map<number, ReturnType<typeof setTimeout>>());
  const nextIdRef = useRef(1);
  const reduceMotion = useReducedMotion();

  const dismissToast = useCallback((id: number) => {
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const pushToast = useCallback(
    ({ title, description, tone = 'info' }: ToastInput) => {
      const id = nextIdRef.current;
      nextIdRef.current += 1;
      setToasts((current) => [...current.slice(-3), { id, title, description, tone }]);
      const timer = setTimeout(() => {
        timersRef.current.delete(id);
        setToasts((current) => current.filter((toast) => toast.id !== id));
      }, 5200);
      timersRef.current.set(id, timer);
    },
    [],
  );

  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      timers.forEach((timer) => clearTimeout(timer));
      timers.clear();
    };
  }, []);

  return (
    <ToastContext.Provider value={{ pushToast, dismissToast }}>
      {children}
      {createPortal(
        <section
          className="toast-viewport"
          aria-label="Notifications"
          aria-live="polite"
          aria-relevant="additions"
        >
          {toasts.map((toast) => {
            const Icon =
              toast.tone === 'success' ? CheckIcon : toast.tone === 'error' ? AlertIcon : InfoIcon;
            return (
              <motion.div
                key={toast.id}
                layout
                className={`toast toast-${toast.tone}`}
                role={toast.tone === 'error' ? 'alert' : 'status'}
                initial={reduceMotion ? false : { opacity: 0, y: 12, scale: 0.985 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
              >
                <span className="toast-icon" aria-hidden="true">
                  <Icon width={16} height={16} />
                </span>
                <div className="toast-copy">
                  <p className="toast-title">{toast.title}</p>
                  {toast.description && (
                    <p className="toast-description">{toast.description}</p>
                  )}
                </div>
                <button
                  type="button"
                  className="toast-close"
                  aria-label={`Dismiss notification: ${toast.title}`}
                  onClick={() => dismissToast(toast.id)}
                >
                  <CloseIcon />
                </button>
              </motion.div>
            );
          })}
        </section>,
        document.body,
      )}
    </ToastContext.Provider>
  );
}
