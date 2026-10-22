import { createContext, useContext } from 'react';

export type ToastTone = 'success' | 'error' | 'info';

export interface ToastInput {
  title: string;
  description?: string;
  tone?: ToastTone;
}

export interface ToastApi {
  pushToast: (toast: ToastInput) => void;
  dismissToast: (id: number) => void;
}

export const ToastContext = createContext<ToastApi | null>(null);

const NOOP_API: ToastApi = {
  pushToast: () => undefined,
  dismissToast: () => undefined,
};

export function useToast(): ToastApi {
  return useContext(ToastContext) ?? NOOP_API;
}
