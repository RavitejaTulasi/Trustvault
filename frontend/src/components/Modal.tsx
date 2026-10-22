import type { ReactNode } from 'react';
import Dialog from './Dialog';

interface ModalProps {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
}

export default function Modal({ title, description, onClose, children }: ModalProps) {
  return (
    <Dialog label={title} description={description} onClose={onClose}>
      {children}
    </Dialog>
  );
}
