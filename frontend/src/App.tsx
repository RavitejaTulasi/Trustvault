import Root from './router';
import { MotionConfig } from 'motion/react';
import GlobalPointerFX from './components/motion/GlobalPointerFX';
import { ToastProvider } from './components/Toast';

export default function App() {
  return (
    <MotionConfig reducedMotion="user">
      <GlobalPointerFX />
      <ToastProvider>
        <Root />
      </ToastProvider>
    </MotionConfig>
  );
}
