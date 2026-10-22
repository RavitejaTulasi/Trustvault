import { useNavigate } from 'react-router-dom';
import { ChevronLeftIcon } from './Icons';

interface BackButtonProps {
  fallback: string;
  label?: string;
}

export default function BackButton({ fallback, label = 'Back' }: BackButtonProps) {
  const navigate = useNavigate();

  const handleBack = () => {
    const historyState = window.history.state as { idx?: number } | null;
    if (typeof historyState?.idx === 'number' && historyState.idx > 0) {
      navigate(-1);
      return;
    }
    navigate(fallback);
  };

  return (
    <button type="button" className="back-button" onClick={handleBack}>
      <ChevronLeftIcon width={15} height={15} />
      {label}
    </button>
  );
}
