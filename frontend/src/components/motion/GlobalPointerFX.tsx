import { useGlobalPointer } from '../../hooks/useGlobalPointer';

export default function GlobalPointerFX() {
  useGlobalPointer();
  return (
    <div className="global-pointer-fx" aria-hidden="true">
      <span className="global-pointer-core" />
    </div>
  );
}
