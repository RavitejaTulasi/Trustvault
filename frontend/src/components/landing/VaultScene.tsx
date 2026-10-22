import { useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import {
  Edges,
  Environment,
  Float,
  Lightformer,
  RoundedBox,
  Sparkles,
} from '@react-three/drei';
import { MathUtils, type Group } from 'three';

interface VaultSceneProps {
  active: boolean;
  onReady: () => void;
  className?: string;
  cameraPosition?: [number, number, number];
  cameraFov?: number;
  vaultScale?: number;
}

const MINT = '#8df5c8';
const MINT_DEEP = '#3fcb98';
const VIOLET = '#8794f2';

function OrbitNodes() {
  const orbit = useRef<Group>(null);

  useFrame((_, delta) => {
    if (orbit.current) {
      orbit.current.rotation.z -= Math.min(delta, 0.05) * 0.16;
    }
  });

  return (
    <group ref={orbit}>
      {[0, 1, 2].map((index) => {
        const angle = (index / 3) * Math.PI * 2;
        return (
          <mesh
            key={index}
            position={[Math.cos(angle) * 1.72, Math.sin(angle) * 1.72, 0.16]}
          >
            <sphereGeometry args={[index === 0 ? 0.045 : 0.032, 16, 16]} />
            <meshBasicMaterial color={index === 1 ? VIOLET : MINT} toneMapped={false} />
          </mesh>
        );
      })}
      <mesh rotation={[0, 0, 0]}>
        <torusGeometry args={[1.72, 0.0035, 6, 160]} />
        <meshBasicMaterial color={MINT} transparent opacity={0.22} toneMapped={false} />
      </mesh>
    </group>
  );
}

function VaultBody({ vaultScale = 1 }: { vaultScale?: number }) {
  const pointerGroup = useRef<Group>(null);
  const outerRings = useRef<Group>(null);
  const innerRings = useRef<Group>(null);
  const core = useRef<Group>(null);
  const lastPointer = useRef({ x: 0, y: 0 });

  useFrame((state, delta) => {
    const step = Math.min(delta, 0.05);

    if (outerRings.current) {
      outerRings.current.rotation.z += step * 0.075;
    }
    if (innerRings.current) {
      innerRings.current.rotation.z -= step * 0.11;
    }
    if (core.current) {
      core.current.rotation.z = Math.sin(state.clock.elapsedTime * 0.45) * 0.18;
    }
    if (pointerGroup.current) {
      const vx = (state.pointer.x - lastPointer.current.x) / step;
      const vy = (state.pointer.y - lastPointer.current.y) / step;
      lastPointer.current = { x: state.pointer.x, y: state.pointer.y };

      const speed = Math.min(Math.sqrt(vx * vx + vy * vy), 14) * 0.028;
      const targetY = state.pointer.x * (0.32 + speed);
      const targetX = -state.pointer.y * (0.24 + speed);

      pointerGroup.current.rotation.y = MathUtils.damp(
        pointerGroup.current.rotation.y,
        targetY,
        3.5,
        step,
      );
      pointerGroup.current.rotation.x = MathUtils.damp(
        pointerGroup.current.rotation.x,
        targetX,
        3.5,
        step,
      );
    }
  });

  return (
    <group ref={pointerGroup} scale={[vaultScale, vaultScale, vaultScale]}>
      <mesh position={[0, 0, -1.5]}>
        <circleGeometry args={[2.32, 72]} />
        <meshBasicMaterial color="#06100b" transparent opacity={0.72} />
      </mesh>

      <Float speed={1.1} rotationIntensity={0.12} floatIntensity={0.22}>
        <group rotation={[0.04, -0.16, 0]}>
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <cylinderGeometry args={[1.34, 1.4, 0.34, 96, 1, false]} />
            <meshPhysicalMaterial
              color="#12271c"
              metalness={0.9}
              roughness={0.24}
              clearcoat={1}
              clearcoatRoughness={0.18}
              envMapIntensity={0.7}
            />
            <Edges color={MINT} threshold={28} />
          </mesh>

          {/* Heavy perimeter locking lugs / bolt extensions */}
          <group rotation={[0, 0, 0]}>
            {Array.from({ length: 12 }, (_, index) => {
              const angle = (index / 12) * Math.PI * 2;
              return (
                <mesh
                  key={index}
                  position={[Math.cos(angle) * 1.38, Math.sin(angle) * 1.38, 0]}
                  rotation={[0, 0, angle]}
                >
                  <boxGeometry args={[0.14, 0.08, 0.18]} />
                  <meshStandardMaterial
                    color="#173a2c"
                    metalness={0.85}
                    roughness={0.3}
                    emissive={MINT_DEEP}
                    emissiveIntensity={0.25}
                  />
                </mesh>
              );
            })}
          </group>

          <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 0, 0.1]}>
            <cylinderGeometry args={[1.13, 1.18, 0.11, 96, 1, false]} />
            <meshPhysicalMaterial
              color="#1a3a2b"
              metalness={0.68}
              roughness={0.3}
              clearcoat={0.8}
              emissive="#1d5a41"
              emissiveIntensity={0.38}
              envMapIntensity={0.6}
            />
            <Edges color={MINT} threshold={24} />
          </mesh>

          <group ref={outerRings}>
            <mesh>
              <torusGeometry args={[1.54, 0.012, 10, 160]} />
              <meshBasicMaterial color={MINT} transparent opacity={0.42} toneMapped={false} />
            </mesh>
            <mesh rotation={[0, 0, Math.PI / 3]}>
              <torusGeometry args={[1.48, 0.004, 8, 160]} />
              <meshBasicMaterial color={MINT} transparent opacity={0.16} toneMapped={false} />
            </mesh>
          </group>

          <group ref={innerRings} position={[0, 0, 0.18]}>
            <mesh>
              <torusGeometry args={[0.86, 0.008, 8, 128]} />
              <meshBasicMaterial color={MINT_DEEP} transparent opacity={0.55} toneMapped={false} />
            </mesh>
            <mesh rotation={[0, 0, Math.PI / 4]}>
              <torusGeometry args={[0.72, 0.004, 8, 128]} />
              <meshBasicMaterial color={MINT} transparent opacity={0.24} toneMapped={false} />
            </mesh>
          </group>

          <group position={[0, 0, 0.2]}>
            {Array.from({ length: 8 }, (_, index) => (
              <mesh
                key={index}
                position={[
                  Math.cos((index / 8) * Math.PI * 2) * 0.5,
                  Math.sin((index / 8) * Math.PI * 2) * 0.5,
                  0,
                ]}
                rotation={[0, 0, (index / 8) * Math.PI * 2]}
              >
                <boxGeometry args={[0.62, 0.016, 0.028]} />
                <meshStandardMaterial
                  color={index % 2 === 0 ? MINT_DEEP : '#173a2c'}
                  metalness={0.55}
                  roughness={0.4}
                  emissive={MINT_DEEP}
                  emissiveIntensity={index % 2 === 0 ? 0.65 : 0.08}
                />
              </mesh>
            ))}
          </group>

          <group ref={core} position={[0, 0, 0.42]}>
            <mesh rotation={[Math.PI / 2, 0, 0]}>
              <cylinderGeometry args={[0.32, 0.32, 0.11, 48]} />
              <meshPhysicalMaterial
                color="#0a2017"
                metalness={0.88}
                roughness={0.22}
                clearcoat={1}
              />
              <Edges color={MINT} threshold={20} />
            </mesh>
            <group position={[0, -0.01, 0.13]}>
              <RoundedBox args={[0.25, 0.2, 0.09]} radius={0.026} smoothness={4}>
                <meshStandardMaterial
                  color={MINT}
                  emissive={MINT}
                  emissiveIntensity={1.35}
                  metalness={0.35}
                  roughness={0.24}
                  toneMapped={false}
                />
              </RoundedBox>
              <mesh position={[0, 0.11, 0]}>
                <torusGeometry args={[0.085, 0.021, 12, 32, Math.PI]} />
                <meshStandardMaterial
                  color={MINT}
                  emissive={MINT}
                  emissiveIntensity={1.15}
                  metalness={0.3}
                  roughness={0.25}
                  toneMapped={false}
                />
              </mesh>
              <mesh position={[0, -0.015, 0.052]} rotation={[Math.PI / 2, 0, 0]}>
                <cylinderGeometry args={[0.027, 0.027, 0.03, 20]} />
                <meshBasicMaterial color="#05120c" />
              </mesh>
            </group>
            <mesh>
              <torusGeometry args={[0.25, 0.006, 8, 64]} />
              <meshBasicMaterial color={MINT} transparent opacity={0.48} toneMapped={false} />
            </mesh>
          </group>

          <mesh position={[0, 0, 0.11]}>
            <ringGeometry args={[1.22, 1.235, 128]} />
            <meshBasicMaterial color={MINT} transparent opacity={0.28} toneMapped={false} />
          </mesh>
        </group>
      </Float>

      <OrbitNodes />

      <Sparkles
        count={34}
        scale={[4.7, 4.7, 1.5]}
        size={1.7}
        speed={0.22}
        opacity={0.44}
        color={MINT}
        noise={0.45}
      />
    </group>
  );
}

export default function VaultScene({
  active,
  onReady,
  className = 'lp-scene',
  cameraPosition = [0, 0, 6.7],
  cameraFov = 38,
  vaultScale = 1,
}: VaultSceneProps) {
  return (
    <div className={className} aria-hidden="true">
      <Canvas
        camera={{ position: cameraPosition, fov: cameraFov, near: 0.1, far: 30 }}
        dpr={[1, 1.5]}
        frameloop={active ? 'always' : 'never'}
        gl={{
          antialias: true,
          alpha: true,
          powerPreference: 'high-performance',
          stencil: false,
          depth: true,
        }}
        onCreated={onReady}
        fallback={null}
      >
        <Environment resolution={64} frames={1}>
          <Lightformer intensity={2.4} position={[0, 4, -6]} scale={[8, 8, 1]} color="#c9ffe9" />
          <Lightformer intensity={1.5} position={[-4, 0, 2]} scale={[3, 6, 1]} color="#5fffc2" />
          <Lightformer intensity={0.9} position={[4, 1, 2]} scale={[3, 4, 1]} color={VIOLET} />
        </Environment>
        <ambientLight intensity={0.7} />
        <directionalLight position={[-3.5, 4.2, 5]} intensity={2.7} color="#e5fff5" />
        <directionalLight position={[4, -2.5, 2]} intensity={1.3} color={VIOLET} />
        <pointLight position={[2.4, 1.2, 3.4]} intensity={16} distance={9} color={MINT} />
        <pointLight position={[-2.2, -1.6, 2.4]} intensity={7} distance={8} color={MINT_DEEP} />
        <VaultBody vaultScale={vaultScale} />
      </Canvas>
    </div>
  );
}
