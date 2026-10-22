import { useEffect } from 'react';
import type { RefObject } from 'react';

export function useLandingGsap(scope: RefObject<HTMLElement | null>, enabled: boolean) {
  useEffect(() => {
    const root = scope.current;
    if (!enabled || !root) {
      return;
    }

    let cancelled = false;
    let cleanup: (() => void) | undefined;

    void (async () => {
      try {
        const [{ gsap }, { ScrollTrigger }] = await Promise.all([
          import('gsap'),
          import('gsap/ScrollTrigger'),
        ]);
        if (cancelled) {
          return;
        }

        gsap.registerPlugin(ScrollTrigger);

        const context = gsap.context(() => {
          const media = gsap.matchMedia();

          media.add('(prefers-reduced-motion: no-preference)', () => {
            gsap.fromTo(
              '.lp-artifact-parallax',
              { y: 0 },
              {
                y: -44,
                ease: 'none',
                scrollTrigger: {
                  trigger: '.lp-hero',
                  start: 'top top',
                  end: 'bottom top',
                  scrub: 0.6,
                },
              },
            );

            gsap.fromTo(
              '.lp-audit-scan',
              { top: '9%', opacity: 0 },
              {
                top: '88%',
                opacity: 0.9,
                ease: 'none',
                scrollTrigger: {
                  trigger: '.lp-chain-console',
                  start: 'top 78%',
                  end: 'bottom 48%',
                  scrub: 0.7,
                },
              },
            );

            gsap.fromTo(
              '.lp-cta-grid',
              { backgroundPositionY: '0px' },
              {
                backgroundPositionY: '180px',
                ease: 'none',
                scrollTrigger: {
                  trigger: '.lp-cta',
                  start: 'top bottom',
                  end: 'bottom top',
                  scrub: 0.8,
                },
              },
            );
          });

          return () => media.revert();
        }, root);

        cleanup = () => context.revert();

        void document.fonts?.ready.then(() => {
          if (!cancelled) {
            ScrollTrigger.refresh();
          }
        });
      } catch {
        cleanup = undefined;
      }
    })();

    return () => {
      cancelled = true;
      cleanup?.();
    };
  }, [enabled, scope]);
}
