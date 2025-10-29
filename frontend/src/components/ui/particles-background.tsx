import React, { useLayoutEffect, useRef } from 'react';

declare global {
  interface Window {
    particlesJS: any;
  }
}

interface ParticlesBackgroundProps {
  colors?: string[];
  size?: number;
  countDesktop?: number;
  countTablet?: number;
  countMobile?: number;
  zIndex?: number;
  height?: string;
}

const ParticlesBackground: React.FC<ParticlesBackgroundProps> = ({
  colors = ['#ffffff'],
  size = 1,
  countDesktop = 60,
  countTablet = 50,
  countMobile = 40,
  zIndex = 0,
  height = '100vh',
}) => {
  const initializedRef = useRef(false);

  useLayoutEffect(() => {
    if (initializedRef.current) return;
    
    const script = document.createElement('script');
    script.src = "https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js";
    script.onload = () => {
      const particlesElement = document.getElementById('js-particles');
      if (particlesElement && window.particlesJS && !initializedRef.current) {
        const getParticleCount = () => {
          const screenWidth = window.innerWidth;
          if (screenWidth > 1024) return countDesktop;
          if (screenWidth > 768) return countTablet;
          return countMobile;
        };

        window.particlesJS('js-particles', {
          particles: {
            number: {
              value: getParticleCount(),
              density: {
                enable: false
              }
            },
            color: {
              value: colors,
            },
            shape: {
              type: 'circle',
            },
            opacity: {
              value: 1,
              random: false,
              anim: {
                enable: false
              }
            },
            size: {
              value: size,
              random: true,
              anim: {
                enable: false
              }
            },
            line_linked: {
              enable: false,
            },
            move: {
              enable: false,
              speed: 0,
              direction: 'none',
              random: false,
              straight: false,
              out_mode: 'out',
              bounce: false,
              attract: {
                enable: false
              }
            },
          },
          interactivity: {
            detect_on: 'canvas',
            events: {
              onhover: {
                enable: false,
              },
              onclick: {
                enable: false,
              },
              resize: false,
            },
          },
          retina_detect: true,
        });
        
        initializedRef.current = true;
        
        // Force canvas to be static
        const canvas = particlesElement.querySelector('canvas');
        if (canvas) {
          canvas.style.position = 'absolute';
          canvas.style.pointerEvents = 'none';
          canvas.style.willChange = 'auto';
        }
      }
    };
    document.body.appendChild(script);

    return () => {
      if (document.body.contains(script)) {
        document.body.removeChild(script);
      }
    };
  }, []);

  return (
    <div
      id="js-particles"
      style={{
        width: '100%',
        height: height,
        position: 'absolute',
        top: 0,
        left: 0,
        zIndex: zIndex,
        pointerEvents: 'none',
        willChange: 'auto',
      }}
    >
      <style>{`
        #js-particles canvas {
          position: absolute !important;
          width: 100%;
          height: 100%;
          pointer-events: none !important;
          will-change: auto !important;
        }

        .particles-js-canvas-el {
          position: absolute !important;
          pointer-events: none !important;
        }

        .particles-js-canvas-el circle {
          fill: currentColor;
          filter: url(#glow);
        }
      `}</style>
      <svg xmlns="http://www.w3.org/2000/svg" version="1.1">
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3.5" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>
      </svg>
    </div>
  );
};

export default ParticlesBackground;