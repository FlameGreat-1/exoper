"use client";
import React, { useEffect, useRef, useState } from "react";
import createGlobe from "cobe";
import { cn } from "../../lib/utils/utils";

/**
 * Convert #RGB or #RRGGBB into normalized [r,g,b] where each component is 0..1.
 */
const hexToRgbNormalized = (hex: string): [number, number, number] => {
  if (!hex) return [0, 0, 0];
  const cleanHex = hex.startsWith("#") ? hex.slice(1) : hex;
  let r = 0,
    g = 0,
    b = 0;
  if (cleanHex.length === 3) {
    r = parseInt(cleanHex[0] + cleanHex[0], 16);
    g = parseInt(cleanHex[1] + cleanHex[1], 16);
    b = parseInt(cleanHex[2] + cleanHex[2], 16);
  } else if (cleanHex.length === 6) {
    r = parseInt(cleanHex.substring(0, 2), 16);
    g = parseInt(cleanHex.substring(2, 4), 16);
    b = parseInt(cleanHex.substring(4, 6), 16);
  } else {
    console.warn(`Invalid hex color: ${hex}. Falling back to black.`);
    return [0, 0, 0];
  }
  return [r / 255, g / 255, b / 255];
};

interface GlobeProps {
  className?: string;
  theta?: number;
  dark?: number;
  scale?: number;
  diffuse?: number;
  mapSamples?: number;
  mapBrightness?: number;
  baseColor?: [number, number, number] | string;
  markerColor?: [number, number, number] | string;
  glowColor?: [number, number, number] | string;
}

const DEFAULT_MAP_SAMPLES = 20000; // safe default; will be reduced on low-power devices
const MAX_DPR = 2; // cap devicePixelRatio to avoid huge texture allocations

const Globe: React.FC<GlobeProps> = ({
  className,
  theta = 0.25,
  dark = 1,
  scale = 1.1,
  diffuse = 1.2,
  mapSamples = DEFAULT_MAP_SAMPLES,
  mapBrightness = 6,
  baseColor = "#8b5cf6",
  markerColor = "#ec4899",
  glowColor = "#a855f7",
}) => {
  const wrapperRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const globeRef = useRef<any>(null);

  // interaction refs
  const phiRef = useRef(0);
  const thetaRef = useRef(theta);
  const isDragging = useRef(false);
  const lastX = useRef(0);
  const lastY = useRef(0);

  // state to show fallback image when WebGL isn't available or fails
  const [webglOk, setWebglOk] = useState<boolean | null>(null);

  // small helper to test WebGL availability
  const detectWebGL = (): boolean => {
    try {
      const testCanvas = document.createElement("canvas");
      // prefer webgl2, fallback to webgl
      const gl =
        (testCanvas.getContext("webgl2") as WebGL2RenderingContext) ||
        (testCanvas.getContext("webgl") as WebGLRenderingContext) ||
        (testCanvas.getContext("experimental-webgl") as WebGLRenderingContext);
      return !!gl;
    } catch (e) {
      return false;
    }
  };

  useEffect(() => {
    setWebglOk(detectWebGL());
  }, []);

  useEffect(() => {
    if (webglOk === false) return; // don't attempt to create globe if not supported

    const canvas = canvasRef.current;
    const wrapper = wrapperRef.current;
    if (!canvas || !wrapper) return;

    // compute effective DPR and mapSamples (reduce if low-power device)
    const rawDPR = window.devicePixelRatio || 1;
    const dpr = Math.min(rawDPR, MAX_DPR);

    // adapt mapSamples to device: reduce on low-powered CPUs / small screens
    const concurrency = (navigator as any).hardwareConcurrency || 4;
    let effectiveMapSamples = mapSamples;
    if (concurrency < 4) effectiveMapSamples = Math.min(effectiveMapSamples, 20000);
    if (window.innerWidth < 480) effectiveMapSamples = Math.min(effectiveMapSamples, 15000);
    effectiveMapSamples = Math.max(2000, effectiveMapSamples); // ensure a minimum

    // helper: initialize or re-init globe with size from wrapper
    let rafResize = 0;
    const initGlobe = () => {
      const rect = wrapper.getBoundingClientRect();
      // size we want to fit into (square)
      const size = Math.max(64, Math.min(rect.width, rect.height || rect.width));
      const internalW = Math.max(64, Math.floor(size * dpr));
      const internalH = internalW;

      // set CSS size to be 100% & rely on parent wrapper for layout, but set internal pixel buffer
      canvas.style.width = "100%";
      canvas.style.height = "100%";
      canvas.width = internalW;
      canvas.height = internalH;

      // destroy previous instance if any
      if (globeRef.current) {
        try {
          globeRef.current.destroy();
        } catch (err) {
          // no-op
        }
        globeRef.current = null;
      }

      // resolve colors to numeric arrays
      const resolvedBase =
        typeof baseColor === "string" ? hexToRgbNormalized(baseColor) : baseColor || [0.45, 0.35, 1];
      const resolvedMarker =
        typeof markerColor === "string" ? hexToRgbNormalized(markerColor) : markerColor || [1, 0, 0];
      const resolvedGlow =
        typeof glowColor === "string" ? hexToRgbNormalized(glowColor) : glowColor || [0.27, 0.58, 0.90];

      try {
        globeRef.current = createGlobe(canvas, {
          devicePixelRatio: dpr,
          width: internalW,
          height: internalH,
          phi: phiRef.current,
          theta: thetaRef.current,
          dark,
          scale,
          diffuse,
          mapSamples: effectiveMapSamples,
          mapBrightness,
          baseColor: resolvedBase,
          markerColor: resolvedMarker,
          glowColor: resolvedGlow,
          opacity: 1,
          offset: [0, 0],
          markers: [],
          onRender: (state: Record<string, any>) => {
            // small auto-rotation when not dragging
            if (!isDragging.current) {
              // scale auto-rotation by delta if available, otherwise use constant
              // createGlobe's state sometimes exposes time/elapsed; fallback to small increment
              phiRef.current += 0.0025;
            }
            state.phi = phiRef.current;
            state.theta = thetaRef.current;
          },
        });
      } catch (err) {
        // if creation fails, show fallback image
        console.error("Failed to initialize globe (createGlobe):", err);
        setWebglOk(false);
      }
    };

    // Resize handling using ResizeObserver for accuracy
    let ro: ResizeObserver | null = null;
    try {
      ro = new ResizeObserver(() => {
        // throttle re-init to the next animation frame to avoid thrash
        if (rafResize) cancelAnimationFrame(rafResize);
        rafResize = requestAnimationFrame(() => {
          initGlobe();
        });
      });
      ro.observe(wrapper);
    } catch (e) {
      // fallback: window resize
      const onResize = () => {
        if (rafResize) cancelAnimationFrame(rafResize);
        rafResize = requestAnimationFrame(() => {
          initGlobe();
        });
      };
      window.addEventListener("resize", onResize);
      // cleanup will remove it
    }

    // pointer events (works for mouse + touch + stylus)
    const onPointerDown = (ev: PointerEvent) => {
      isDragging.current = true;
      lastX.current = ev.clientX;
      lastY.current = ev.clientY;
      try {
        (ev.target as Element).setPointerCapture?.(ev.pointerId);
      } catch (err) {
        // ignore
      }
      // optionally change cursor visually
      canvas.style.cursor = "grabbing";
    };

    const onPointerMove = (ev: PointerEvent) => {
      if (!isDragging.current) return;
      // prevent page scroll when dragging inside the canvas
      ev.preventDefault?.();
      const deltaX = ev.clientX - lastX.current;
      const deltaY = ev.clientY - lastY.current;
      const rotationSpeed = 0.005; // tune sensitivity
      phiRef.current += deltaX * rotationSpeed;
      thetaRef.current = Math.max(
        -Math.PI / 2,
        Math.min(Math.PI / 2, thetaRef.current - deltaY * rotationSpeed)
      );
      lastX.current = ev.clientX;
      lastY.current = ev.clientY;
    };

    const onPointerUp = (ev: PointerEvent) => {
      isDragging.current = false;
      try {
        (ev.target as Element).releasePointerCapture?.(ev.pointerId);
      } catch (err) {
        // ignore
      }
      canvas.style.cursor = "grab";
    };

    // attach pointer listeners to canvas (pointer capture ensures move events will be delivered to canvas)
    canvas.addEventListener("pointerdown", onPointerDown, { passive: false });
    // listen on window so we still get pointermove/up if pointer leaves canvas (defensive)
    window.addEventListener("pointermove", onPointerMove, { passive: false });
    window.addEventListener("pointerup", onPointerUp, { passive: false });
    window.addEventListener("pointercancel", onPointerUp, { passive: false });

    // Ensure touch-driven browsers do not treat the canvas as scrollable while interacting
    canvas.style.touchAction = "none";
    // default cursor
    canvas.style.cursor = "grab";
    // initial init
    initGlobe();

    // cleanup on unmount
    return () => {
      if (ro) {
        try {
          ro.disconnect();
        } catch (err) {}
      } else {
        window.removeEventListener("resize", initGlobe);
      }
      cancelAnimationFrame(rafResize);
      canvas.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("pointermove", onPointerMove);
      window.removeEventListener("pointerup", onPointerUp);
      window.removeEventListener("pointercancel", onPointerUp);
      if (globeRef.current) {
        try {
          globeRef.current.destroy();
        } catch (err) {}
        globeRef.current = null;
      }
    };
  }, [
    theta,
    dark,
    scale,
    diffuse,
    mapSamples,
    mapBrightness,
    baseColor,
    markerColor,
    glowColor,
    webglOk, // re-run initialization when detection completes/changes
  ]);

  // If we determined WebGL is unsupported or creation failed, show fallback (static svg/png).
  // Place your fallback asset in public/images/globe-fallback.png (or change path)
  if (webglOk === false) {
    return (
      <div
        ref={wrapperRef}
        className={cn("relative flex items-center justify-center overflow-hidden", className)}
        style={{
          // parent should size this; default fallback sizing for safety:
          width: "100%",
          height: "100%",
          minWidth: 120,
          minHeight: 120,
        }}
      >
        <img
          src="/images/globe-fallback.png"
          alt="Globe (fallback)"
          style={{
            width: "100%",
            height: "100%",
            objectFit: "contain",
            display: "block",
            pointerEvents: "none",
          }}
        />
      </div>
    );
  }

  // normal render: canvas fills the parent wrapper; parent should provide aspect-square / sizing
  return (
    <div
      ref={wrapperRef}
      className={cn("relative flex items-center justify-center overflow-hidden", className)}
      style={{
        width: "100%",
        height: "100%",
      }}
    >
      <canvas
        ref={canvasRef}
        aria-hidden
        role="img"
        style={{
          width: "100%",
          height: "100%",
          display: "block",
          aspectRatio: "1 / 1",
        }}
      />
    </div>
  );
};

export default Globe;
