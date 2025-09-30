import React, { useRef, useEffect, useState } from "react";
import {
  motion,
  useScroll,
  useTransform,
  useSpring,
} from "framer-motion";

/**
 * PROJECTS.JSX
 * ---------------------------------------------------------------------------
 * A single-file React + Tailwind component that reproduces a dark landing
 * section with animated pipe/wire SVGs, flow diagram cards, and rockets that
 * travel along the wires in response to the page scroll. This file is
 * intentionally self-contained and uses only inline SVGs and CSS classes
 * (Tailwind) for styling. It uses Framer Motion for smooth motion and
 * useScroll for scroll progress.
 *
 * HOW TO USE
 * - Place this file in your React (Vite) project (e.g. src/components/Projects.jsx)
 * - Ensure Tailwind CSS is configured and Framer Motion is installed.
 * - Import and render <Projects /> on a page. Header is intentionally excluded
 *   as requested by the user.
 *
 * NOTES ON ACCURACY
 * - The layout, colors, glow, and animations are designed to closely match
 *   the provided screenshots. Exact pixel-perfect replication can require
 *   tuning of spacing values and SVG curve control points; adjust if needed.
 */

// Utility: simple clamp
const clamp = (v, a = 0, b = 1) => Math.max(a, Math.min(b, v));

export default function Projects() {
  const containerRef = useRef(null);

  // Global scroll progress for the container (0..1)
  const { scrollYProgress } = useScroll({ target: containerRef, offset: ["start end", "end start"] });
  const smoothProgress = useSpring(scrollYProgress, { stiffness: 120, damping: 25 });

  // Map global progress to local segments for two rockets (top pipe, bottom pipe)
  // The maps are loose and can be tweaked to match the original.
  const topRocketProgress = useTransform(smoothProgress, [0, 0.7, 1], [0, 0.9, 1]);
  const middleRocketProgress = useTransform(smoothProgress, [0.15, 0.65, 1], [0, 0.8, 1]);

  // Have a spring for nicer motion
  const topRocketSpring = useSpring(topRocketProgress, { stiffness: 200, damping: 30 });
  const middleRocketSpring = useSpring(middleRocketProgress, { stiffness: 220, damping: 28 });

  // Refs to SVG path elements so we can query length and points
  const topPathRef = useRef(null);
  const middlePathRef = useRef(null);

  // Coordinates for rockets
  const [topRocketCoords, setTopRocketCoords] = useState({ x: 0, y: 0, angle: 0 });
  const [middleRocketCoords, setMiddleRocketCoords] = useState({ x: 0, y: 0, angle: 0 });

  // Helper that samples path and sets coordinates
  useEffect(() => {
    let mounted = true;
    const unsubTop = topRocketSpring.onChange((p) => {
      const path = topPathRef.current;
      if (!path) return;
      const len = path.getTotalLength();
      const clamped = clamp(p, 0, 1);
      const point = path.getPointAtLength(len * clamped);
      // find a small forward point to calculate angle
      const ahead = path.getPointAtLength(Math.min(len, len * clamped + 1));
      const angle = Math.atan2(ahead.y - point.y, ahead.x - point.x) * (180 / Math.PI);
      if (mounted) setTopRocketCoords({ x: point.x, y: point.y, angle });
    });
    const unsubMid = middleRocketSpring.onChange((p) => {
      const path = middlePathRef.current;
      if (!path) return;
      const len = path.getTotalLength();
      const clamped = clamp(p, 0, 1);
      const point = path.getPointAtLength(len * clamped);
      const ahead = path.getPointAtLength(Math.min(len, len * clamped + 1));
      const angle = Math.atan2(ahead.y - point.y, ahead.x - point.x) * (180 / Math.PI);
      if (mounted) setMiddleRocketCoords({ x: point.x, y: point.y, angle });
    });

    return () => {
      mounted = false;
      if (unsubTop) unsubTop();
      if (unsubMid) unsubMid();
    };
  }, [topRocketSpring, middleRocketSpring]);

  // Flow nodes data
  const nodes = [
    { id: "frontend", title: "frontend", subtitle: "frontend-prod.up.railway.app", x: 720, y: 120 },
    { id: "api", title: "api gateway", subtitle: "api-prod.up.railway.app", x: 920, y: 220 },
    { id: "backend", title: "backend", subtitle: "Just deployed", x: 920, y: 320 },
    { id: "analytics", title: "ackee analytics", subtitle: "ackee-prod.up.railway.app", x: 600, y: 220 },
    { id: "postgres", title: "postgres", subtitle: "pg-data", x: 740, y: 360 },
  ];

  // small helper to animate nodes into view
  const cardVariants = {
    off: { opacity: 0, y: 12, scale: 0.98 },
    on: (i) => ({ opacity: 1, y: 0, scale: 1, transition: { delay: i * 0.08, duration: 0.6 } }),
  };

  return (
    <div ref={containerRef} className="min-h-screen bg-[#050507] text-white overflow-hidden relative">
      {/* Centered content wrapper */}
      <div className="max-w-[1200px] mx-auto py-28 px-6">
        {/* Two-column layout: left text, right flow diagram */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
          {/* LEFT COLUMN: Content / heading */}
          <div className="lg:col-span-5">
            <div className="max-w-lg">
              <p className="text-sm text-[#8b5cf6] mb-3">Network and Connect</p>
              <h1 className="text-3xl sm:text-4xl font-bold leading-tight mb-4">Interconnect your application seamlessly with highly performant networking</h1>
              <p className="text-sm text-[#8b98a6] mb-6">Railway provides automated service discovery, blazing fast networking, and support for any protocol, all out of the box.</p>

              <div className="flex items-center gap-3 text-xs text-[#9aa6b0]">
                <button className="px-3 py-2 rounded-md border border-[#2b2f36] bg-[#0b0b0c] hover:bg-[rgba(255,255,255,0.02)]">Learn More →</button>
                <div className="flex items-center gap-2 opacity-80">
                  {/* Small icons placeholders */}
                  <div className="w-6 h-6 rounded-full bg-[#18181b] flex items-center justify-center">R</div>
                  <div className="w-6 h-6 rounded-full bg-[#18181b] flex items-center justify-center">N</div>
                </div>
              </div>
            </div>

            {/* Decorative left vertical pipe (like screenshot) */}
            <div className="mt-16 relative h-[420px]">
              <svg className="absolute left-0 top-0 h-full w-24" viewBox="0 0 80 420" preserveAspectRatio="xMinYMid slice">
                {/* vertical pipe track */}
                <defs>
                  <linearGradient id="pipeGradient" x1="0" x2="1">
                    <stop offset="0%" stopColor="#6d28d9" stopOpacity="0.7" />
                    <stop offset="100%" stopColor="#0ea5e9" stopOpacity="0.25" />
                  </linearGradient>
                </defs>
                <path d="M40 8 L40 80 C40 120 40 120 20 150 L10 160" stroke="url(#pipeGradient)" strokeWidth="6" strokeLinecap="round" fill="none" />
                {/* small glow dot */}
                <circle cx="40" cy="80" r="6" fill="#7c3aed" opacity="0.9" />
              </svg>
            </div>
          </div>

          {/* RIGHT COLUMN: Flow Diagram */}
          <div className="lg:col-span-7 relative">
            {/* SVG canvas for pipes / wires */}
            <div className="relative h-[520px] w-full">
              <svg className="absolute inset-0 w-full h-full" viewBox="0 0 1100 520" preserveAspectRatio="xMidYMid slice">
                <defs>
                  <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="6" result="coloredBlur" />
                    <feMerge>
                      <feMergeNode in="coloredBlur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                </defs>

                {/* Top wire path */}
                <path
                  ref={topPathRef}
                  id="topWire"
                  d="M200 120 C300 80 420 80 520 120 C610 150 660 170 720 140"
                  stroke="#1f2937"
                  strokeWidth="4"
                  strokeLinecap="round"
                  fill="none"
                  style={{ filter: "url(#glow)" }}
                />
                {/* middle wire path */}
                <path
                  ref={middlePathRef}
                  id="middleWire"
                  d="M260 320 C380 280 520 260 660 320 C740 360 820 380 920 360"
                  stroke="#0f172a"
                  strokeWidth="4"
                  strokeLinecap="round"
                  fill="none"
                  style={{ filter: "url(#glow)" }}
                />

                {/* Decorative dot pattern behind nodes */}
                <g opacity="0.06">
                  {Array.from({ length: 200 }).map((_, i) => {
                    const cx = 400 + (i % 20) * 20;
                    const cy = 40 + Math.floor(i / 20) * 20;
                    return <circle key={i} cx={cx} cy={cy} r="1.2" fill="#9ca3af" />;
                  })}
                </g>

                {/* Draw connectors from wires to nodes (small animated circles) */}
                <motion.circle cx="520" cy="120" r="6" fill="#06b6d4" opacity={0.9} animate={{ scale: [1, 1.2, 1] }} transition={{ repeat: Infinity, duration: 2 }} />
                <motion.circle cx="660" cy="320" r="6" fill="#7c3aed" opacity={0.9} animate={{ scale: [1, 1.2, 1] }} transition={{ repeat: Infinity, duration: 2, delay: 0.3 }} />

                {/* Top rocket - positioned via absolute div over svg, but we draw a small path head for reference here (optional) */}
              </svg>

              {/* Rocket elements: absolutely positioned - their coordinates are in SVG space; we must transform to DOM */}
              <Rocket x={topRocketCoords.x} y={topRocketCoords.y} angle={topRocketCoords.angle} color="#7c3aed" size={22} containerViewBox={{ width: 1100, height: 520 }} containerClassName="absolute left-0 top-0 w-full h-full pointer-events-none" />
              <Rocket x={middleRocketCoords.x} y={middleRocketCoords.y} angle={middleRocketCoords.angle} color="#06b6d4" size={20} containerViewBox={{ width: 1100, height: 520 }} containerClassName="absolute left-0 top-0 w-full h-full pointer-events-none" />

              {/* Flow cards (nodes) - absolutely positioned to match screenshot layout */}
              {nodes.map((n, i) => (
                <motion.div
                  key={n.id}
                  custom={i}
                  initial="off"
                  whileInView="on"
                  viewport={{ once: false, amount: 0.2 }}
                  variants={cardVariants}
                  className="absolute bg-[#0b0b0d] border border-[#1f2937] rounded-lg shadow-2xl p-4 w-48"
                  style={{ left: n.x, top: n.y }}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-xs text-[#9ca3af]">{n.id === 'frontend' ? <strong className="uppercase tracking-wide text-[#f3f4f6]">{n.title}</strong> : <span className="text-sm font-semibold">{n.title}</span>}</div>
                      <div className="text-[11px] text-[#7b8794]">{n.subtitle}</div>
                    </div>
                    <div className="text-[11px] text-[#22c1ff]">●</div>
                  </div>
                </motion.div>
              ))}

              {/* Large backend card lower-left to emulate screenshot cluster */}
              <motion.div className="absolute left-48 top-[380px] w-64 bg-[#0b0b0d] border border-[#1f2937] rounded-lg p-4 shadow-2xl" initial={{ opacity: 0, y: 12 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: false }}>
                <div className="text-sm font-semibold">backend [EU]</div>
                <div className="text-xs text-[#7b8794] mt-2">Just deployed via CLI</div>
                <div className="mt-3 w-full h-12 bg-[#05060a] rounded-md border border-[#15161a] flex items-center justify-center text-[10px] text-[#9aa6b0]">16x CPU</div>
              </motion.div>

            </div>

            {/* Bottom section: scale and grow (small text) */}
            <div className="mt-8 text-right text-sm text-[#9aa6b0]">Scale your applications with intuitive controls</div>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Rocket component
 * - x,y are in SVG coordinate space (matching the svg viewBox width/height)
 * - we render the rocket as an HTML absolute element overlaying the SVG and
 *   translate the SVG coordinates to DOM pixels using the container bounding box
 */
function Rocket({ x = 0, y = 0, angle = 0, color = "#7c3aed", size = 20, containerViewBox = { width: 1100, height: 520 }, containerClassName = "" }) {
  const elRef = useRef(null);
  const wrapperRef = useRef(null);
  const [style, setStyle] = useState({ left: -9999, top: -9999, rotate: 0 });

  // convert svg coordinate to DOM pixels by comparing viewBox to wrapper size
  useEffect(() => {
    const wrapper = wrapperRef.current;
    if (!wrapper) return;
    const update = () => {
      const { width: domW, height: domH } = wrapper.getBoundingClientRect();
      const svgW = containerViewBox.width;
      const svgH = containerViewBox.height;
      // maintain aspect ratio (preserveAspectRatio="xMidYMid slice") used in svg
      // we approximate by scaling both by min(domW/svgW, domH/svgH) and centering
      const scale = Math.min(domW / svgW, domH / svgH);
      const offsetX = (domW - svgW * scale) / 2;
      const offsetY = (domH - svgH * scale) / 2;
      const left = offsetX + x * scale - size / 2;
      const top = offsetY + y * scale - size / 2;
      setStyle({ left, top, rotate: angle });
    };
    update();
    // update on resize
    const ro = new ResizeObserver(update);
    ro.observe(wrapper);
    return () => ro.disconnect();
  }, [x, y, angle, size, containerViewBox]);

  // subtle bobbing animation to make rocket feel alive
  const bobY = useSpring(0, { stiffness: 80, damping: 8 });
  useEffect(() => {
    let mounted = true;
    let t = 0;
    const loop = () => {
      if (!mounted) return;
      t += 0.03;
      const v = Math.sin(t) * 3; // +/- 3 px
      bobY.set(v);
      requestAnimationFrame(loop);
    };
    loop();
    return () => (mounted = false);
  }, []);

  return (
    <div ref={wrapperRef} className={containerClassName} style={{ position: "absolute", inset: 0 }}>
      <motion.div
        ref={elRef}
        className="absolute pointer-events-none"
        style={{ left: style.left, top: style.top, rotate: `${style.rotate}deg`, zIndex: 60 }}
        animate={{ y: [0, -4, 0] }}
        transition={{ repeat: Infinity, duration: 3, ease: "easeInOut" }}
      >
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <g transform="translate(2 2)">
            <path d="M8 0 L10 8 L8 6 L6 8 Z" fill={color} opacity="0.95" />
            <rect x="3" y="7" width="8" height="6" rx="2" fill="#0b1020" stroke={color} strokeWidth="0.8" />
            <circle cx="7" cy="10" r="1.2" fill="#0ea5e9" />
          </g>
        </svg>
      </motion.div>
    </div>
  );
}
