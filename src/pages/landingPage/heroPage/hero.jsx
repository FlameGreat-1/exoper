import { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import ParticlesBackground from "../../../components/ui/particles-background";
import TerminalCard from "../../../components/ui/terminal-card";
import TechStacks from "../../../components/ui/stacks";

const Hero = () => {
  const [currentTextIndex, setCurrentTextIndex] = useState(0);
  const [isVisible, setIsVisible] = useState(false);
  const [glowingLineIndex, setGlowingLineIndex] = useState(0);
  const [scrollY, setScrollY] = useState(0);
  const [isMobile, setIsMobile] = useState(false);
  const heroRef = useRef(null);
  const animationFrameRef = useRef(null);
  const textIntervalRef = useRef(null);
  const glowIntervalRef = useRef(null);

  const rotatingTexts = useMemo(() => [
    "Integrate AI Zero Trust API Gateway ?",
    "Optimize Cost, Time & Ship Faster ?",
    "Build cutting-edge solutions ?",
    "Ship secure software ?"
  ], []);
  
  const textColors = useMemo(() => [
    'text-purple-400',
    'text-white',
    'text-blue-400'
  ], []);
  
  const glowingColors = useMemo(() => [
    'rgba(139, 92, 246, 0.8)',
    'rgba(59, 130, 246, 0.8)',
    'rgba(255, 215, 0, 0.8)',
    'rgba(139, 92, 246, 0.8)',
    'rgba(59, 130, 246, 0.8)'
  ], []);

  const terminalCommands = useMemo(() => [
    `// Welcome to my portfolio
const developer = {
  name: "Emmanuel U. Iziogo",
  skills: ["Python", "React", "Tailwind CSS", "JavaScript", "Node.js"],
  passion: "Building beautiful web experiences"
};

// Let's create something amazing together!
developer.createArt();`,

    `// My services 1:
const builds = {
  offers: "AI Integration",
  services: ["Governance", "Security", "Compliance", "Auditing", "Monitoring"],
  passion: "Creating a protective layer between enterprises (YOU) and the AI models you use."
};

// Providing You Zero-Trust API Gateway for AI !
builds.createAI();`,

    `// My services 2:
const builds = {
  offers: "Software Solutions",
  services: ["Web applications", "Mobile applications", "Cloud solutions", "Workflow automation"],
  passion: "Developing innovative software solutions that drive business success."
};

// Let's build cutting-edge solutions !
builds.createApp();`
  ], []);

  const mainText = "Let me help you in Transforming ideas into exceptional digital experiences with modern web technologies and creative design solutions.";

  // Detect mobile device
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 1024 || /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent));
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Optimized scroll handler with throttling
  useEffect(() => {
    if (isMobile) return; // Disable scroll parallax on mobile
    
    let ticking = false;
    let lastScrollY = 0;
    
    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      
      // Only update if scroll changed significantly (reduce calculations)
      if (Math.abs(currentScrollY - lastScrollY) < 5) return;
      
      if (!ticking) {
        animationFrameRef.current = window.requestAnimationFrame(() => {
          setScrollY(currentScrollY);
          lastScrollY = currentScrollY;
          ticking = false;
        });
        ticking = true;
      }
    };
    
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', handleScroll);
      if (animationFrameRef.current) {
        window.cancelAnimationFrame(animationFrameRef.current);
      }
    };
  }, [isMobile]);

  // Text rotation with cleanup
  useEffect(() => {
    textIntervalRef.current = setInterval(() => {
      setCurrentTextIndex((prevIndex) => (prevIndex + 1) % rotatingTexts.length);
    }, 3000);
    
    return () => {
      if (textIntervalRef.current) {
        clearInterval(textIntervalRef.current);
      }
    };
  }, [rotatingTexts.length]);
  
  // Intersection Observer
  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        setIsVisible(entry.isIntersecting);
      },
      { threshold: 0.1 }
    );
    
    if (heroRef.current) {
      observer.observe(heroRef.current);
    }
    
    return () => {
      if (heroRef.current) {
        observer.unobserve(heroRef.current);
      }
    };
  }, []);
  
  // Glowing line animation with cleanup
  useEffect(() => {
    glowIntervalRef.current = setInterval(() => {
      setGlowingLineIndex((prevIndex) => (prevIndex + 1) % glowingColors.length);
    }, 1500);
    
    return () => {
      if (glowIntervalRef.current) {
        clearInterval(glowIntervalRef.current);
      }
    };
  }, [glowingColors.length]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (animationFrameRef.current) {
        window.cancelAnimationFrame(animationFrameRef.current);
      }
      if (textIntervalRef.current) {
        clearInterval(textIntervalRef.current);
      }
      if (glowIntervalRef.current) {
        clearInterval(glowIntervalRef.current);
      }
    };
  }, []);

  return (
    <section 
      ref={heroRef}
      className="relative w-full min-h-screen overflow-hidden bg-black"
      aria-label="Hero section"
    >
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-b from-black via-gray-950 to-black"></div>
        <div 
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, rgb(148 163 184 / 0.15) 1px, transparent 1px)`,
            backgroundSize: '24px 24px',
            backgroundPosition: isMobile ? '0 0' : `${scrollY * 0.1}px ${scrollY * 0.1}px`,
            willChange: isMobile ? 'auto' : 'background-position'
          }}
        ></div>
      </div>

      {/* Simplified SVG - removed infinite animations on mobile */}
      {!isMobile && (
        <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 1 }}>
          <defs>
            <linearGradient id="heroGradient" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#8B5CF6" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#3B82F6" stopOpacity="1" />
              <stop offset="100%" stopColor="#8B5CF6" stopOpacity="0.8" />
            </linearGradient>
            
            <filter id="glow">
              <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
              <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
          </defs>

          <path
            d="M 100 100 Q 200 150 300 100 T 500 100"
            stroke="url(#heroGradient)"
            strokeWidth="2"
            fill="none"
            filter="url(#glow)"
            opacity="0.5"
            vectorEffect="non-scaling-stroke"
          />

          <path
            d="M 800 200 Q 900 250 1000 200 T 1200 200"
            stroke="url(#heroGradient)"
            strokeWidth="2"
            fill="none"
            filter="url(#glow)"
            opacity="0.5"
            vectorEffect="non-scaling-stroke"
          />

          <circle cx="200" cy="150" r="4" fill="#8B5CF6" filter="url(#glow)" />
          <circle cx="900" cy="250" r="4" fill="#3B82F6" filter="url(#glow)" />
        </svg>
      )}

      <div className="absolute top-1/4 -right-20 w-80 h-80 bg-purple-600/10 rounded-full blur-3xl"></div>
      <div className="absolute -bottom-20 left-1/4 w-72 h-72 bg-blue-600/10 rounded-full blur-3xl"></div>
                
      <div className="relative z-20 w-full max-w-7xl mx-auto px-4 sm:px-6 md:px-8 lg:px-12 flex flex-col items-center justify-center min-h-screen py-16 sm:py-20 md:py-24">
        <div className="w-full max-w-6xl mx-auto text-center">
          <motion.h1 
            className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-7xl font-bold tracking-tight mb-4 sm:mb-6 px-2"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 20 }}
            transition={{ duration: 0.7, delay: 0.2 }}
          >
            <span className="block text-white">Let's Create And Craft</span>
            <span className="bg-gradient-to-r from-purple-500 to-blue-500 bg-clip-text text-transparent">ART</span>
          </motion.h1>
          
          <div className="h-auto min-h-[3rem] sm:min-h-[3.5rem] md:min-h-[4rem] mb-6 sm:mb-8 overflow-hidden px-2">
            <AnimatePresence mode="wait">
              <motion.p
                key={currentTextIndex}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.5 }}
                className={`text-base sm:text-lg md:text-xl lg:text-2xl xl:text-3xl font-medium ${textColors[currentTextIndex]}`}
              >
                {rotatingTexts[currentTextIndex]}
              </motion.p>
            </AnimatePresence>
          </div>
          
          <motion.div 
            className="mt-4 sm:mt-6 relative px-2"
            initial={{ opacity: 0 }}
            animate={{ opacity: isVisible ? 1 : 0 }}
            transition={{ duration: 0.7, delay: 0.4 }}
          >
            <div className="text-sm sm:text-base md:text-lg lg:text-xl text-gray-400 max-w-2xl mx-auto leading-relaxed">
              {mainText}
            </div>
            
            {/* Simplified glowing line - single element instead of 5 overlays */}
            <div className="relative w-full h-1 mt-4 overflow-hidden">
              <motion.div
                className="absolute inset-0 flex items-center justify-center"
                animate={{ opacity: [0.6, 1, 0.6] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                <div 
                  className="h-0.5 w-3/4 mx-auto" 
                  style={{ 
                    background: `linear-gradient(90deg, transparent 0%, ${glowingColors[glowingLineIndex]} 20%, ${glowingColors[glowingLineIndex]} 80%, transparent 100%)`,
                    boxShadow: `0 0 8px ${glowingColors[glowingLineIndex]}`
                  }}
                />
              </motion.div>
            </div>
          </motion.div>
          
          <motion.div 
            className="w-full max-w-2xl mx-auto mt-6 sm:mt-8 md:mt-10 px-2"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 30 }}
            transition={{ duration: 0.7, delay: 0.6 }}
          >
            <div className="relative">
              <div className="absolute -inset-4 bg-gradient-to-r from-purple-600/10 to-blue-600/10 rounded-lg blur-xl"></div>
              <div className="relative bg-gray-900/80 backdrop-blur-sm rounded-lg border border-gray-800 hover:border-purple-500/50 transition-all duration-300">
                <TerminalCard 
                  commands={terminalCommands}
                  language="javascript"
                  className="shadow-xl rounded-xl overflow-hidden"
                />
              </div>
            </div>
          </motion.div>
          
          <motion.div 
            className="mt-6 sm:mt-8 md:mt-10 lg:mt-12 px-2"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 30 }}
            transition={{ duration: 0.7, delay: 0.8 }}
          >
            <TechStacks />
          </motion.div>
          
          <motion.div 
            className="mt-10 sm:mt-12 md:mt-14 lg:mt-16 pt-6 sm:pt-8 border-t border-gray-800 px-2"
            initial={{ opacity: 0 }}
            animate={{ opacity: isVisible ? 1 : 0 }}
            transition={{ duration: 0.7, delay: 1 }}
          >
            <div className="flex items-center justify-center space-x-2 mb-4">
              <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></div>
              <span className="text-purple-400 text-xs sm:text-sm font-medium tracking-wide">TRUSTED BY INNOVATIVE TEAMS</span>
            </div>
            <div className="flex flex-wrap justify-center gap-3 sm:gap-4 md:gap-6 lg:gap-8">
              {['Company 1', 'Company 2', 'Company 3', 'Company 4'].map((company, index) => (
                <div 
                  key={index}
                  className="px-3 sm:px-4 py-2 bg-gray-900/60 backdrop-blur-sm rounded border border-gray-800 hover:border-purple-500/50 transition-all duration-300 transform hover:-translate-y-1"
                >
                  <span className="text-gray-400 hover:text-purple-400 transition-colors text-xs sm:text-sm md:text-base">{company}</span>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>

      {/* Simplified avatar animations - no infinite loops on mobile */}
      {!isMobile && (
        <>
          <div
            className="pointer-events-none hidden xl:block z-20"
            style={{ position: 'absolute', left: '8%', top: '15%' }}
            aria-hidden="true"
          >
            <div className="space-y-6">
              <motion.div
                className="relative w-20 h-20 xl:w-24 xl:h-24 rounded-full ring-8 ring-purple-900/20 shadow-2xl overflow-hidden bg-gray-900/60 backdrop-blur-sm border border-gray-800"
                initial={{ opacity: 0, y: 12, scale: 0.92 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ delay: 0.12, duration: 0.45, ease: "easeOut" }}
              >
                <img
                  src="/images/avatars/avatar-left-1.png"
                  alt=""
                  className="object-cover w-full h-full rounded-full"
                  loading="lazy"
                />
                <span className="absolute inset-0 rounded-full mix-blend-screen" style={{ boxShadow: "0 10px 30px rgba(139,92,246,0.22)", filter: "blur(6px)", opacity: 0.55 }} />
              </motion.div>

              <motion.div
                className="relative w-14 h-14 xl:w-16 xl:h-16 rounded-full ring-6 ring-blue-900/20 shadow-2xl overflow-hidden bg-gray-900/60 backdrop-blur-sm border border-gray-800"
                initial={{ opacity: 0, y: 12, scale: 0.92 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ delay: 0.24, duration: 0.45, ease: "easeOut" }}
              >
                <img
                  src="/images/avatars/avatar-left-2.png"
                  alt=""
                  className="object-cover w-full h-full rounded-full"
                  loading="lazy"
                />
                <span className="absolute inset-0 rounded-full mix-blend-screen" style={{ boxShadow: "0 8px 24px rgba(59,130,246,0.18)", filter: "blur(6px)", opacity: 0.5 }} />
              </motion.div>
            </div>
          </div>

          <div
            className="pointer-events-none hidden xl:block z-20"
            style={{ position: 'absolute', right: '8%', top: '30%' }}
            aria-hidden="true"
          >
            <div className="space-y-6">
              <motion.div
                className="relative w-20 h-20 xl:w-24 xl:h-24 rounded-full ring-8 ring-purple-900/20 shadow-2xl overflow-hidden bg-gray-900/60 backdrop-blur-sm border border-gray-800"
                initial={{ opacity: 0, y: -12, scale: 0.92 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ delay: 0.12, duration: 0.45, ease: "easeOut" }}
              >
                <img
                  src="/images/avatars/avatar-right-1.png"
                  alt=""
                  className="object-cover w-full h-full rounded-full"
                  loading="lazy"
                />
                <span className="absolute inset-0 rounded-full mix-blend-screen" style={{ boxShadow: "0 10px 30px rgba(139,92,246,0.22)", filter: "blur(6px)", opacity: 0.55 }} />
              </motion.div>

              <motion.div
                className="relative w-10 h-10 xl:w-12 xl:h-12 rounded-full ring-4 ring-blue-900/12 shadow-2xl overflow-hidden bg-gray-900/60 backdrop-blur-sm border border-gray-800"
                initial={{ opacity: 0, y: -12, scale: 0.92 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ delay: 0.24, duration: 0.45, ease: "easeOut" }}
              >
                <img
                  src="/images/avatars/avatar-right-2.png"
                  alt=""
                  className="object-cover w-full h-full rounded-full"
                  loading="lazy"
                />
                <span className="absolute inset-0 rounded-full mix-blend-screen" style={{ boxShadow: "0 8px 24px rgba(59,130,246,0.18)", filter: "blur(6px)", opacity: 0.5 }} />
              </motion.div>
            </div>
          </div>
        </>
      )}

      {/* Reduced particle count on mobile */}
      <div className="absolute inset-0 w-full h-full" style={{ zIndex: 2 }}>
        <ParticlesBackground 
          colors={['#8B5CF6', '#3B82F6', '#FFD700']}
          size={isMobile ? 2 : 3}
          countDesktop={isMobile ? 15 : 50}
          countTablet={isMobile ? 10 : 35}
          countMobile={15}
          zIndex={2}
          height="100%"
          width="100%"
        />
      </div>
      
      <motion.div 
        className="absolute bottom-8 left-1/2 transform -translate-x-1/2 z-20 hidden md:block"
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: [0, 1, 0], y: [0, 10, 0] }}
        transition={{ duration: 2, repeat: Infinity }}
      >
        <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
        </svg>
      </motion.div>
    </section>
  );
};

export default Hero;