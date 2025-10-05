import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import ParticlesBackground from "../../../components/ui/particles-background";
import TerminalCard from "../../../components/ui/terminal-card";
import Companies from "../../../components/ui/companies";

const Hero = () => {
  const [currentTextIndex, setCurrentTextIndex] = useState(0);
  const [isVisible, setIsVisible] = useState(false);
  const [glowingLineIndex, setGlowingLineIndex] = useState(0);
  const [scrollY, setScrollY] = useState(0);
  const [isMobile, setIsMobile] = useState(false);
  const [devCount, setDevCount] = useState(500);
  const [communityCount, setCommunityCount] = useState(1);
  const [isCountingDevs, setIsCountingDevs] = useState(true);
  const [showCelebration, setShowCelebration] = useState(false);
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

  const triggerCelebration = useCallback(() => {
    setShowCelebration(true);
    setTimeout(() => setShowCelebration(false), 800);
  }, []);

  useEffect(() => {
    if (!isVisible) return;

    const interval = setInterval(() => {
      if (isCountingDevs) {
        setDevCount(prev => {
          const next = prev + Math.floor(Math.random() * 15000) + 5000;
          if (next >= 500000) {
            triggerCelebration();
            setTimeout(() => {
              setIsCountingDevs(false);
              setCommunityCount(1);
            }, 1000);
            return 500000;
          }
          if (next >= 100000 && prev < 100000) triggerCelebration();
          if (next >= 250000 && prev < 250000) triggerCelebration();
          return next;
        });
      } else {
        setCommunityCount(prev => {
          const next = prev + Math.floor(Math.random() * 2) + 1;
          if (next >= 18) {
            triggerCelebration();
            setTimeout(() => {
              setIsCountingDevs(true);
              setDevCount(500);
            }, 1000);
            return 18;
          }
          if (next >= 5 && prev < 5) triggerCelebration();
          if (next >= 10 && prev < 10) triggerCelebration();
          return next;
        });
      }
    }, 50);

    return () => clearInterval(interval);
  }, [isVisible, isCountingDevs, triggerCelebration]);

  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 1024 || /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent));
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  useEffect(() => {
    if (isMobile) return;
    
    let ticking = false;
    let lastScrollY = 0;
    
    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      
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
            backgroundPosition: '0 0'
          }}
        ></div>
      </div>

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
                
      <div className="relative z-20 w-full max-w-7xl mx-auto px-4 sm:px-6 md:px-8 lg:px-12 flex flex-col items-center justify-center min-h-screen py-8 md:py-12 lg:py-16 xl:py-20">
        
        <div className="w-full flex flex-col lg:flex-row items-start justify-between gap-4 lg:gap-8 mb-4 md:mb-6 lg:mb-8">
          
          <motion.div 
            className="w-full lg:w-[52%] order-2 lg:order-1 mt-2 sm:mt-3 md:mt-4 px-2 lg:px-0 lg:-ml-16 flex justify-center lg:justify-start items-start"
            initial={{ opacity: 0, x: -30 }}
            animate={{ opacity: isVisible ? 1 : 0, x: isVisible ? 0 : -30 }}
            transition={{ duration: 0.7, delay: 0.6 }}
          >
            <div className="relative w-full max-w-3xl h-[300px]">
              <div className="absolute -inset-4 bg-gradient-to-r from-purple-600/10 to-blue-600/10 rounded-lg blur-xl"></div>
              <div className="relative bg-gray-900/80 backdrop-blur-sm rounded-lg border border-gray-800 hover:border-purple-500/50 transition-all duration-300 h-full overflow-hidden">
                <TerminalCard 
                  commands={terminalCommands}
                  language="javascript"
                  className="shadow-xl rounded-xl h-full overflow-hidden [&_pre]:text-center [&_.react-syntax-highlighter]:text-center [&>div:last-child]:h-[calc(100%-44px)] [&>div:last-child]:overflow-hidden [&>div:last-child]:max-h-none"
                />
              </div>
            </div>
          </motion.div>

          <div className="w-full lg:w-[44%] order-1 lg:order-2 text-center lg:text-left px-2 lg:px-0 lg:ml-8">
            <motion.h1 
              className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl xl:text-7xl font-bold tracking-tight mb-4 sm:mb-6"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 20 }}
              transition={{ duration: 0.7, delay: 0.2 }}
            >
              <span className="block lg:inline text-white">Let's Create And Craft </span>
              <span className="bg-gradient-to-r from-purple-500 to-blue-500 bg-clip-text text-transparent">ART</span>
            </motion.h1>
            
            <div className="h-auto min-h-[3rem] sm:min-h-[3.5rem] md:min-h-[4rem] mb-6 sm:mb-8 overflow-hidden">
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
              className="mt-4 sm:mt-6 relative"
              initial={{ opacity: 0 }}
              animate={{ opacity: isVisible ? 1 : 0 }}
              transition={{ duration: 0.7, delay: 0.4 }}
            >
              <div className="text-sm sm:text-base md:text-lg lg:text-xl text-gray-400 max-w-2xl mx-auto lg:mx-0 leading-relaxed">
                {mainText}
              </div>
              
              <div className="relative w-full h-1 mt-4 overflow-hidden">
                <motion.div
                  className="absolute inset-0 flex items-center justify-center lg:justify-start"
                  animate={{ opacity: [0.6, 1, 0.6] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  <div 
                    className="h-0.5 w-3/4 mx-auto lg:mx-0" 
                    style={{ 
                      background: `linear-gradient(90deg, transparent 0%, ${glowingColors[glowingLineIndex]} 20%, ${glowingColors[glowingLineIndex]} 80%, transparent 100%)`,
                      boxShadow: `0 0 8px ${glowingColors[glowingLineIndex]}`
                    }}
                  />
                </motion.div>
              </div>
            </motion.div>
          </div>
        </div>

        <motion.div 
          className="mt-8 sm:mt-10 md:mt-12 lg:mt-16 px-2"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 30 }}
          transition={{ duration: 0.7, delay: 0.8 }}
        >
          <Companies />
        </motion.div>
        
        <motion.div 
          className="mt-6 sm:mt-8 md:mt-10 lg:mt-12 pt-4 sm:pt-6 md:pt-8 border-t border-gray-800 px-2 w-full flex flex-col items-center"
          initial={{ opacity: 0 }}
          animate={{ opacity: isVisible ? 1 : 0 }}
          transition={{ duration: 0.7, delay: 1 }}
        >
          <div className="text-center mb-6 sm:mb-8 relative">
            <h3 className="text-lg sm:text-xl md:text-2xl lg:text-3xl text-gray-300 font-medium mb-4">
              Trusted by more than {devCount.toLocaleString()}+ developers at the world's leading AI companies
            </h3>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-6 sm:gap-8 md:gap-12">
              <div className="flex items-center gap-2 relative">
                <AnimatePresence>
                  {showCelebration && isCountingDevs && (
                    <>
                      {[...Array(8)].map((_, i) => (
                        <motion.div
                          key={i}
                          className="absolute w-2 h-2 bg-yellow-400 rounded-full"
                          initial={{ scale: 0, x: 0, y: 0 }}
                          animate={{ 
                            scale: [0, 1, 0],
                            x: Math.cos((i * Math.PI * 2) / 8) * 40,
                            y: Math.sin((i * Math.PI * 2) / 8) * 40,
                            opacity: [1, 1, 0]
                          }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 0.8 }}
                        />
                      ))}
                    </>
                  )}
                </AnimatePresence>
                <svg className="w-6 h-6 sm:w-7 sm:h-7 text-purple-400" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                </svg>
                <div className="flex items-center gap-1">
                  {[...Array(5)].map((_, i) => (
                    <svg key={i} className="w-5 h-5 sm:w-6 sm:h-6 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                      <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/>
                    </svg>
                  ))}
                </div>
                <span className="text-gray-300 text-base sm:text-lg md:text-xl font-medium ml-2">4.8 rating</span>
              </div>
              <div className="flex items-center gap-2 relative">
                <AnimatePresence>
                  {showCelebration && !isCountingDevs && (
                    <>
                      {[...Array(8)].map((_, i) => (
                        <motion.div
                          key={i}
                          className="absolute w-2 h-2 bg-purple-400 rounded-full"
                          initial={{ scale: 0, x: 0, y: 0 }}
                          animate={{ 
                            scale: [0, 1, 0],
                            x: Math.cos((i * Math.PI * 2) / 8) * 40,
                            y: Math.sin((i * Math.PI * 2) / 8) * 40,
                            opacity: [1, 1, 0]
                          }}
                          exit={{ opacity: 0 }}
                          transition={{ duration: 0.8 }}
                        />
                      ))}
                    </>
                  )}
                </AnimatePresence>
                <svg className="w-6 h-6 sm:w-7 sm:h-7 text-purple-400" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/>
                </svg>
                <span className="text-gray-300 text-base sm:text-lg md:text-xl font-medium">{communityCount}K+ AI native engineering community</span>
              </div>
            </div>
          </div>
        </motion.div>
      </div>

      <div className="absolute inset-0 w-full h-full" style={{ zIndex: 2 }}>
      <ParticlesBackground 
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