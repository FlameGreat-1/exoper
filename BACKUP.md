import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { GridBackground } from "../../../components/ui/grid-dot-background";
import ParticlesBackground from "../../../components/ui/particles-background";
import TerminalCard from "../../../components/ui/terminal-card";
import TechStacks from "../../../components/ui/stacks";
import { motion, AnimatePresence } from 'framer-motion';

const Hero = () => {
  const [currentTextIndex, setCurrentTextIndex] = useState(0);
  const [isVisible, setIsVisible] = useState(false);
  const [glowingLineIndex, setGlowingLineIndex] = useState(0);
  const heroRef = useRef(null);

  const rotatingTexts = ["Optimize Cost, Time & Ship Faster ?", "Build cutting-edge solutions ?", "Ship secure software ?"];
  
  const textColors = [
    'text-primary dark:text-primary', // First text - primary color
    'text-white dark:text-white',     // Second text - white
    'text-purple-500 dark:text-purple-400' // Third text - purple
  ];
  
  const glowingColors = [
    'rgba(102, 126, 234, 0.8)',
    'rgba(237, 100, 166, 0.8)',
    'rgba(246, 173, 85, 0.8)',
    'rgba(72, 187, 120, 0.8)',
    'rgba(99, 179, 237, 0.8)'
  ];

  const terminalCommands = [
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
  ];

  // Split the paragraph into groups of 3 words for underlining
  const mainText = "Let me help you in Transforming ideas into exceptional digital experiences with modern web technologies and creative design solutions.";
  const words = mainText.split(' ');
  const wordGroups = [];
  
  for (let i = 0; i < words.length; i += 3) {
    wordGroups.push(words.slice(i, i + 3).join(' '));
  }
  
  const underlineColors = [
    '#646cff', // primary
    '#5d1eb2', // purple
    '#ff7300', // orange
    '#00c4cc', // teal
    '#ff223e', // red
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTextIndex((prevIndex) => (prevIndex + 1) % rotatingTexts.length);
    }, 3000);
    
    return () => clearInterval(interval);
  }, []);
  
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
    const interval = setInterval(() => {
      setGlowingLineIndex((prevIndex) => (prevIndex + 1) % glowingColors.length);
    }, 1500);
    
    return () => clearInterval(interval);
  }, []);

  return (
    <section 
      ref={heroRef}
      className="relative w-full min-h-screen overflow-hidden"
      aria-label="Hero section"
    >
      <div className="absolute inset-0 bg-gradient-to-br from-gray-950 to-black dark:from-black dark:to-gray-950 z-0" />
    
      <div className="absolute inset-0 bg-black/40 z-0" />

      <GridBackground 
        className="w-full min-h-screen"
        gridSize={20}
        gridColor="rgba(228, 228, 231, 0.4)"
        darkGridColor="rgba(38, 38, 38, 0.5)"
        showFade={true}
        fadeIntensity={30}
      >
        <div className="absolute inset-0 w-full h-full">
          <ParticlesBackground 
            colors={['var(--color-primary)', '#5d1eb2', '#ff7300']}
            size={3}
            countDesktop={60}
            countTablet={50}
            countMobile={40}
            zIndex={10}
            height="100%"
            width="100%"
          />
        </div>

        <div className="absolute top-1/4 -right-20 w-80 h-80 bg-primary/5 rounded-full blur-3xl -z-10" />
        <div className="absolute -bottom-20 left-1/4 w-72 h-72 bg-purple-500/5 rounded-full blur-3xl -z-10" />
                
        <div className="relative z-20 container mx-auto px-4 sm:px-6 lg:px-8 flex flex-col items-center justify-center min-h-screen py-20">
          <div className="max-w-4xl mx-auto text-center">
            <motion.h1 
              className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-extrabold tracking-tight mb-6"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 20 }}
              transition={{ duration: 0.7, delay: 0.2 }}
            >
              <span className="block text-foreground dark:text-white">Let's Create And Craft</span>
              <span className="bg-gradient-to-r from-primary to-purple-600 bg-clip-text text-transparent">ART</span>
            </motion.h1>
            
            <div className="h-12 sm:h-16 mb-8 overflow-hidden">
              <AnimatePresence mode="wait">
                <motion.p
                  key={currentTextIndex}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.5 }}
                  className={`text-xl sm:text-2xl md:text-3xl font-semibold ${textColors[currentTextIndex]}`}
                >
                  {rotatingTexts[currentTextIndex]}
                </motion.p>
              </AnimatePresence>
            </div>
            
            <motion.div 
              className="mt-6 relative"
              initial={{ opacity: 0 }}
              animate={{ opacity: isVisible ? 1 : 0 }}
              transition={{ duration: 0.7, delay: 0.4 }}
            >
              <div className="text-lg sm:text-xl text-foreground/80 dark:text-gray-300 max-w-2xl mx-auto">
                {wordGroups.map((group, index) => (
                  <span key={index} className="relative inline">
                    {group}{' '}
                    <span 
                      className="absolute bottom-0 left-0 w-full h-0.5"
                      style={{ 
                        backgroundColor: underlineColors[index % underlineColors.length],
                        boxShadow: `0 0 4px ${underlineColors[index % underlineColors.length]}`
                      }}
                    ></span>
                  </span>
                ))}
              </div>
              
              <div className="relative w-full h-1 mt-4 overflow-hidden">
                {glowingColors.map((color, index) => (
                  <motion.div
                    key={index}
                    className="absolute inset-0 flex items-center justify-center"
                    initial={{ opacity: 0 }}
                    animate={{ 
                      opacity: glowingLineIndex === index ? 1 : 0,
                    }}
                    transition={{ duration: 0.5 }}
                  >
                    <div 
                      className="h-0.5 w-3/4 mx-auto" 
                      style={{ 
                        background: `linear-gradient(90deg, transparent 0%, ${color} 20%, ${color} 80%, transparent 100%)`,
                        boxShadow: `0 0 8px ${color}, 0 0 12px ${color}`
                      }}
                    >
                      <div className="absolute inset-0 flex justify-between">
                        {[...Array(8)].map((_, i) => (
                          <div 
                            key={i} 
                            className="h-0.5 w-4" 
                            style={{ 
                              background: 'transparent',
                              boxShadow: `0 0 4px ${color}`
                            }}
                          ></div>
                        ))}
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
            
            <motion.div 
              className="w-full max-w-2xl mx-auto mt-10"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 30 }}
              transition={{ duration: 0.7, delay: 0.6 }}
            >
              <TerminalCard 
                commands={terminalCommands}
                language="javascript"
                className="shadow-xl dark:shadow-gray-900/30 rounded-xl overflow-hidden"
              />
            </motion.div>
            
            <motion.div 
              className="mt-12"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 30 }}
              transition={{ duration: 0.7, delay: 0.8 }}
            >
              <TechStacks />
            </motion.div>
            
            <motion.div 
              className="mt-16 pt-8 border-t border-gray-200 dark:border-gray-800"
              initial={{ opacity: 0 }}
              animate={{ opacity: isVisible ? 1 : 0 }}
              transition={{ duration: 0.7, delay: 1 }}
            >
              <p className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-4">
                TRUSTED BY INNOVATIVE TEAMS
              </p>
              <div className="flex flex-wrap justify-center gap-8 opacity-70">
                <div className="h-8 flex items-center grayscale hover:grayscale-0 transition-all duration-300">
                  <span className="text-gray-400">Company 1</span>
                </div>
                <div className="h-8 flex items-center grayscale hover:grayscale-0 transition-all duration-300">
                  <span className="text-gray-400">Company 2</span>
                </div>
                <div className="h-8 flex items-center grayscale hover:grayscale-0 transition-all duration-300">
                  <span className="text-gray-400">Company 3</span>
                </div>
                <div className="h-8 flex items-center grayscale hover:grayscale-0 transition-all duration-300">
                  <span className="text-gray-400">Company 4</span>
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </GridBackground>
      
      <motion.div 
        className="absolute bottom-8 left-1/2 transform -translate-x-1/2 z-20 hidden md:block"
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: [0, 1, 0], y: [0, 10, 0] }}
        transition={{ duration: 2, repeat: Infinity }}
      >
        <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
        </svg>
      </motion.div>
    </section>
  );
};

export default Hero;
