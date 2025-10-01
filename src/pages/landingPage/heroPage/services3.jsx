import React, { useState, useEffect, useRef } from 'react';
import { ChevronRight, GitBranch, Database, Globe, Shield, Zap, Server, Cloud, Lock, Activity, Terminal, Code, Box, Layers, Cpu, ArrowRight, Circle, Hexagon } from 'lucide-react';

const Projects = () => {
  const [scrollY, setScrollY] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(0);
  const containerRef = useRef(null);
  const [elementPositions, setElementPositions] = useState({});

  useEffect(() => {
    const handleScroll = () => {
      setScrollY(window.scrollY);
    };

    const handleResize = () => {
      setViewportHeight(window.innerHeight);
    };

    window.addEventListener('scroll', handleScroll);
    window.addEventListener('resize', handleResize);
    handleResize();

    return () => {
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const calculatePathProgress = (startY, endY) => {
    const progress = Math.max(0, Math.min(1, (scrollY - startY) / (endY - startY)));
    return progress;
  };

  return (
    <div ref={containerRef} className="min-h-screen bg-[#0B0D14] text-white relative">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <svg className="absolute inset-0 w-full" style={{ height: '300vh' }} preserveAspectRatio="none">
          <defs>
            <linearGradient id="pipeGradient1" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#FF006E" stopOpacity="0.8">
                <animate attributeName="stopOpacity" values="0.8;0.4;0.8" dur="3s" repeatCount="indefinite" />
              </stop>
              <stop offset="100%" stopColor="#8338EC" stopOpacity="0.3" />
            </linearGradient>
            <linearGradient id="pipeGradient2" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#8338EC" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#FF006E" stopOpacity="0.3">
                <animate attributeName="stopOpacity" values="0.3;0.8;0.3" dur="2s" repeatCount="indefinite" />
              </stop>
            </linearGradient>
            <filter id="glow">
              <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
              <feMerge>
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
              </feMerge>
            </filter>
            <filter id="blur">
              <feGaussianBlur in="SourceGraphic" stdDeviation="2"/>
            </filter>
          </defs>

          <path
            d="M 450 0 L 450 500 Q 450 550 500 550 L 700 550 Q 750 550 750 600 L 750 1200"
            stroke="url(#pipeGradient1)"
            strokeWidth="3"
            fill="none"
            opacity="0.9"
            filter="url(#glow)"
          />
          
          <path
            d="M 450 0 L 450 500 Q 450 550 500 550 L 700 550 Q 750 550 750 600 L 750 1200"
            stroke="url(#pipeGradient1)"
            strokeWidth="8"
            fill="none"
            opacity="0.3"
            filter="url(#blur)"
          />

          <g transform={`translate(450, ${Math.min(500, scrollY * 0.3)})`}>
            <circle cx="0" cy="0" r="4" fill="#FF006E">
              <animate attributeName="r" values="4;6;4" dur="2s" repeatCount="indefinite"/>
            </circle>
            <circle cx="0" cy="0" r="12" fill="#FF006E" opacity="0.3">
              <animate attributeName="r" values="12;20;12" dur="2s" repeatCount="indefinite"/>
            </circle>
            <path d="M -6 -8 L 6 -8 L 8 4 L 0 10 L -8 4 Z" fill="#FF006E" opacity="0.8">
              <animateTransform attributeName="transform" type="rotate" from="0 0 0" to="360 0 0" dur="3s" repeatCount="indefinite"/>
            </path>
          </g>

          <path
            d="M 450 700 L 450 900"
            stroke="url(#pipeGradient2)"
            strokeWidth="3"
            fill="none"
            opacity="0.9"
            filter="url(#glow)"
          />
          
          <g transform={`translate(450, ${700 + Math.min(200, scrollY * 0.1)})`}>
            <circle cx="0" cy="0" r="4" fill="#8338EC">
              <animate attributeName="r" values="4;6;4" dur="1.5s" repeatCount="indefinite"/>
            </circle>
            <circle cx="0" cy="0" r="12" fill="#8338EC" opacity="0.3">
              <animate attributeName="r" values="12;20;12" dur="1.5s" repeatCount="indefinite"/>
            </circle>
            <path d="M -6 -8 L 6 -8 L 8 4 L 0 10 L -8 4 Z" fill="#8338EC" opacity="0.8">
              <animateTransform attributeName="transform" type="rotate" from="0 0 0" to="-360 0 0" dur="2.5s" repeatCount="indefinite"/>
            </path>
          </g>
        </svg>
      </div>

      <div className="relative z-10">
        <section className="min-h-screen flex items-center justify-center px-8 py-20">
          <div className="max-w-4xl mx-auto text-center">
            <div className="space-y-6">
              <p className="text-gray-400 text-lg leading-relaxed">
                For too long, deploying cloud infrastructure has been<br />
                the <span className="text-white underline decoration-pink-500 underline-offset-4">most painful part</span> of the developer toolchain.
              </p>
              
              <p className="text-gray-400 text-lg leading-relaxed mt-8">
                We're working at the intersection of distributed systems<br />
                engineering and interface design to rebuild every layer<br />
                of the stack for speed and developer experience.
              </p>
              
              <p className="text-gray-400 text-lg leading-relaxed mt-8">
                With instant deployments and effortless scale, a better<br />
                way to deploy applications is now boarding.
              </p>
              
              <p className="text-white text-lg mt-12">
                Welcome to Exoper.
              </p>
            </div>
          </div>
        </section>

        <section className="min-h-screen flex items-center px-8 py-20">
          <div className="max-w-6xl mx-auto w-full">
            <div className="grid grid-cols-2 gap-20 items-center">
              <div>
                <p className="text-pink-500 text-sm font-medium mb-4">Build and Deploy</p>
                <h2 className="text-5xl font-bold mb-6 leading-tight">
                  Craft a complete full-stack<br />
                  application with a powerful<br />
                  visual canvas
                </h2>
                <p className="text-gray-400 text-lg mb-8">
                  Exoper builds and deploys any combination of services,<br />
                  volumes, and databases from GitHub or Docker.
                </p>
                <button className="text-white hover:text-gray-300 transition-colors flex items-center gap-2 group">
                  <span>Learn More</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </button>

                <div className="flex gap-4 mt-12">
                  <div className="flex items-center gap-2 px-3 py-1 bg-[#1A1B26] rounded-full border border-gray-800">
                    <Circle className="w-3 h-3 text-gray-500" fill="currentColor" />
                    <span className="text-xs text-gray-400">Replicas</span>
                  </div>
                  <div className="flex items-center gap-2 px-3 py-1 bg-[#1A1B26] rounded-full border border-gray-800">
                    <Hexagon className="w-3 h-3 text-blue-500" fill="currentColor" />
                    <span className="text-xs text-gray-400"></span>
                  </div>
                  <div className="flex items-center gap-2 px-3 py-1 bg-[#1A1B26] rounded-full border border-gray-800">
                    <Database className="w-3 h-3 text-purple-500" />
                    <span className="text-xs text-gray-400"></span>
                  </div>
                  <div className="flex items-center gap-2 px-3 py-1 bg-[#1A1B26] rounded-full border border-gray-800">
                    <Globe className="w-3 h-3 text-green-500" />
                    <span className="text-xs text-gray-400"></span>
                  </div>
                </div>
              </div>

              <div className="relative">
                <div className="bg-[#13141C] rounded-2xl p-8 border border-gray-900">
                  <div className="grid grid-cols-2 gap-6">
                    <div className="bg-[#1A1B26] rounded-xl p-4 border border-gray-800 hover:border-pink-500/50 transition-all cursor-pointer">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="w-8 h-8 bg-pink-500/20 rounded-lg flex items-center justify-center">
                          <Server className="w-4 h-4 text-pink-500" />
                        </div>
                        <span className="text-sm font-medium">project_name</span>
                      </div>
                      <div className="text-xs text-gray-500">production</div>
                    </div>

                    <div className="bg-[#1A1B26] rounded-xl p-4 border border-gray-800 hover:border-purple-500/50 transition-all cursor-pointer">
                      <div className="flex items-center gap-3 mb-3">
                        <div className="w-8 h-8 bg-purple-500/20 rounded-lg flex items-center justify-center">
                          <Database className="w-4 h-4 text-purple-500" />
                        </div>
                        <span className="text-sm font-medium">production</span>
                      </div>
                      <div className="text-xs text-gray-500"></div>
                    </div>
                  </div>

                  <div className="mt-6 space-y-3">
                    <div className="flex items-center justify-between px-4 py-3 bg-[#1A1B26] rounded-lg">
                      <span className="text-xs text-gray-400">Architecture</span>
                      <span className="text-xs text-white">Observability</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-3 bg-[#1A1B26] rounded-lg">
                      <span className="text-xs text-gray-400">Logs</span>
                      <span className="text-xs text-white">Settings</span>
                    </div>
                    <div className="flex items-center justify-between px-4 py-3 bg-[#1A1B26] rounded-lg">
                      <span className="text-xs text-gray-400">Share</span>
                      <span className="text-xs text-white">▶</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>

      <div className="fixed bottom-8 left-1/2 transform -translate-x-1/2 z-50">
        <div className="flex items-center gap-4 px-6 py-3 bg-[#1A1B26]/80 backdrop-blur-lg rounded-full border border-gray-800">
          <div className="flex gap-2">
            <div className="w-2 h-2 bg-pink-500 rounded-full animate-pulse"></div>
            <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse animation-delay-200"></div>
            <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse animation-delay-400"></div>
          </div>
        </div>
      </div>

      <style jsx>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        .animation-delay-200 {
          animation-delay: 200ms;
        }
        .animation-delay-400 {
          animation-delay: 400ms;
        }
      `}</style>
    </div>
  );
};

export default Projects;