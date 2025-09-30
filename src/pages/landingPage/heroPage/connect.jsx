import React, { useEffect, useRef, useState } from 'react';
import { ChevronRight, Globe, Database, Server, Activity, GitBranch, Terminal, Zap, Box, Layers } from 'lucide-react';

const Projects = () => {
  const [scrollY, setScrollY] = useState(0);
  const [rocketPosition, setRocketPosition] = useState(0);
  const sectionRef = useRef(null);

  useEffect(() => {
    const handleScroll = () => {
      if (sectionRef.current) {
        const rect = sectionRef.current.getBoundingClientRect();
        const sectionTop = window.scrollY + rect.top;
        const sectionHeight = rect.height;
        const relativeScroll = window.scrollY - sectionTop;
        const scrollProgress = Math.max(0, Math.min(1, (relativeScroll + window.innerHeight/2) / (sectionHeight + window.innerHeight)));
        
        setScrollY(window.scrollY);
        setRocketPosition(scrollProgress);
      }
    };

    window.addEventListener('scroll', handleScroll);
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <div ref={sectionRef} className="relative bg-black overflow-hidden">
      <div className="absolute inset-0">
        <div 
          className="absolute inset-0 opacity-30"
          style={{
            backgroundImage: `radial-gradient(circle at 2px 2px, rgb(59 130 246 / 0.15) 1px, transparent 1px)`,
            backgroundSize: '40px 40px',
            backgroundPosition: `${scrollY * 0.05}px ${scrollY * 0.05}px`
          }}
        ></div>
      </div>

      <svg className="absolute left-0 top-0 w-full h-full pointer-events-none" style={{ height: '200%', zIndex: 2 }}>
        <defs>
          <linearGradient id="purplePipe" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#a855f7" stopOpacity="0.6"/>
            <stop offset="50%" stopColor="#8b5cf6" stopOpacity="0.8"/>
            <stop offset="100%" stopColor="#7c3aed" stopOpacity="0.6"/>
          </linearGradient>
          
          <linearGradient id="bluePipe" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.4"/>
            <stop offset="50%" stopColor="#60a5fa" stopOpacity="0.8"/>
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.4"/>
          </linearGradient>

          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>

          <filter id="strongGlow">
            <feGaussianBlur stdDeviation="6" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>

        <path
          d="M 320 -50 L 320 250 L 320 450 Q 320 480 350 480 L 500 480 Q 530 480 530 510 L 530 800 Q 530 830 560 830 L 700 830"
          stroke="url(#purplePipe)"
          strokeWidth="4"
          fill="none"
          filter="url(#glow)"
          opacity="0.9"
        />

        <circle cx="320" cy="200" r="8" fill="#a855f7" filter="url(#strongGlow)">
          <animate attributeName="opacity" values="0.6;1;0.6" dur="2s" repeatCount="indefinite" />
        </circle>
        
        <circle cx="320" cy="350" r="6" fill="#8b5cf6" filter="url(#glow)">
          <animate attributeName="opacity" values="0.8;1;0.8" dur="2.5s" repeatCount="indefinite" />
        </circle>

        <circle cx="480" cy="480" r="10" fill="#7c3aed" filter="url(#strongGlow)">
          <animate attributeName="r" values="10;12;10" dur="3s" repeatCount="indefinite" />
        </circle>

        <circle cx="530" cy="650" r="8" fill="#8b5cf6" filter="url(#glow)">
          <animate attributeName="opacity" values="0.6;1;0.6" dur="2s" repeatCount="indefinite" />
        </circle>

        <g transform={`translate(320, ${100 + rocketPosition * 600})`}>
          <g className="rocket">
            <circle cx="0" cy="0" r="12" fill="rgba(168, 85, 247, 0.2)" filter="url(#strongGlow)">
              <animate attributeName="r" values="12;16;12" dur="1s" repeatCount="indefinite" />
            </circle>
            <rect x="-4" y="-8" width="8" height="12" rx="2" fill="#fbbf24" />
            <path d="M 0 -8 L -4 4 L 0 2 L 4 4 Z" fill="#f59e0b" />
            <rect x="-2" y="4" width="4" height="4" fill="#ef4444" opacity="0.8">
              <animate attributeName="height" values="4;6;4" dur="0.3s" repeatCount="indefinite" />
            </rect>
          </g>
        </g>

        <path
          d="M 700 830 Q 730 830 730 800 L 730 650"
          stroke="url(#bluePipe)"
          strokeWidth="3"
          fill="none"
          filter="url(#glow)"
          opacity="0.7"
        />
      </svg>

      <div className="relative z-10 container max-w-7xl mx-auto px-8 py-32">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-24 items-center">
          <div className="space-y-8">
            <div className="inline-flex items-center space-x-2">
              <div className="w-2 h-2 bg-purple-500 rounded-full">
                <div className="w-2 h-2 bg-purple-500 rounded-full animate-ping"></div>
              </div>
              <span className="text-purple-400 text-sm font-medium uppercase tracking-wider">Network and Connect</span>
            </div>

            <h1 className="text-5xl lg:text-6xl font-bold text-white leading-tight">
              Interconnect your application<br />
              seamlessly with highly<br />
              performant networking
            </h1>

            <p className="text-gray-400 text-lg leading-relaxed max-w-lg">
              Railway provides automated service discovery, blazing fast networking, and support for any protocol, all out of the box.
            </p>

            <button className="inline-flex items-center space-x-2 text-white hover:text-purple-400 transition-colors group">
              <span className="text-lg font-medium">Learn More</span>
              <ChevronRight className="w-5 h-5 transform group-hover:translate-x-1 transition-transform" />
            </button>

            <div className="pt-8 border-t border-gray-800/50">
              <div className="flex items-center space-x-4">
                <span className="text-gray-500 text-xs uppercase tracking-wider">Replaces</span>
                <div className="flex items-center space-x-2">
                  <div className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center hover:border-gray-500 transition-colors">
                    <span className="text-[10px] text-gray-400">⚡</span>
                  </div>
                  <div className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center hover:border-green-500/50 transition-colors">
                    <span className="text-[10px] text-green-500">N</span>
                  </div>
                  <div className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center hover:border-blue-500/50 transition-colors">
                    <span className="text-[10px] text-blue-500">K</span>
                  </div>
                  <div className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center hover:border-blue-400/50 transition-colors">
                    <span className="text-[10px] text-blue-400">D</span>
                  </div>
                  <div className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center hover:border-orange-500/50 transition-colors">
                    <span className="text-[10px] text-orange-500">A</span>
                  </div>
                  <div className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center hover:border-purple-500/50 transition-colors">
                    <span className="text-[10px] text-purple-500">T</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="relative">
            <div className="absolute -inset-8 bg-gradient-to-r from-purple-600/5 via-blue-600/5 to-purple-600/5 rounded-3xl blur-3xl"></div>
            
            <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 500 600" style={{ zIndex: 1 }}>
              <path d="M 120 80 Q 200 80 250 120" stroke="#3b82f6" strokeWidth="2" fill="none" strokeDasharray="4,4" opacity="0.4">
                <animate attributeName="stroke-dashoffset" from="0" to="8" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M 250 120 L 250 200" stroke="#8b5cf6" strokeWidth="2" fill="none" strokeDasharray="4,4" opacity="0.4">
                <animate attributeName="stroke-dashoffset" from="0" to="8" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M 120 280 Q 180 280 250 240" stroke="#3b82f6" strokeWidth="2" fill="none" strokeDasharray="4,4" opacity="0.4">
                <animate attributeName="stroke-dashoffset" from="0" to="8" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M 380 280 Q 320 280 250 240" stroke="#8b5cf6" strokeWidth="2" fill="none" strokeDasharray="4,4" opacity="0.4">
                <animate attributeName="stroke-dashoffset" from="0" to="8" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M 250 240 L 250 320" stroke="#a855f7" strokeWidth="2" fill="none" strokeDasharray="4,4" opacity="0.4">
                <animate attributeName="stroke-dashoffset" from="0" to="8" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M 120 400 Q 180 380 250 360" stroke="#3b82f6" strokeWidth="2" fill="none" strokeDasharray="4,4" opacity="0.4">
                <animate attributeName="stroke-dashoffset" from="0" to="8" dur="2s" repeatCount="indefinite" />
              </path>
              <path d="M 380 400 Q 320 380 250 360" stroke="#8b5cf6" strokeWidth="2" fill="none" strokeDasharray="4,4" opacity="0.4">
                <animate attributeName="stroke-dashoffset" from="0" to="8" dur="2s" repeatCount="indefinite" />
              </path>
            </svg>

            <div className="relative space-y-6" style={{ zIndex: 2 }}>
              <div className="bg-gray-900/90 backdrop-blur-xl rounded-xl p-5 border border-gray-800 hover:border-purple-500/30 transition-all duration-300 transform hover:scale-[1.02]">
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 bg-yellow-500/10 rounded-lg flex items-center justify-center">
                      <span className="text-yellow-500 font-bold text-sm">JS</span>
                    </div>
                    <div>
                      <div className="text-white font-semibold">frontend</div>
                      <div className="text-purple-400 text-xs mt-0.5">frontend-prod.up.railway.app</div>
                    </div>
                  </div>
                </div>
                <div className="mt-4 flex items-center space-x-2">
                  <div className="w-1.5 h-1.5 bg-green-500 rounded-full">
                    <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-ping"></div>
                  </div>
                  <span className="text-gray-500 text-xs">Just deployed</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-900/90 backdrop-blur-xl rounded-xl p-4 border border-gray-800 hover:border-purple-500/30 transition-all duration-300 transform hover:scale-[1.02]">
                  <div className="flex items-center space-x-3">
                    <div className="w-9 h-9 bg-purple-500/10 rounded-lg flex items-center justify-center">
                      <Activity className="w-5 h-5 text-purple-500" />
                    </div>
                    <div className="flex-1">
                      <div className="text-white font-medium text-sm">ackee analytics</div>
                      <div className="text-purple-400 text-[11px] mt-0.5 truncate">ackee-prod.up.railway.app</div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center space-x-2">
                    <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-gray-500 text-xs">Just deployed</span>
                  </div>
                </div>

                <div className="bg-gray-900/90 backdrop-blur-xl rounded-xl p-4 border border-gray-800 hover:border-blue-500/30 transition-all duration-300 transform hover:scale-[1.02]">
                  <div className="flex items-center space-x-3">
                    <div className="w-9 h-9 bg-blue-500/10 rounded-lg flex items-center justify-center">
                      <Globe className="w-5 h-5 text-blue-500" />
                    </div>
                    <div className="flex-1">
                      <div className="text-white font-medium text-sm">api gateway</div>
                      <div className="text-purple-400 text-[11px] mt-0.5 truncate">api-prod.up.railway.app</div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center space-x-2">
                    <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-gray-500 text-xs">Just deployed</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-900/90 backdrop-blur-xl rounded-xl p-4 border border-gray-800 hover:border-orange-500/30 transition-all duration-300 transform hover:scale-[1.02]">
                  <div className="flex items-center space-x-3">
                    <div className="w-9 h-9 bg-orange-500/10 rounded-lg flex items-center justify-center">
                      <Layers className="w-5 h-5 text-orange-500" />
                    </div>
                    <div>
                      <div className="text-white font-medium text-sm">backend</div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center space-x-2">
                    <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-gray-500 text-xs">Just deployed</span>
                  </div>
                </div>

                <div className="bg-gray-900/90 backdrop-blur-xl rounded-xl p-4 border border-gray-800 hover:border-blue-500/30 transition-all duration-300 transform hover:scale-[1.02]">
                  <div className="flex items-center space-x-3">
                    <div className="w-9 h-9 bg-blue-400/10 rounded-lg flex items-center justify-center">
                      <Database className="w-5 h-5 text-blue-400" />
                    </div>
                    <div>
                      <div className="text-white font-medium text-sm">postgres</div>
                      <div className="text-gray-500 text-[11px] mt-0.5">pg-data</div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center space-x-2">
                    <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-gray-500 text-xs">Just deployed</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="relative z-10 container max-w-7xl mx-auto px-8 pb-32">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-gray-900/80 backdrop-blur-xl rounded-xl p-6 border border-gray-800 hover:border-yellow-500/30 transition-all duration-300">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-4">
                <div className="w-10 h-10 bg-yellow-500/10 rounded-lg flex items-center justify-center">
                  <Box className="w-5 h-5 text-yellow-500" />
                </div>
                <div>
                  <div className="text-white font-semibold text-lg">backend [US-West]</div>
                  <div className="text-gray-400 text-sm mt-1 flex items-center space-x-2">
                    <GitBranch className="w-4 h-4 text-gray-500" />
                    <span>Just deployed via GitHub</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-gray-900/80 backdrop-blur-xl rounded-xl p-6 border border-gray-800 hover:border-blue-500/30 transition-all duration-300">
            <div className="flex items-start justify-between">
              <div className="flex items-center space-x-4">
                <div className="w-10 h-10 bg-blue-500/10 rounded-lg flex items-center justify-center">
                  <Zap className="w-5 h-5 text-blue-500" />
                </div>
                <div>
                  <div className="text-white font-semibold text-lg">backend [EU]</div>
                  <div className="text-gray-400 text-sm mt-1 flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-gray-500" />
                    <span>Just deployed via CLI</span>
                  </div>
                </div>
              </div>
              <div className="bg-purple-600/20 border border-purple-600/30 text-purple-400 px-3 py-1.5 rounded-lg text-sm font-bold">
                16x<br/>CPU
              </div>
            </div>
          </div>
        </div>

        <div className="mt-32 text-center">
          <div className="inline-flex items-center space-x-2 mb-8">
            <div className="w-2 h-2 bg-blue-500 rounded-full">
              <div className="w-2 h-2 bg-blue-500 rounded-full animate-ping"></div>
            </div>
            <span className="text-blue-400 text-sm font-medium uppercase tracking-wider">Scale and Grow</span>
          </div>
          <h2 className="text-5xl lg:text-6xl font-bold text-white">
            Scale your applications with intuitive
          </h2>
        </div>
      </div>
    </div>
  );
};

export default Projects;