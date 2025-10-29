import React, { useState, useEffect, useRef } from 'react';
import { ChevronRight, GitBranch, Database, Globe, Shield, Server, Cloud, Lock, Activity, Terminal, Layers, Cpu } from 'lucide-react';

const Projects = () => {
  const [scrollProgress, setScrollProgress] = useState(0);
  const [activeSection, setActiveSection] = useState(0);
  const containerRef = useRef(null);

  useEffect(() => {
    const handleScroll = () => {
      if (containerRef.current) {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const docHeight = document.documentElement.scrollHeight - window.innerHeight;
        const progress = Math.min(scrollTop / docHeight, 1);
        setScrollProgress(progress);
        
        const sectionIndex = Math.floor(progress * 4);
        setActiveSection(sectionIndex);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const rocketPosition = scrollProgress * 100;

  return (
    <div ref={containerRef} className="min-h-screen bg-[#0a0b14] text-white overflow-hidden relative">
      <div className="absolute inset-0 pointer-events-none">
        <svg className="absolute inset-0 w-full h-full" style={{ height: '200vh' }}>
          <defs>
            <linearGradient id="pipeGradient" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#8B5CF6" stopOpacity="0.35" />
              <stop offset="50%" stopColor="#3B82F6" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#8B5CF6" stopOpacity="0.35" />
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
            d="M 150 100 L 150 400 Q 150 450 200 450 L 600 450 Q 650 450 650 500 L 650 800"
            stroke="url(#pipeGradient)"
            strokeWidth="3"
            fill="none"
            filter="url(#glow)"
          />
          
          <path
            d="M 300 200 L 300 350 Q 300 400 350 400 L 700 400"
            stroke="url(#pipeGradient)"
            strokeWidth="3"
            fill="none"
            filter="url(#glow)"
          />
          
          <path
            d="M 500 150 L 500 600 Q 500 650 550 650 L 800 650"
            stroke="url(#pipeGradient)"
            strokeWidth="3"
            fill="none"
            filter="url(#glow)"
          />

          <g transform={`translate(150, ${100 + rocketPosition * 7})`}>
            <circle cx="0" cy="0" r="12" fill="#8B5CF6" opacity="0.3">
              <animate attributeName="r" values="12;15;12" dur="2s" repeatCount="indefinite"/>
            </circle>
            <polygon points="-6,-10 6,-10 8,5 0,12 -8,5" fill="#8B5CF6" filter="url(#glow)">
              <animateTransform attributeName="transform" type="rotate" from="0 0 0" to="360 0 0" dur="4s" repeatCount="indefinite"/>
            </polygon>
          </g>

          <g transform={`translate(${300 + rocketPosition * 4}, 350)`}>
            <circle cx="0" cy="0" r="10" fill="#3B82F6" opacity="0.3">
              <animate attributeName="r" values="10;13;10" dur="1.5s" repeatCount="indefinite"/>
            </circle>
            <polygon points="-5,-8 5,-8 7,4 0,10 -7,4" fill="#3B82F6" filter="url(#glow)">
              <animateTransform attributeName="transform" type="rotate" from="0 0 0" to="-360 0 0" dur="3s" repeatCount="indefinite"/>
            </polygon>
          </g>
        </svg>
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-20">
        <section className="relative z-10 mb-16 lg:mb-32 flex justify-center lg:justify-end">
          <div className="text-center lg:text-right max-w-2xl">
            <div className="text-sm text-purple-400 mb-4 tracking-wide font-medium">Network and Connect</div>
            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-6 leading-tight">
              Interconnect your application<br className="hidden sm:block" />
              seamlessly with highly<br className="hidden sm:block" />
              performant networking
            </h1>
            <p className="text-gray-300 text-base lg:text-lg mb-8 leading-relaxed">
              Exoper provides automated service discovery, blazing fast networking, and support for any protocol, all out of the box.
            </p>
            <button className="text-purple-400 hover:text-purple-300 transition-colors flex items-center gap-2 mx-auto lg:ml-auto lg:mr-0">
              Learn More <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </section>

        <section className="relative z-10 mb-16 lg:mb-32">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 lg:gap-8 mt-12 lg:mt-20">
            <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-4 lg:p-6 border border-[#2a2a2a] hover:border-purple-500/50 transition-all duration-200">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-purple-600/20 rounded-lg border border-purple-500/30">
                  <GitBranch className="w-4 h-4 lg:w-5 lg:h-5 text-purple-400" />
                </div>
                <span className="text-sm text-gray-400 font-medium">Replicas</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-300">Auto-scaling enabled</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-300">Load balanced</span>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-4 lg:p-6 border border-[#2a2a2a] hover:border-purple-500/50 transition-all duration-200">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-purple-600/20 rounded-lg border border-purple-500/30">
                  <Database className="w-4 h-4 lg:w-5 lg:h-5 text-purple-400" />
                </div>
                <span className="text-sm text-gray-400 font-medium">Database</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-300">PostgreSQL 15</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-300">Auto-backups</span>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-4 lg:p-6 border border-[#2a2a2a] hover:border-purple-500/50 transition-all duration-200 md:col-span-2 lg:col-span-1">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-purple-600/20 rounded-lg border border-purple-500/30">
                  <Globe className="w-4 h-4 lg:w-5 lg:h-5 text-purple-400" />
                </div>
                <span className="text-sm text-gray-400 font-medium">Network</span>
              </div>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-300">Private network</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-300">Service mesh</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="relative z-10 mb-16 lg:mb-32 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8 lg:gap-12">
          <div className="max-w-lg">
            <h2 className="text-3xl lg:text-4xl font-bold mb-6 leading-tight">
              Scale your applications with intuitive
            </h2>
          </div>

          <div className="relative w-full lg:w-auto">
            <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 lg:p-8 border border-[#2a2a2a]">
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6">
                <div className="p-3 bg-purple-600/20 rounded-lg border border-purple-500/30">
                  <Server className="w-5 h-5 lg:w-6 lg:h-6 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white">backend [US-West]</h3>
                  <p className="text-sm text-gray-400">Just deployed via GitHub</p>
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-[#1f1f1f] rounded-lg border border-[#2a2a2a] gap-2 sm:gap-0">
                  <span className="text-sm text-gray-400 font-medium">CPU</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 sm:w-32 h-2 bg-gray-700 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-purple-500 to-purple-400 rounded-full" style={{width: '65%'}}>
                        <div className="h-full bg-white/20 animate-pulse"></div>
                      </div>
                    </div>
                    <span className="text-sm font-mono text-gray-300">16x</span>
                  </div>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 bg-[#1f1f1f] rounded-lg border border-[#2a2a2a] gap-2 sm:gap-0">
                  <span className="text-sm text-gray-400 font-medium">Memory</span>
                  <div className="flex items-center gap-2">
                    <div className="w-24 sm:w-32 h-2 bg-gray-700 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-purple-500 to-purple-400 rounded-full" style={{width: '45%'}}>
                        <div className="h-full bg-white/20 animate-pulse"></div>
                      </div>
                    </div>
                    <span className="text-sm font-mono text-gray-300">8GB</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="relative z-10 mb-16 lg:mb-32">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-12 items-start">
            <div className="space-y-6">
              <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 lg:p-8 border border-[#2a2a2a] hover:border-purple-500/50 transition-all duration-200">
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6">
                  <div className="p-3 bg-purple-600/20 rounded-lg border border-purple-500/30">
                    <Cloud className="w-5 h-5 lg:w-6 lg:h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white">frontend</h3>
                </div>
                
                <div className="bg-[#1f1f1f] rounded-lg p-4 mb-4 border border-[#2a2a2a]">
                  <div className="flex items-center gap-2 mb-2">
                    <Activity className="w-4 h-4 text-green-400" />
                    <span className="text-sm text-gray-300 break-all">frontend-prod.Exoper.app</span>
                  </div>
                  <button className="text-sm text-purple-400 hover:text-purple-300 transition-colors">
                    Just deployed
                  </button>
                </div>
              </div>

              <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 lg:p-8 border border-[#2a2a2a] hover:border-purple-500/50 transition-all duration-200">
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6">
                  <div className="p-3 bg-purple-600/20 rounded-lg border border-purple-500/30">
                    <Database className="w-5 h-5 lg:w-6 lg:h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white">backend</h3>
                </div>
                
                <div className="bg-[#1f1f1f] rounded-lg p-4 border border-[#2a2a2a]">
                  <div className="flex items-center gap-2 mb-2">
                    <Terminal className="w-4 h-4 text-blue-400" />
                    <span className="text-sm text-gray-300">Just deployed</span>
                  </div>
                  <button className="text-sm text-purple-400 hover:text-purple-300 transition-colors">
                    Just deployed
                  </button>
                </div>
              </div>
            </div>

            <div className="space-y-6">
              <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 lg:p-8 border border-[#2a2a2a] hover:border-purple-500/50 transition-all duration-200">
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6">
                  <div className="p-3 bg-purple-600/20 rounded-lg border border-purple-500/30">
                    <Shield className="w-5 h-5 lg:w-6 lg:h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white">api gateway</h3>
                </div>
                
                <div className="bg-[#1f1f1f] rounded-lg p-4 mb-4 border border-[#2a2a2a]">
                  <div className="flex items-center gap-2 mb-2">
                    <Lock className="w-4 h-4 text-yellow-400" />
                    <span className="text-sm text-gray-300 break-all">api-prod.Exoper.app</span>
                  </div>
                  <button className="text-sm text-purple-400 hover:text-purple-300 transition-colors">
                    Just deployed
                  </button>
                </div>
              </div>

              <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 lg:p-8 border border-[#2a2a2a] hover:border-purple-500/50 transition-all duration-200">
                <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6">
                  <div className="p-3 bg-purple-600/20 rounded-lg border border-purple-500/30">
                    <Layers className="w-5 h-5 lg:w-6 lg:h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white">postgres</h3>
                </div>
                
                <div className="bg-[#1f1f1f] rounded-lg p-4 border border-[#2a2a2a]">
                  <div className="flex items-center gap-2 mb-2">
                    <Cpu className="w-4 h-4 text-green-400" />
                    <span className="text-sm text-gray-300">Just deployed</span>
                  </div>
                  <div className="text-xs text-gray-500 font-mono">
                    pg-data
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default Projects;

