import React, { useEffect, useRef, useState } from 'react';
import { ChevronRight, Globe, Database, Server, Activity, GitBranch, Terminal } from 'lucide-react';

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
        const scrollProgress = Math.max(0, Math.min(1, relativeScroll / sectionHeight));
        
        setScrollY(window.scrollY);
        setRocketPosition(scrollProgress * 100);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const techLogos = [
    { name: 'Docker', icon: '/images/icons/docker.png' },
    { name: 'Amazon ECS', icon: '/images/icons/amazon-ecs.png' },
    { name: 'Datadog', icon: '/images/icons/datalog.png' },
    { name: 'BetterStack', icon: '/images/icons/betterstack.png' },
    { name: 'Kubernetes', icon: '/images/icons/kubernetes.png' },
    { name: 'Nomad', icon: '/images/icons/nomad.png' },
    { name: 'Sentry', icon: '/images/icons/sentry.png' }
  ];

  return (
    <div ref={sectionRef} className="relative min-h-screen bg-black overflow-hidden">
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-b from-black via-gray-950 to-black"></div>
        <div 
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, rgb(148 163 184 / 0.15) 1px, transparent 1px)`,
            backgroundSize: '24px 24px',
            backgroundPosition: `${scrollY * 0.1}px ${scrollY * 0.1}px`
          }}
        ></div>
      </div>

      <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 1 }}>
        <defs>
          <linearGradient id="pipeGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#8B5CF6" stopOpacity="0.8">
              <animate attributeName="stopOpacity" values="0.8;1;0.8" dur="3s" repeatCount="indefinite" />
            </stop>
            <stop offset="50%" stopColor="#3B82F6" stopOpacity="1">
              <animate attributeName="stopOpacity" values="1;0.8;1" dur="3s" repeatCount="indefinite" />
            </stop>
            <stop offset="100%" stopColor="#8B5CF6" stopOpacity="0.8">
              <animate attributeName="stopOpacity" values="0.8;1;0.8" dur="3s" repeatCount="indefinite" />
            </stop>
          </linearGradient>
          
          <filter id="glow">
            <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>

          <filter id="pulseGlow">
            <feGaussianBlur stdDeviation="2">
              <animate attributeName="stdDeviation" values="2;4;2" dur="2s" repeatCount="indefinite" />
            </feGaussianBlur>
          </filter>
        </defs>

        <path
          d="M 150 0 L 150 300 Q 150 350 200 350 L 400 350"
          stroke="url(#pipeGradient)"
          strokeWidth="3"
          fill="none"
          filter="url(#glow)"
          strokeDasharray="0"
        >
          <animate attributeName="stroke-dasharray" from="0 1000" to="1000 0" dur="3s" repeatCount="indefinite" />
        </path>

        <path
          d="M 1200 100 L 1200 400 Q 1200 450 1150 450 L 800 450"
          stroke="url(#pipeGradient)"
          strokeWidth="3"
          fill="none"
          filter="url(#glow)"
        />

        <circle cx="150" cy="200" r="6" fill="#8B5CF6" filter="url(#pulseGlow)">
          <animate attributeName="r" values="6;8;6" dur="2s" repeatCount="indefinite" />
        </circle>
        
        <circle cx="150" cy="300" r="6" fill="#3B82F6" filter="url(#pulseGlow)">
          <animate attributeName="r" values="6;8;6" dur="2.5s" repeatCount="indefinite" />
        </circle>

        <circle cx="1200" cy="250" r="6" fill="#8B5CF6" filter="url(#pulseGlow)">
          <animate attributeName="r" values="6;8;6" dur="2s" repeatCount="indefinite" />
        </circle>

        <g transform={`translate(150, ${100 + rocketPosition * 2})`}>
          <circle cx="0" cy="0" r="4" fill="#FFD700">
            <animate attributeName="opacity" values="1;0.6;1" dur="1s" repeatCount="indefinite" />
          </circle>
          <path d="M -2 -6 L 2 -6 L 3 0 L 0 3 L -3 0 Z" fill="#FFD700" />
        </g>
      </svg>

      <div className="relative z-10 max-w-7xl mx-auto px-8 py-24">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16">
          <div className="flex flex-col justify-center space-y-6">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></div>
              <span className="text-purple-400 text-sm font-medium tracking-wide">AI Integration, Governance, Securty and Compliance</span>
            </div>

            <h2 className="text-5xl font-bold text-white leading-tight">
              Integrate AI into your business with Exoper Zero Trust Security API Gateway
            </h2>

            <p className="text-gray-400 text-lg leading-relaxed">
              Route all AI traffic through EXOPER's security gateway. Block threats in real-time. Stay compliant with EU AI Act, GDPR, and HIPAA. Audit every decision.
            </p>

            <div className="flex items-center space-x-2 text-white hover:text-purple-400 transition-colors cursor-pointer group">
              <span className="text-lg font-medium">Learn More</span>
              <ChevronRight className="w-5 h-5 transform group-hover:translate-x-1 transition-transform" />
            </div>

            <div className="pt-8 border-t border-gray-800">
              <div className="flex items-center space-x-4">
                <span className="text-gray-500 text-sm">Replaces</span>
                {techLogos.map((logo, index) => (
                  <div
                    key={index}
                    className="w-8 h-8 rounded bg-gray-800/50 flex items-center justify-center transform hover:scale-110 transition-transform border border-gray-700/50"
                  >
                    <img 
                      src={logo.icon} 
                      alt={logo.name}
                      className="w-5 h-5 object-contain opacity-60 hover:opacity-100 transition-opacity"
                    />
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="relative">
            <div className="absolute -inset-4 bg-gradient-to-r from-purple-600/10 to-blue-600/10 rounded-lg blur-xl"></div>
            
            <div className="relative space-y-8">
              <div className="absolute top-20 left-20 w-64 h-0.5 bg-gradient-to-r from-transparent via-blue-500/50 to-transparent">
                <div className="absolute -top-1 left-0 w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
              </div>
              <div className="absolute top-40 right-20 w-48 h-0.5 bg-gradient-to-r from-transparent via-purple-500/50 to-transparent rotate-45"></div>

              <div className="bg-gray-900/80 backdrop-blur-sm rounded-lg p-4 border border-gray-800 hover:border-purple-500/50 transition-all duration-300 transform hover:-translate-y-1">
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-yellow-500/20 rounded flex items-center justify-center">
                      <span className="text-yellow-500 text-sm font-bold">JS</span>
                    </div>
                    <div>
                      <div className="text-white font-medium">frontend</div>
                      <div className="text-purple-400 text-xs">frontend-prod.Exoper.app</div>
                    </div>
                  </div>
                </div>
                <div className="mt-3 flex items-center space-x-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-gray-400 text-xs">Modern UI to run and beta-test LLMs Models before inetgration. Deploy With our UI let's handle all interactions</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-900/80 backdrop-blur-sm rounded-lg p-4 border border-gray-800 hover:border-blue-500/50 transition-all duration-300">
                  <div className="flex items-center space-x-3 mb-3">
                    <Activity className="w-6 h-6 text-purple-500" />
                    <div>
                      <div className="text-white font-medium text-sm">Analytics, Monitoring and Logging</div>
                      <div className="text-purple-400 text-xs">exope-prod.Exoper.app</div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-gray-400 text-xs">Monitor allrequests and Analyze performance in real-time</span>
                  </div>
                </div>

                <div className="bg-gray-900/80 backdrop-blur-sm rounded-lg p-4 border border-gray-800 hover:border-blue-500/50 transition-all duration-300">
                  <div className="flex items-center space-x-3 mb-3">
                    <Globe className="w-6 h-6 text-blue-500" />
                    <div>
                      <div className="text-white font-medium text-sm">api gateway</div>
                      <div className="text-purple-400 text-xs">api-prod.Exoper.app</div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-gray-400 text-xs">Guard LLMs with our Zero Trust security API gateway</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-900/80 backdrop-blur-sm rounded-lg p-4 border border-gray-800 hover:border-purple-500/50 transition-all duration-300">
                  <div className="flex items-center space-x-3 mb-3">
                    <Server className="w-6 h-6 text-orange-500" />
                    <div className="text-white font-medium text-sm">backend</div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-gray-400 text-xs">Deploy our AI infrastructure with blazing ease</span>
                  </div>
                </div>

                <div className="bg-gray-900/80 backdrop-blur-sm rounded-lg p-4 border border-gray-800 hover:border-blue-500/50 transition-all duration-300">
                  <div className="flex items-center space-x-3 mb-3">
                    <Database className="w-6 h-6 text-blue-400" />
                    <div>
                      <div className="text-white font-medium text-sm">Milvus</div>
                      <div className="text-gray-500 text-xs">BlockChain Transaction</div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-gray-400 text-xs">Store and Encrypt all data going-in and out AI models</span>
                  </div>
                </div>
              </div>

              <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: -1 }}>
                <path d="M 100 50 Q 150 80 200 80" stroke="#3B82F6" strokeWidth="1" fill="none" strokeDasharray="5,5" opacity="0.3">
                  <animate attributeName="stroke-dashoffset" from="0" to="10" dur="1s" repeatCount="indefinite" />
                </path>
                <path d="M 300 100 L 300 150" stroke="#8B5CF6" strokeWidth="1" fill="none" strokeDasharray="5,5" opacity="0.3">
                  <animate attributeName="stroke-dashoffset" from="0" to="10" dur="1s" repeatCount="indefinite" />
                </path>
                <path d="M 100 180 Q 150 200 200 180" stroke="#3B82F6" strokeWidth="1" fill="none" strokeDasharray="5,5" opacity="0.3">
                  <animate attributeName="stroke-dashoffset" from="0" to="10" dur="1s" repeatCount="indefinite" />
                </path>
              </svg>
            </div>
          </div>
        </div>

        <div className="mt-32 relative">
          <div className="absolute -left-8 top-0 w-96 h-px bg-gradient-to-r from-transparent via-blue-500/50 to-transparent"></div>
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mt-16">
            <div className="bg-gray-900/60 backdrop-blur-sm rounded-lg p-6 border border-gray-800 hover:border-yellow-500/50 transition-all duration-300">
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-3">
                  <Server className="w-6 h-6 text-yellow-500" />
                  <div>
                    <div className="text-white font-medium">backend [US-West]</div>
                    <div className="text-gray-400 text-sm mt-1 flex items-center space-x-2">
                      <GitBranch className="w-4 h-4" />
                      <span>Just deployed via GitHub</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-gray-900/60 backdrop-blur-sm rounded-lg p-6 border border-gray-800 hover:border-blue-500/50 transition-all duration-300">
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-3">
                  <Server className="w-6 h-6 text-blue-500" />
                  <div>
                    <div className="text-white font-medium">backend [EU]</div>
                    <div className="text-gray-400 text-sm mt-1 flex items-center space-x-2">
                      <Terminal className="w-4 h-4" />
                      <span>Just deployed via CLI</span>
                    </div>
                  </div>
                </div>
                <div className="bg-purple-600/20 text-purple-400 px-3 py-1 rounded text-sm font-bold">
                  16x CPU
                </div>
              </div>
            </div>
          </div>
        </div>
        </div>
    </div>
  );
};

export default Projects;