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

  return (
    <div ref={containerRef} className="min-h-screen bg-[#0b0b10] text-white overflow-hidden relative" style={{fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto"}}>
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -left-24 -top-24 w-80 h-80 rounded-full" style={{background: "radial-gradient(closest-side, rgba(139,92,246,0.12), rgba(139,92,246,0.02))", filter: "blur(48px)"}} />
        <div className="absolute right-[-6rem] top-24 w-72 h-72 rounded-full" style={{background: "radial-gradient(closest-side, rgba(168,85,247,0.08), rgba(168,85,247,0.01))", filter: "blur(44px)"}} />
        <div className="absolute left-1/2 bottom-24 w-96 h-96 rounded-full" style={{background: "radial-gradient(closest-side, rgba(139,92,246,0.1), rgba(139,92,246,0.01))", filter: "blur(52px)"}} />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 sm:py-20 lg:py-24">
        <section className="relative z-10 mb-16 lg:mb-24 text-center">
          <div className="max-w-3xl mx-auto">
            <div className="text-sm text-purple-400 mb-4 tracking-wide font-medium uppercase">Network and Connect</div>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold mb-6 leading-tight">
              Interconnect your application seamlessly with highly performant networking
            </h1>
            <p className="text-gray-400 text-base sm:text-lg lg:text-xl mb-8 leading-relaxed">
              Exoper provides automated service discovery, blazing fast networking, and support for any protocol, all out of the box.
            </p>
            <button className="inline-flex items-center gap-2 text-purple-400 hover:text-purple-300 transition-colors font-medium">
              Learn More <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </section>

        <section className="relative z-10 mb-16 lg:mb-24">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8">
            <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 lg:p-8 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)] hover:border-[#8b5cf6]/50 transition-all duration-300">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2.5 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30">
                  <GitBranch className="w-5 h-5 text-purple-400" />
                </div>
                <span className="text-base text-gray-300 font-semibold">Replicas</span>
              </div>
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-400">Auto-scaling enabled</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-400">Load balanced</span>
                </div>
              </div>
            </div>

            <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 lg:p-8 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)] hover:border-[#8b5cf6]/50 transition-all duration-300">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2.5 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30">
                  <Database className="w-5 h-5 text-purple-400" />
                </div>
                <span className="text-base text-gray-300 font-semibold">Database</span>
              </div>
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-400">PostgreSQL 15</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-400">Auto-backups</span>
                </div>
              </div>
            </div>

            <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 lg:p-8 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)] hover:border-[#8b5cf6]/50 transition-all duration-300 md:col-span-2 lg:col-span-1">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-2.5 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30">
                  <Globe className="w-5 h-5 text-purple-400" />
                </div>
                <span className="text-base text-gray-300 font-semibold">Network</span>
              </div>
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-400">Private network</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse"></div>
                  <span className="text-sm text-gray-400">Service mesh</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="relative z-10 mb-16 lg:mb-24 flex justify-center">
          <div className="w-full max-w-2xl">
            <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 lg:p-8 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)]">
              <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 mb-6">
                <div className="p-3 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30">
                  <Server className="w-6 h-6 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-white">backend [US-West]</h3>
                  <p className="text-sm text-gray-400">Just deployed via GitHub</p>
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 bg-[#0b0b10]/60 rounded-xl border border-[#222631] gap-3 sm:gap-0">
                  <span className="text-sm text-gray-400 font-semibold">CPU</span>
                  <div className="flex items-center gap-3">
                    <div className="w-32 sm:w-40 h-2.5 bg-gray-700/50 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-[#8b5cf6] to-[#a855f7] rounded-full" style={{width: '65%'}}>
                        <div className="h-full bg-white/20 animate-pulse"></div>
                      </div>
                    </div>
                    <span className="text-sm font-mono text-gray-300 min-w-[3rem]">16x</span>
                  </div>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between p-4 bg-[#0b0b10]/60 rounded-xl border border-[#222631] gap-3 sm:gap-0">
                  <span className="text-sm text-gray-400 font-semibold">Memory</span>
                  <div className="flex items-center gap-3">
                    <div className="w-32 sm:w-40 h-2.5 bg-gray-700/50 rounded-full overflow-hidden">
                      <div className="h-full bg-gradient-to-r from-[#8b5cf6] to-[#a855f7] rounded-full" style={{width: '45%'}}>
                        <div className="h-full bg-white/20 animate-pulse"></div>
                      </div>
                    </div>
                    <span className="text-sm font-mono text-gray-300 min-w-[3rem]">8GB</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="relative z-10 mb-16 lg:mb-24">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 lg:gap-8">
            <div className="space-y-6">
              <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 lg:p-8 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)] hover:border-[#8b5cf6]/50 transition-all duration-300">
                <div className="flex items-center gap-4 mb-6">
                  <div className="p-3 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30">
                    <Cloud className="w-6 h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white">frontend</h3>
                </div>
                
                <div className="bg-[#0b0b10]/60 rounded-xl p-4 mb-4 border border-[#222631]">
                  <div className="flex items-center gap-2 mb-2">
                    <Activity className="w-4 h-4 text-green-400" />
                    <span className="text-sm text-gray-400 break-all">frontend-prod.Exoper.app</span>
                  </div>
                  <button className="text-sm text-purple-400 hover:text-purple-300 transition-colors font-medium">
                    Just deployed
                  </button>
                </div>
              </div>

              <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 lg:p-8 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)] hover:border-[#8b5cf6]/50 transition-all duration-300">
                <div className="flex items-center gap-4 mb-6">
                  <div className="p-3 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30">
                    <Database className="w-6 h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white">backend</h3>
                </div>
                
                <div className="bg-[#0b0b10]/60 rounded-xl p-4 border border-[#222631]">
                  <div className="flex items-center gap-2 mb-2">
                    <Terminal className="w-4 h-4 text-blue-400" />
                    <span className="text-sm text-gray-400">Just deployed</span>
                  </div>
                  <button className="text-sm text-purple-400 hover:text-purple-300 transition-colors font-medium">
                    Just deployed
                  </button>
                </div>
              </div>
            </div>

            <div className="space-y-6">
              <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 lg:p-8 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)] hover:border-[#8b5cf6]/50 transition-all duration-300">
                <div className="flex items-center gap-4 mb-6">
                  <div className="p-3 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30">
                    <Shield className="w-6 h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white">api gateway</h3>
                </div>
                
                <div className="bg-[#0b0b10]/60 rounded-xl p-4 mb-4 border border-[#222631]">
                  <div className="flex items-center gap-2 mb-2">
                    <Lock className="w-4 h-4 text-yellow-400" />
                    <span className="text-sm text-gray-400 break-all">api-prod.Exoper.app</span>
                  </div>
                  <button className="text-sm text-purple-400 hover:text-purple-300 transition-colors font-medium">
                    Just deployed
                  </button>
                </div>
              </div>

              <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 lg:p-8 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)] hover:border-[#8b5cf6]/50 transition-all duration-300">
                <div className="flex items-center gap-4 mb-6">
                  <div className="p-3 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30">
                    <Layers className="w-6 h-6 text-purple-400" />
                  </div>
                  <h3 className="text-xl font-semibold text-white">postgres</h3>
                </div>
                
                <div className="bg-[#0b0b10]/60 rounded-xl p-4 border border-[#222631]">
                  <div className="flex items-center gap-2 mb-2">
                    <Cpu className="w-4 h-4 text-green-400" />
                    <span className="text-sm text-gray-400">Just deployed</span>
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