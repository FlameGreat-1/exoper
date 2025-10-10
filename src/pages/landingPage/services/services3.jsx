import React, { useEffect, useRef, useState } from 'react';
import { ArrowRight, Database, HardDrive, Clock, FileText, Lock, Github, Terminal, Gauge, BarChart3, Workflow, Repeat, Shield } from 'lucide-react';
import { GlowingCards, GlowingCard } from '../../../components/ui/glowing-cards';

const Services3 = () => {
  const gridRef = useRef(null);
  const pipelineRef = useRef(null);
  const [pipelinePosition, setPipelinePosition] = useState(0);

  useEffect(() => {
    const cards = document.querySelectorAll('.server-mini-card');
    cards.forEach((card, index) => {
      card.style.animation = `float ${2 + index * 0.3}s ease-in-out infinite`;
      card.style.animationDelay = `${index * 0.2}s`;
    });

    if (gridRef.current) {
      gridRef.current.style.animation = 'rotateGrid 20s linear infinite';
    }

    let lastScrollY = window.scrollY;

    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      const scrollDelta = currentScrollY - lastScrollY;
      lastScrollY = currentScrollY;

      setPipelinePosition(prev => {
        const newPos = prev + scrollDelta * 0.5;
        return Math.max(-150, Math.min(50, newPos));
      });
    };

    window.addEventListener('scroll', handleScroll, { passive: true });

    return () => {
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white overflow-hidden">
      <style>{`
        @keyframes float {
          0%, 100% { transform: translateY(0px) scale(1); }
          50% { transform: translateY(-5px) scale(1.05); }
        }
        @keyframes pulse-glow {
          0%, 100% { opacity: 0.5; }
          50% { opacity: 1; }
        }
        @keyframes rotateGrid {
          0% { transform: rotateX(60deg) rotateZ(-45deg) rotateY(0deg); }
          100% { transform: rotateX(60deg) rotateZ(-45deg) rotateY(360deg); }
        }
        @keyframes spark {
          0% { transform: scale(0); opacity: 1; }
          50% { transform: scale(1.5); opacity: 0.5; }
          100% { transform: scale(0); opacity: 0; }
        }
        .server-mini-card {
          transition: all 0.3s ease;
        }
        .glowing-cards-container {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 1.5rem;
        }
        @media (min-width: 768px) {
          .glowing-cards-container {
            grid-template-columns: repeat(2, 1fr);
          }
        }
        @media (min-width: 1024px) {
          .glowing-cards-container {
            grid-template-columns: repeat(3, 1fr);
          }
        }
        .equal-card {
          display: flex;
          flex-direction: column;
          height: 100%;
          min-height: 320px;
        }
        .equal-card-content {
          display: flex;
          flex-direction: column;
          flex: 1;
        }
        .equal-card-list {
          flex: 1;
          display: flex;
          flex-direction: column;
          justify-content: flex-start;
        }
      `}</style>
      
      <section className="relative py-12 md:py-24 px-4 lg:px-8 overflow-visible">
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
        </div>

        <div className="max-w-7xl mx-auto relative z-10">
          <div className="grid lg:grid-cols-2 gap-8 lg:gap-16 items-center">
            
            <div className="relative h-[550px] md:h-[750px] lg:h-[800px] w-full overflow-visible order-2 lg:order-1">
              <div className="absolute top-10 md:top-20 left-0 right-0 flex items-start justify-center gap-4 md:gap-8 px-2">
                
                <div className="relative" style={{ marginTop: '60px' }}>
                  <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 rounded-xl p-3 md:p-5 border border-gray-800/50 shadow-2xl backdrop-blur-sm w-[140px] sm:w-[200px] md:w-[280px]">
                    <div className="flex items-center gap-2 md:gap-3 mb-2 md:mb-3">
                      <div className="w-5 h-5 md:w-7 md:h-7 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                        <span className="text-sm md:text-lg">⚡</span>
                      </div>
                      <div>
                        <h3 className="text-white font-semibold text-xs md:text-sm">backend [US-West]</h3>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-1 md:gap-2 text-[10px] md:text-xs text-gray-400 mb-2 md:mb-3">
                      <div className="w-2 h-2 md:w-3 md:h-3 rounded-full bg-green-500/20 flex items-center justify-center">
                        <div className="w-1 h-1 md:w-1.5 md:h-1.5 rounded-full bg-green-500"></div>
                      </div>
                      <span className="hidden sm:inline">Just deployed via GitHub</span>
                      <span className="sm:hidden">Deployed</span>
                    </div>

                    <div className="bg-[#0d0d15] rounded-lg p-2 md:p-3 border border-gray-800/50">
                      <div className="flex gap-1 md:gap-2 mb-1 md:mb-2">
                        <div className="w-4 h-4 md:w-5 md:h-5 bg-gray-800 rounded flex items-center justify-center text-xs text-gray-500">
                          <Terminal size={8} className="md:hidden" />
                          <Terminal size={10} className="hidden md:block" />
                        </div>
                        <div className="w-4 h-4 md:w-5 md:h-5 bg-gray-800 rounded flex items-center justify-center text-xs text-gray-500">
                          <Github size={8} className="md:hidden" />
                          <Github size={10} className="hidden md:block" />
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-3 gap-1 md:gap-1.5 mb-1 md:mb-2">
                        {[...Array(9)].map((_, i) => (
                          <div 
                            key={i} 
                            className="server-mini-card h-6 md:h-10 bg-gradient-to-b from-emerald-500/30 to-emerald-500/10 rounded border border-emerald-500/40 shadow-lg shadow-emerald-500/20"
                          ></div>
                        ))}
                      </div>

                      <div className="flex items-center justify-between gap-1 md:gap-2">
                        <div className="flex-1 h-1 md:h-1.5 bg-gradient-to-r from-emerald-500/40 to-blue-500/40 rounded-full"></div>
                        <div className="bg-gradient-to-br from-orange-500 to-orange-600 px-1.5 md:px-2.5 py-0.5 md:py-1 rounded text-[8px] md:text-[10px] font-bold text-white shadow-lg shadow-orange-500/30 leading-tight">
                          64x<br/>CPU
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="absolute -right-2 md:-right-4 top-1/2 w-8 md:w-16 h-px">
                    <div className="w-full h-full bg-gradient-to-r from-blue-500/60 to-transparent"></div>
                    <div className="absolute right-0 top-1/2 w-1 h-1 bg-blue-400 rounded-full -translate-y-1/2 shadow-lg shadow-blue-400/50"></div>
                  </div>
                </div>

                <div className="relative" style={{ marginTop: '0px' }}>
                  <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 rounded-xl p-3 md:p-5 border border-gray-800/50 shadow-2xl backdrop-blur-sm w-[140px] sm:w-[200px] md:w-[280px]">
                    <div className="flex items-center gap-2 md:gap-3 mb-2 md:mb-3">
                      <div className="w-5 h-5 md:w-7 md:h-7 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                        <span className="text-sm md:text-lg">⚡</span>
                      </div>
                      <div>
                        <h3 className="text-white font-semibold text-xs md:text-sm">backend [EU]</h3>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-1 md:gap-2 text-[10px] md:text-xs text-gray-400 mb-2 md:mb-3">
                      <div className="w-2 h-2 md:w-3 md:h-3 rounded-full bg-green-500/20 flex items-center justify-center">
                        <div className="w-1 h-1 md:w-1.5 md:h-1.5 rounded-full bg-green-500"></div>
                      </div>
                      <span className="hidden sm:inline">Just deployed via CLI</span>
                      <span className="sm:hidden">Deployed</span>
                    </div>

                    <div className="bg-[#0d0d15] rounded-lg p-2 md:p-3 border border-gray-800/50">
                      <div className="flex gap-1 md:gap-2 mb-1 md:mb-2">
                        <div className="w-4 h-4 md:w-5 md:h-5 bg-gray-800 rounded flex items-center justify-center text-xs text-gray-500">
                          <Terminal size={8} className="md:hidden" />
                          <Terminal size={10} className="hidden md:block" />
                        </div>
                        <div className="w-4 h-4 md:w-5 md:h-5 bg-gray-800 rounded flex items-center justify-center text-xs text-gray-500">
                          <Github size={8} className="md:hidden" />
                          <Github size={10} className="hidden md:block" />
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-3 gap-1 md:gap-1.5 mb-1 md:mb-2">
                        {[...Array(6)].map((_, i) => (
                          <div 
                            key={i} 
                            className="server-mini-card h-6 md:h-10 bg-gradient-to-b from-emerald-500/30 to-emerald-500/10 rounded border border-emerald-500/40 shadow-lg shadow-emerald-500/20"
                          ></div>
                        ))}
                      </div>

                      <div className="flex items-center justify-between gap-1 md:gap-2">
                        <div className="flex-1 h-1 md:h-1.5 bg-gradient-to-r from-emerald-500/40 to-purple-500/40 rounded-full"></div>
                        <div className="bg-gradient-to-br from-purple-500 to-purple-600 px-1.5 md:px-2.5 py-0.5 md:py-1 rounded text-[8px] md:text-[10px] font-bold text-white shadow-lg shadow-purple-500/30 leading-tight">
                          16x<br/>CPU
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="absolute -left-2 md:-left-4 top-1/2 w-8 md:w-16 h-px">
                    <div className="w-full h-full bg-gradient-to-l from-blue-500/60 to-transparent"></div>
                    <div className="absolute left-0 top-1/2 w-1 h-1 bg-blue-400 rounded-full -translate-y-1/2 shadow-lg shadow-blue-400/50"></div>
                  </div>
                </div>
              </div>

              <div className="absolute top-[420px] md:top-[680px] left-1/2 -translate-x-1/2 flex flex-col items-center pointer-events-auto">
                <div 
                  className="absolute top-[-380px] md:top-[-620px] left-1/2 w-px h-[1000px] md:h-[1300px] bg-gradient-to-b from-transparent via-blue-400/60 via-blue-500/80 via-blue-400/50 to-transparent -translate-x-1/2 z-0"
                ></div>
                
                <div className="absolute top-[-380px] md:top-[-620px] right-[-70px] md:right-[-140px] w-[70px] md:w-[140px] h-px bg-gradient-to-l from-blue-500/70 to-transparent z-10"></div>
                <div className="absolute top-[-380px] md:top-[-620px] right-[-70px] md:right-[-140px] w-1 md:w-1.5 h-1 md:h-1.5 bg-blue-400 rounded-full shadow-lg shadow-blue-400/50 z-10"></div>

                <div className="absolute top-[-380px] md:top-[-620px] left-[-70px] md:left-[-140px] w-[70px] md:w-[140px] h-px bg-gradient-to-r from-blue-500/70 to-transparent z-10"></div>
                <div className="absolute top-[-380px] md:top-[-620px] left-[-70px] md:left-[-140px] w-1 md:w-1.5 h-1 md:h-1.5 bg-blue-400 rounded-full shadow-lg shadow-blue-400/50 z-10"></div>

                <div 
                  ref={pipelineRef}
                  className="relative w-10 md:w-12 h-32 md:h-40 cursor-pointer z-20"
                  style={{
                    transform: `translateY(${pipelinePosition}px)`,
                    transition: 'transform 0.1s ease-out'
                  }}
                >
                  <div className="absolute inset-0 bg-gradient-to-b from-blue-500/40 via-cyan-400/50 to-blue-500/40 blur-xl animate-pulse"></div>
                  <div className="relative w-full h-full rounded-full bg-gradient-to-b from-blue-500/70 via-cyan-400/80 to-blue-500/70 shadow-2xl shadow-cyan-500/50"></div>
                  
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-7 md:w-9 h-24 md:h-28 bg-gradient-to-b from-cyan-300/60 to-blue-400/60 rounded-full"></div>
                  
                  <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-1 md:w-1.5 h-1 md:h-1.5 bg-white rounded-full shadow-lg shadow-white/50" style={{ animation: 'pulse-glow 2s ease-in-out infinite' }}></div>
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 w-1 md:w-1.5 h-1 md:h-1.5 bg-white rounded-full shadow-lg shadow-white/50" style={{ animation: 'pulse-glow 2s ease-in-out infinite', animationDelay: '0.5s' }}></div>
                  <div className="absolute top-2/3 left-1/2 -translate-x-1/2 w-1 md:w-1.5 h-1 md:h-1.5 bg-white rounded-full shadow-lg shadow-white/50" style={{ animation: 'pulse-glow 2s ease-in-out infinite', animationDelay: '1s' }}></div>
                </div>
              </div>
            </div>

            <div className="space-y-4 md:space-y-6 px-2 order-1 lg:order-2">
              <div className="inline-flex items-center gap-2 text-blue-400 font-medium text-xs md:text-sm">
                <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                AI Security & Compliance
              </div>
              
              <h2 className="text-2xl md:text-4xl lg:text-5xl font-bold leading-tight">
                Enterprise AI Security, Governance, Auditable, Compliant and monitoring.
              </h2>
              
              <p className="text-gray-400 text-base md:text-lg leading-relaxed">
                Deploy zero-trust API gateway, real-time threat detection, and compliance automation for all AI workloads. Block prompt injections, prevent data exfiltration, enforce granular access policies, and maintain immutable audit trails—across  LLMs.{' '}
                <a href="#" className="text-white inline-flex items-center gap-1 hover:gap-2 transition-all">
                  Learn More <ArrowRight size={16} />
                </a>
              </p>

              <div className="flex items-center gap-3 md:gap-4 pt-4">
                <div className="flex items-center gap-2 text-xs md:text-sm text-gray-500">
                  <Repeat size={14} className="md:hidden" />
                  <Repeat size={16} className="hidden md:block" />
                  <span>Replaces</span>
                </div>
                <div className="flex items-center gap-2 md:gap-3">
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/docker.png" alt="Docker" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/helm.png" alt="Helm" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/heroku.png" alt="Heroku" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/cloudrun.png" alt="Cloud Run" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/istio.png" alt="Istio" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
      <section className="relative py-12 md:py-24 px-4 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-8">
            <div className="flex items-center justify-center gap-2 md:gap-4 lg:gap-6 mb-12 border-b border-gray-800/50 overflow-x-auto px-4">
              <button className="pb-3 md:pb-4 px-2 md:px-4 lg:px-6 text-white border-b-2 border-white font-medium transition-colors text-xs md:text-sm lg:text-base whitespace-nowrap bg-black">Deploy</button>
              <button className="pb-3 md:pb-4 px-2 md:px-4 lg:px-6 text-white hover:text-white transition-colors text-xs md:text-sm lg:text-base whitespace-nowrap bg-black">Secure</button>
              <button className="pb-3 md:pb-4 px-2 md:px-4 lg:px-6 text-white hover:text-white transition-colors text-xs md:text-sm lg:text-base whitespace-nowrap bg-black">Comply</button>
              <button className="pb-3 md:pb-4 px-2 md:px-4 lg:px-6 text-white hover:text-white transition-colors text-xs md:text-sm lg:text-base whitespace-nowrap bg-black">Monitor</button>
              <button className="pb-3 md:pb-4 px-2 md:px-4 lg:px-6 text-white hover:text-white transition-colors text-xs md:text-sm lg:text-base whitespace-nowrap bg-black">Audit</button>
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-8 lg:gap-16 items-start mb-12 md:mb-16">
            <div className="relative flex justify-center items-center min-h-[300px] md:min-h-[400px]">
              <div className="relative w-full max-w-md aspect-square">
                <div className="absolute inset-0 bg-gradient-to-br from-purple-500/20 via-transparent to-blue-500/20 rounded-2xl blur-3xl"></div>
                
                <div 
                  ref={gridRef}
                  className="relative w-full h-full"
                  style={{ 
                    transformStyle: 'preserve-3d',
                    transform: 'rotateX(60deg) rotateZ(-45deg)'
                  }}
                >
                  <div className="absolute inset-0 grid grid-cols-3 gap-4 md:gap-8 p-4 md:p-8">
                    {[...Array(9)].map((_, i) => {
                      const isHighlighted = i === 1 || i === 4 || i === 7;
                      const zHeight = i === 1 ? 60 : i === 4 ? 80 : i === 7 ? 40 : 0;
                      const color = i === 1 ? 'purple' : i === 4 ? 'cyan' : i === 7 ? 'blue' : 'gray';
                      
                      return (
                        <div
                          key={i}
                          className="relative"
                          style={{ 
                            transform: `translateZ(${zHeight}px)`,
                            transformStyle: 'preserve-3d'
                          }}
                        >
                          <div 
                            className={`aspect-square rounded-lg backdrop-blur-sm flex items-center justify-center relative overflow-hidden ${
                              isHighlighted 
                                ? `bg-gradient-to-br from-${color}-500/50 to-${color}-600/30 border-2 border-${color}-500/70 shadow-2xl` 
                                : 'bg-gradient-to-br from-gray-800/40 to-gray-900/20 border border-gray-700/40'
                            }`}
                            style={isHighlighted ? {
                              boxShadow: `0 0 40px ${color === 'purple' ? '#a855f7' : color === 'cyan' ? '#06b6d4' : '#3b82f6'}40`
                            } : {}}
                          >
                            {isHighlighted && (
                              <>
                                <div 
                                  className={`w-6 md:w-8 h-6 md:h-8 rounded-full animate-pulse`}
                                  style={{
                                    background: color === 'purple' ? '#a855f7' : color === 'cyan' ? '#06b6d4' : '#3b82f6',
                                    boxShadow: `0 0 20px ${color === 'purple' ? '#a855f7' : color === 'cyan' ? '#06b6d4' : '#3b82f6'}`
                                  }}
                                ></div>
                                
                                {[...Array(3)].map((_, sparkIndex) => (
                                  <div
                                    key={sparkIndex}
                                    className="absolute w-1.5 md:w-2 h-1.5 md:h-2 rounded-full"
                                    style={{
                                      background: color === 'purple' ? '#a855f7' : color === 'cyan' ? '#06b6d4' : '#3b82f6',
                                      animation: `spark 2s ease-out infinite`,
                                      animationDelay: `${sparkIndex * 0.7}s`,
                                      top: '50%',
                                      left: '50%'
                                    }}
                                  ></div>
                                ))}
                              </>
                            )}
                          </div>
                          
                          {i === 1 && (
                            <>
                              <div 
                                className="absolute top-1/2 left-1/2 w-1 bg-gradient-to-b from-purple-500/80 to-transparent"
                                style={{ 
                                  height: '60px',
                                  transform: 'translate(-50%, 100%)',
                                  boxShadow: '0 0 10px #a855f7'
                                }}
                              ></div>
                              <div 
                                className="absolute top-1/2 left-full h-1 bg-gradient-to-r from-purple-500/80 to-transparent"
                                style={{ 
                                  width: '80px',
                                  transform: 'translateY(-50%)',
                                  boxShadow: '0 0 10px #a855f7'
                                }}
                              ></div>
                            </>
                          )}
                          {i === 4 && (
                            <>
                              <div 
                                className="absolute top-1/2 left-1/2 w-1 bg-gradient-to-b from-cyan-500/80 to-transparent"
                                style={{ 
                                  height: '100px',
                                  transform: 'translate(-50%, 100%)',
                                  boxShadow: '0 0 10px #06b6d4'
                                }}
                              ></div>
                              <div 
                                className="absolute top-1/2 right-full h-1 bg-gradient-to-l from-cyan-500/80 to-transparent"
                                style={{ 
                                  width: '80px',
                                  transform: 'translateY(-50%)',
                                  boxShadow: '0 0 10px #06b6d4'
                                }}
                              ></div>
                            </>
                          )}
                          
                          {i === 7 && (
                            <div 
                              className="absolute top-1/2 left-1/2 w-1 bg-gradient-to-b from-blue-500/80 to-transparent"
                              style={{ 
                                height: '50px',
                                transform: 'translate(-50%, 100%)',
                                boxShadow: '0 0 10px #3b82f6'
                              }}
                            ></div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>

            <div className="space-y-4 md:space-y-6 px-2">
              <h2 className="text-2xl md:text-4xl lg:text-5xl font-bold leading-tight">
                Zero-Trust AI Security Components
              </h2>
              
              <p className="text-gray-400 text-base md:text-lg leading-relaxed">
                Enterprise AI security requires multiple layers of protection. These are the core security primitives that protect every AI interaction on EXOPER's platform.
              </p>

              <div className="flex items-center gap-3 md:gap-4 pt-4">
                <div className="flex items-center gap-2 text-xs md:text-sm text-gray-500">
                  <Repeat size={14} className="md:hidden" />
                  <Repeat size={16} className="hidden md:block" />
                  <span>Replaces</span>
                </div>
                <div className="flex items-center gap-2 md:gap-3">
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/cilium.png" alt="Cilium" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/envoy.png" alt="Envoy" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/nginx.png" alt="Nginx" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/haproxy.png" alt="HAProxy" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <img src="/images/icons/sentry.png" alt="Sentry" className="w-4 h-4 md:w-6 md:h-6 object-contain" />
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="glowing-cards-container mb-12">
            <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border border-gray-800/50 rounded-xl p-4 md:p-6 equal-card">
              <div className="equal-card-content">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <Workflow className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">API Gateway</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Zero-trust gateway routes all AI requests through policy enforcement and threat detection layers.</p>
                <ul className="space-y-2 md:space-y-3 equal-card-list">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Workflow size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Multi-tenant isolation</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Workflow size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Identity verification (mTLS/OIDC)</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Workflow size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Policy-driven routing</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border border-gray-800/50 rounded-xl p-4 md:p-6 equal-card">
              <div className="equal-card-content">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <Shield className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Threat Detection</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Real-time detection engine blocks malicious AI requests before they reach models.</p>
                <ul className="space-y-2 md:space-y-3 equal-card-list">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Shield size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Prompt injection detection</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Shield size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Adversarial input mitigation</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Shield size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Data poisoning defense</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Shield size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>PII leak prevention</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border border-gray-800/50 rounded-xl p-4 md:p-6 equal-card">
              <div className="equal-card-content">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <BarChart3 className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Compliance Engine</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Automated compliance monitoring against global AI regulations and standards.</p>
                <ul className="space-y-2 md:space-y-3 equal-card-list">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <BarChart3 size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>EU AI Act alignment</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Gauge size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>GDPR/HIPAA compliance</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <BarChart3 size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>ISO 42001 certification</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border border-gray-800/50 rounded-xl p-4 md:p-6 equal-card">
              <div className="equal-card-content">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <Clock className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Model Connectors</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Secure connectors to external and internal AI models with encryption.</p>
                <ul className="space-y-2 md:space-y-3 equal-card-list">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Clock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Internal LLM integration</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Lock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>End-to-end encryption</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500 invisible">
                    <Clock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Placeholder</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500 invisible">
                    <Clock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Placeholder</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border border-gray-800/50 rounded-xl p-4 md:p-6 equal-card">
              <div className="equal-card-content">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <FileText className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Audit Logs</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Deploy arbitrarily complex collections of services, databases, etc.</p>
                <ul className="space-y-2 md:space-y-3 equal-card-list">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <FileText size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>WORM storage (S3)</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <FileText size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Cryptographic hashing</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <FileText size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Forensic-grade logging</span>
                  </li>
                </ul>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border border-gray-800/50 rounded-xl p-4 md:p-6 equal-card">
              <div className="equal-card-content">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <Lock className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Fine-grained access control and governance policies enforced in real-time.</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Manage secrets and environment variables across the stack.</p>
                <ul className="space-y-2 md:space-y-3 equal-card-list">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Lock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Role-based permissions (RBAC)</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Lock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Model usage policies</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Lock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Tenant-specific rules</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>

          <div className="text-center">
            <p className="text-xs md:text-sm text-gray-500 px-4">
              EXOPER's security infrastructure runs on-premises or cloud with Kubernetes, Envoy, and Rust-based detection engines.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Services3;