import React, { useEffect, useRef, useState } from 'react';
import { ArrowRight, Database, HardDrive, Clock, FileText, Lock, Github, Terminal, Gauge, BarChart3, Workflow, Repeat } from 'lucide-react';
import { GlowingCards, GlowingCard } from '../../../components/ui/glowing-cards';

const Services3 = () => {
  const gridRef = useRef(null);
  const pipelineRef = useRef(null);
  const [oscillation, setOscillation] = useState(0);
  const [isHovered, setIsHovered] = useState(false);

  useEffect(() => {
    const cards = document.querySelectorAll('.server-mini-card');
    cards.forEach((card, index) => {
      card.style.animation = `float ${2 + index * 0.3}s ease-in-out infinite`;
      card.style.animationDelay = `${index * 0.2}s`;
    });

    if (gridRef.current) {
      gridRef.current.style.animation = 'rotateGrid 20s linear infinite';
    }

    let animationFrame;
    let lastScrollY = window.scrollY;
    let velocity = 0;
    let angle = 0;

    const animate = () => {
      const currentScrollY = window.scrollY;
      const scrollDelta = currentScrollY - lastScrollY;
      lastScrollY = currentScrollY;

      velocity += scrollDelta * 0.001;
      velocity *= 0.95;

      if (isHovered) {
        angle += Math.sin(Date.now() * 0.003) * 0.5;
      } else {
        angle += velocity;
      }

      angle *= 0.92;

      setOscillation(angle);
      animationFrame = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationFrame) {
        cancelAnimationFrame(animationFrame);
      }
    };
  }, [isHovered]);

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
      `}</style>
      
      <section className="relative py-12 md:py-24 px-4 lg:px-8 overflow-visible">
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
        </div>

        <div className="max-w-7xl mx-auto relative z-10">
          <div className="grid lg:grid-cols-2 gap-8 lg:gap-16 items-center">
            
            <div className="relative h-[650px] md:h-[750px] lg:h-[800px] w-full overflow-visible order-2 lg:order-1">
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

              <div className="absolute top-[520px] md:top-[680px] left-1/2 -translate-x-1/2 flex flex-col items-center pointer-events-auto">
                <div 
                  className="absolute top-[-480px] md:top-[-620px] left-1/2 w-px h-[1000px] md:h-[1300px] bg-gradient-to-b from-transparent via-blue-400/60 via-blue-500/80 via-blue-400/50 to-transparent -translate-x-1/2 z-0"
                  style={{
                    transform: `translateX(-50%) rotate(${oscillation * 0.3}deg)`,
                    transformOrigin: 'top center',
                    transition: 'transform 0.1s ease-out'
                  }}
                ></div>
                
                <div 
                  className="absolute top-[-480px] md:top-[-620px] right-[-70px] md:right-[-140px] w-[70px] md:w-[140px] h-px bg-gradient-to-l from-blue-500/70 to-transparent z-10"
                  style={{
                    transform: `rotate(${oscillation * 0.2}deg)`,
                    transformOrigin: 'right center',
                    transition: 'transform 0.1s ease-out'
                  }}
                ></div>
                <div className="absolute top-[-480px] md:top-[-620px] right-[-70px] md:right-[-140px] w-1 md:w-1.5 h-1 md:h-1.5 bg-blue-400 rounded-full shadow-lg shadow-blue-400/50 z-10"></div>

                <div 
                  className="absolute top-[-480px] md:top-[-620px] left-[-70px] md:left-[-140px] w-[70px] md:w-[140px] h-px bg-gradient-to-r from-blue-500/70 to-transparent z-10"
                  style={{
                    transform: `rotate(${-oscillation * 0.2}deg)`,
                    transformOrigin: 'left center',
                    transition: 'transform 0.1s ease-out'
                  }}
                ></div>
                <div className="absolute top-[-480px] md:top-[-620px] left-[-70px] md:left-[-140px] w-1 md:w-1.5 h-1 md:h-1.5 bg-blue-400 rounded-full shadow-lg shadow-blue-400/50 z-10"></div>

                <div 
                  ref={pipelineRef}
                  className="relative w-10 md:w-12 h-32 md:h-40 cursor-pointer z-20"
                  style={{
                    transform: `rotate(${oscillation}deg)`,
                    transformOrigin: 'top center',
                    transition: 'transform 0.1s ease-out'
                  }}
                  onMouseEnter={() => setIsHovered(true)}
                  onMouseLeave={() => setIsHovered(false)}
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
                Scale and Grow
              </div>
              
              <h2 className="text-2xl md:text-4xl lg:text-5xl font-bold leading-tight">
                Scale your applications with intuitive vertical and horizontal scaling
              </h2>
              
              <p className="text-gray-400 text-base md:text-lg leading-relaxed">
                Exoper dynamically scales highly performant servers, storage, and networking to meet application demands.{' '}
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
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6" fill="#0080FF">
                      <path d="M12 2L2 7v10c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z"/>
                    </svg>
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6" fill="#FF6B35">
                      <circle cx="12" cy="12" r="10" fill="#FF6B35"/>
                      <path d="M8 8h8v8H8z" fill="white"/>
                    </svg>
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6">
                      <path d="M12 2l3 7h7l-5.5 4 2 7-6.5-5-6.5 5 2-7L2 9h7z" fill="#00D9B5"/>
                    </svg>
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6" fill="#9945FF">
                      <rect x="6" y="6" width="12" height="12" rx="2" fill="#9945FF"/>
                    </svg>
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
            <div className="flex items-center justify-center gap-3 md:gap-6 mb-12 border-b border-gray-800/50 overflow-x-auto">
              <button className="pb-3 md:pb-4 px-3 md:px-6 text-white border-b-2 border-white font-medium transition-colors text-sm md:text-base whitespace-nowrap">Deploy</button>
              <button className="pb-3 md:pb-4 px-3 md:px-6 text-gray-500 hover:text-white transition-colors text-sm md:text-base whitespace-nowrap">Network</button>
              <button className="pb-3 md:pb-4 px-3 md:px-6 text-gray-500 hover:text-white transition-colors text-sm md:text-base whitespace-nowrap">Scale</button>
              <button className="pb-3 md:pb-4 px-3 md:px-6 text-gray-500 hover:text-white transition-colors text-sm md:text-base whitespace-nowrap">Monitor</button>
              <button className="pb-3 md:pb-4 px-3 md:px-6 text-gray-500 hover:text-white transition-colors text-sm md:text-base whitespace-nowrap">Evolve</button>
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
                Build and Deploy
              </h2>
              
              <p className="text-gray-400 text-base md:text-lg leading-relaxed">
                Every application stack is different, but the building blocks are similar. These are the core primitives behind every app hosted on Exoper.
              </p>

              <div className="flex items-center gap-3 md:gap-4 pt-4">
                <div className="flex items-center gap-2 text-xs md:text-sm text-gray-500">
                  <Repeat size={14} className="md:hidden" />
                  <Repeat size={16} className="hidden md:block" />
                  <span>Replaces</span>
                </div>
                <div className="flex items-center gap-2 md:gap-3">
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6" fill="#0db7ed">
                      <path d="M13.5 10.5h-3v-3h3v3zm6.5 0h-3v-3h3v3zm-13 0h-3v-3h3v3zm6.5 6.5h-3v-3h3v3zm6.5 0h-3v-3h3v3zm-13 0h-3v-3h3v3z"/>
                    </svg>
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6">
                      <path d="M10.9 2.1l9.899 1.415 1.414 9.9-9.192 9.192-1.414 1.414-9.9-1.415-1.415-9.9 9.192-9.192 1.415-1.414z" fill="#326CE5"/>
                    </svg>
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6" fill="#7B42BC">
                      <rect x="4" y="4" width="7" height="7" fill="#7B42BC"/>
                      <rect x="13" y="4" width="7" height="7" fill="#7B42BC"/>
                      <rect x="4" y="13" width="7" height="7" fill="#7B42BC"/>
                      <rect x="13" y="13" width="7" height="7" fill="#7B42BC"/>
                    </svg>
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6">
                      <circle cx="12" cy="12" r="10" fill="#161616"/>
                      <path d="M12 2L6 12l6 10 6-10z" fill="#39E09B"/>
                    </svg>
                  </div>
                  <div className="w-6 h-6 md:w-8 md:h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-4 h-4 md:w-6 md:h-6" fill="#632CA6">
                      <circle cx="12" cy="12" r="10" fill="#632CA6"/>
                      <circle cx="12" cy="12" r="4" fill="white"/>
                    </svg>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <GlowingCards 
            className="w-full mb-12"
            enableGlow={true}
            glowRadius={30}
            glowOpacity={0.8}
            gap="1.5rem"
            enableHover={true}
            responsive={true}
          >
            <GlowingCard 
              className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border-gray-800/50 flex-1 min-w-[280px] max-w-full md:max-w-[calc(50%-0.75rem)] lg:max-w-[calc(33.333%-1rem)]"
              glowColor="#ec4899"
              hoverEffect={true}
            >
              <div className="relative">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <Workflow className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Services</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Deploy any container image as a service, just specify the source.</p>
                <ul className="space-y-2 md:space-y-3">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Database size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Docker Image</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Github size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Github repository</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Terminal size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Local repository</span>
                  </li>
                </ul>
              </div>
            </GlowingCard>

            <GlowingCard 
              className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border-gray-800/50 flex-1 min-w-[280px] max-w-full md:max-w-[calc(50%-0.75rem)] lg:max-w-[calc(33.333%-1rem)]"
              glowColor="#ec4899"
              hoverEffect={true}
            >
              <div className="relative">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <Database className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Databases</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Spin-up any database, with built-in backups.</p>
                <ul className="space-y-2 md:space-y-3">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Database size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>PostgreSQL</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Database size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>MySQL</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Database size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>MongoDB</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Database size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Redis</span>
                  </li>
                </ul>
              </div>
            </GlowingCard>

            <GlowingCard 
              className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border-gray-800/50 flex-1 min-w-[280px] max-w-full md:max-w-[calc(50%-0.75rem)] lg:max-w-[calc(33.333%-1rem)]"
              glowColor="#ec4899"
              hoverEffect={true}
            >
              <div className="relative">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <HardDrive className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Volumes</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Attach and mount high-performance persistent storage volumes.</p>
                <ul className="space-y-2 md:space-y-3">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <HardDrive size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Up to 256TB of storage</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Gauge size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>100,000+ IOPS</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <BarChart3 size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Disk usage metrics</span>
                  </li>
                </ul>
              </div>
            </GlowingCard>

            <GlowingCard 
              className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border-gray-800/50 flex-1 min-w-[280px] max-w-full md:max-w-[calc(50%-0.75rem)] lg:max-w-[calc(33.333%-1rem)]"
              glowColor="#ec4899"
              hoverEffect={true}
            >
              <div className="relative">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <Clock className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Cron Jobs</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Configure a job to run on a fixed schedule.</p>
                <ul className="space-y-2 md:space-y-3">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Clock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Atomic to 5-minute intervals</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Terminal size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Programmable via crontab expression</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500 invisible">
                    <Terminal size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Placeholder</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500 invisible">
                    <Terminal size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Placeholder</span>
                  </li>
                </ul>
              </div>
            </GlowingCard>

            <GlowingCard 
              className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border-gray-800/50 flex-1 min-w-[280px] max-w-full md:max-w-[calc(50%-0.75rem)] lg:max-w-[calc(33.333%-1rem)]"
              glowColor="#ec4899"
              hoverEffect={true}
            >
              <div className="relative">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <FileText className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Templates</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Deploy arbitrarily complex collections of services, databases, etc.</p>
                <ul className="space-y-2 md:space-y-3">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <FileText size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>800+ templates</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <FileText size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Sharable</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <FileText size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Customizable</span>
                  </li>
                </ul>
              </div>
            </GlowingCard>

            <GlowingCard 
              className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 border-gray-800/50 flex-1 min-w-[280px] max-w-full md:max-w-[calc(50%-0.75rem)] lg:max-w-[calc(33.333%-1rem)]"
              glowColor="#ec4899"
              hoverEffect={true}
            >
              <div className="relative">
                <div className="w-12 h-12 md:w-14 md:h-14 bg-gradient-to-br from-pink-500/20 to-purple-600/20 rounded-xl flex items-center justify-center mb-4 md:mb-5 group-hover:scale-110 transition-transform border border-pink-500/20">
                  <Lock className="text-pink-400" size={24} />
                </div>
                <h3 className="text-lg md:text-xl font-semibold mb-2 md:mb-3 text-white">Variables</h3>
                <p className="text-gray-400 text-xs md:text-sm mb-4 md:mb-5 leading-relaxed">Manage secrets and environment variables across the stack.</p>
                <ul className="space-y-2 md:space-y-3">
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Lock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Service variables</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Lock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Shared variables</span>
                  </li>
                  <li className="flex items-center gap-2 md:gap-3 text-xs md:text-sm text-gray-500">
                    <Lock size={14} className="text-gray-600 md:w-4 md:h-4" />
                    <span>Reference variables</span>
                  </li>
                </ul>
              </div>
            </GlowingCard>
          </GlowingCards>

          <div className="text-center">
            <p className="text-xs md:text-sm text-gray-500 px-4">
              Exoper uses Nixpacks or your Dockerfile to build and deploy your code.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Services3;