import React, { useEffect, useRef } from 'react';
import { ArrowRight, Database, HardDrive, Clock, FileText, Lock, Github, Terminal, Gauge, BarChart3, Workflow, Repeat } from 'lucide-react';

const Services3 = () => {
  const gridRef = useRef(null);

  useEffect(() => {
    const cards = document.querySelectorAll('.server-mini-card');
    cards.forEach((card, index) => {
      card.style.animation = `float ${2 + index * 0.3}s ease-in-out infinite`;
      card.style.animationDelay = `${index * 0.2}s`;
    });

    if (gridRef.current) {
      gridRef.current.style.animation = 'rotateGrid 20s linear infinite';
    }
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
      `}</style>
      
      <section className="relative py-24 px-4 lg:px-8">
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl"></div>
        </div>

        <div className="max-w-7xl mx-auto relative z-10">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            
            <div className="relative h-[600px] lg:h-[700px]">
              <div className="absolute top-20 left-0 right-0 flex items-start justify-center gap-8">
                
                <div className="relative" style={{ marginTop: '80px' }}>
                  <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 rounded-xl p-5 border border-gray-800/50 shadow-2xl backdrop-blur-sm w-[280px]">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="w-7 h-7 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                        <span className="text-lg">⚡</span>
                      </div>
                      <div>
                        <h3 className="text-white font-semibold text-sm">backend [US-West]</h3>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-2 text-xs text-gray-400 mb-3">
                      <div className="w-3 h-3 rounded-full bg-green-500/20 flex items-center justify-center">
                        <div className="w-1.5 h-1.5 rounded-full bg-green-500"></div>
                      </div>
                      <span>Just deployed via GitHub</span>
                    </div>

                    <div className="bg-[#0d0d15] rounded-lg p-3 border border-gray-800/50">
                      <div className="flex gap-2 mb-2">
                        <div className="w-5 h-5 bg-gray-800 rounded flex items-center justify-center text-xs text-gray-500">
                          <Terminal size={10} />
                        </div>
                        <div className="w-5 h-5 bg-gray-800 rounded flex items-center justify-center text-xs text-gray-500">
                          <Github size={10} />
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-3 gap-1.5 mb-2">
                        {[...Array(9)].map((_, i) => (
                          <div 
                            key={i} 
                            className="server-mini-card h-10 bg-gradient-to-b from-emerald-500/30 to-emerald-500/10 rounded border border-emerald-500/40 shadow-lg shadow-emerald-500/20"
                          ></div>
                        ))}
                      </div>

                      <div className="flex items-center justify-between gap-2">
                        <div className="flex-1 h-1.5 bg-gradient-to-r from-emerald-500/40 to-blue-500/40 rounded-full"></div>
                        <div className="bg-gradient-to-br from-orange-500 to-orange-600 px-2.5 py-1 rounded text-[10px] font-bold text-white shadow-lg shadow-orange-500/30 leading-tight">
                          64x<br/>CPU
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="absolute -right-4 top-1/2 w-16 h-px">
                    <div className="w-full h-full bg-gradient-to-r from-blue-500/60 to-transparent"></div>
                    <div className="absolute right-0 top-1/2 w-1 h-1 bg-blue-400 rounded-full -translate-y-1/2 shadow-lg shadow-blue-400/50"></div>
                  </div>
                </div>

                <div className="relative" style={{ marginTop: '0px' }}>
                  <div className="bg-gradient-to-br from-[#1a1a2e]/90 to-[#16162a]/90 rounded-xl p-5 border border-gray-800/50 shadow-2xl backdrop-blur-sm w-[280px]">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="w-7 h-7 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                        <span className="text-lg">⚡</span>
                      </div>
                      <div>
                        <h3 className="text-white font-semibold text-sm">backend [EU]</h3>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-2 text-xs text-gray-400 mb-3">
                      <div className="w-3 h-3 rounded-full bg-green-500/20 flex items-center justify-center">
                        <div className="w-1.5 h-1.5 rounded-full bg-green-500"></div>
                      </div>
                      <span>Just deployed via CLI</span>
                    </div>

                    <div className="bg-[#0d0d15] rounded-lg p-3 border border-gray-800/50">
                      <div className="flex gap-2 mb-2">
                        <div className="w-5 h-5 bg-gray-800 rounded flex items-center justify-center text-xs text-gray-500">
                          <Terminal size={10} />
                        </div>
                        <div className="w-5 h-5 bg-gray-800 rounded flex items-center justify-center text-xs text-gray-500">
                          <Github size={10} />
                        </div>
                      </div>
                      
                      <div className="grid grid-cols-3 gap-1.5 mb-2">
                        {[...Array(6)].map((_, i) => (
                          <div 
                            key={i} 
                            className="server-mini-card h-10 bg-gradient-to-b from-emerald-500/30 to-emerald-500/10 rounded border border-emerald-500/40 shadow-lg shadow-emerald-500/20"
                          ></div>
                        ))}
                      </div>

                      <div className="flex items-center justify-between gap-2">
                        <div className="flex-1 h-1.5 bg-gradient-to-r from-emerald-500/40 to-purple-500/40 rounded-full"></div>
                        <div className="bg-gradient-to-br from-purple-500 to-purple-600 px-2.5 py-1 rounded text-[10px] font-bold text-white shadow-lg shadow-purple-500/30 leading-tight">
                          16x<br/>CPU
                        </div>
                      </div>
                    </div>
                  </div>
                  
                  <div className="absolute -left-4 top-1/2 w-16 h-px">
                    <div className="w-full h-full bg-gradient-to-l from-blue-500/60 to-transparent"></div>
                    <div className="absolute left-0 top-1/2 w-1 h-1 bg-blue-400 rounded-full -translate-y-1/2 shadow-lg shadow-blue-400/50"></div>
                  </div>
                </div>
              </div>

              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
                <div className="relative w-20 h-60">
                  <div className="absolute inset-0 bg-gradient-to-b from-blue-500/40 via-cyan-400/50 to-blue-500/40 blur-2xl animate-pulse"></div>
                  <div className="relative w-full h-full rounded-full bg-gradient-to-b from-blue-500/70 via-cyan-400/80 to-blue-500/70 shadow-2xl shadow-cyan-500/50"></div>
                  
                  <div className="absolute top-0 left-1/2 -translate-x-1/2 w-px h-32 bg-gradient-to-b from-transparent via-blue-400/60 to-blue-500/80"></div>
                  <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-px h-32 bg-gradient-to-t from-transparent via-blue-400/60 to-blue-500/80"></div>
                  
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-14 h-32 bg-gradient-to-b from-cyan-300/60 to-blue-400/60 rounded-full"></div>
                  
                  <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-2 h-2 bg-white rounded-full shadow-lg shadow-white/50" style={{ animation: 'pulse-glow 2s ease-in-out infinite' }}></div>
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 w-2 h-2 bg-white rounded-full shadow-lg shadow-white/50" style={{ animation: 'pulse-glow 2s ease-in-out infinite', animationDelay: '0.5s' }}></div>
                  <div className="absolute top-2/3 left-1/2 -translate-x-1/2 w-2 h-2 bg-white rounded-full shadow-lg shadow-white/50" style={{ animation: 'pulse-glow 2s ease-in-out infinite', animationDelay: '1s' }}></div>
                </div>
              </div>
            </div>

            <div className="space-y-6">
              <div className="inline-flex items-center gap-2 text-blue-400 font-medium text-sm">
                <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                Scale and Grow
              </div>
              
              <h2 className="text-4xl lg:text-5xl font-bold leading-tight">
                Scale your applications with intuitive vertical and horizontal scaling
              </h2>
              
              <p className="text-gray-400 text-lg leading-relaxed">
                Railway dynamically scales highly performant servers, storage, and networking to meet application demands.{' '}
                <a href="#" className="text-white inline-flex items-center gap-1 hover:gap-2 transition-all">
                  Learn More <ArrowRight size={16} />
                </a>
              </p>

              <div className="flex items-center gap-4 pt-4">
                <div className="flex items-center gap-2 text-sm text-gray-500">
                  <Repeat size={16} />
                  <span>Replaces</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-6 h-6" fill="#0080FF">
                      <path d="M12 2L2 7v10c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-10-5z"/>
                    </svg>
                  </div>
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-6 h-6" fill="#FF6B35">
                      <circle cx="12" cy="12" r="10" fill="#FF6B35"/>
                      <path d="M8 8h8v8H8z" fill="white"/>
                    </svg>
                  </div>
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-6 h-6">
                      <path d="M12 2l3 7h7l-5.5 4 2 7-6.5-5-6.5 5 2-7L2 9h7z" fill="#00D9B5"/>
                    </svg>
                  </div>
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center opacity-60 hover:opacity-100 transition-opacity">
                    <svg viewBox="0 0 24 24" className="w-6 h-6" fill="#9945FF">
                      <rect x="6" y="6" width="12" height="12" rx="2" fill="#9945FF"/>
                    </svg>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>



go build -o bin/gateway ./cmd/gateway