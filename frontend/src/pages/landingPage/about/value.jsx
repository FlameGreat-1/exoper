import React from "react";
import { Link } from 'react-router-dom';

const Value = () => {
  return (
    <div className="min-h-screen w-full bg-[#0b0b10] text-white antialiased" style={{fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto"}}>
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 sm:py-20 lg:py-24">
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          <div className="absolute -left-24 -top-24 w-80 h-80 rounded-full" style={{background: "radial-gradient(closest-side, rgba(168,85,247,0.12), rgba(168,85,247,0.02))", filter: "blur(48px)"}} />
          <div className="absolute right-[-6rem] top-24 w-72 h-72 rounded-full" style={{background: "radial-gradient(closest-side, rgba(236,72,153,0.08), rgba(236,72,153,0.01))", filter: "blur(44px)"}} />
        </div>

        <div className="text-center relative z-10 mb-12 sm:mb-16 lg:mb-20">
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold leading-tight">Our Values</h1>
          <p className="text-gray-400 mt-4 text-lg sm:text-xl lg:text-2xl">What keeps our engines running</p>
        </div>

        <div className="relative z-10">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 lg:gap-8 max-w-4xl mx-auto">
            <div className="relative bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 sm:p-8 lg:p-10 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)]">
              <div className="flex justify-center mb-6">
                <div className="w-14 h-14 sm:w-16 sm:h-16 flex items-center justify-center rounded-full">
                  <svg viewBox="0 0 64 64" className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <linearGradient id="g1" x1="0%" x2="100%" y1="0%" y2="100%">
                        <stop offset="0%" stopColor="#8b5cf6"/>
                        <stop offset="100%" stopColor="#a855f7"/>
                      </linearGradient>
                    </defs>
                    <path d="M32 8C32 8 20 12 20 24C20 36 32 44 32 44C32 44 44 36 44 24C44 12 32 8 32 8Z" stroke="url(#g1)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" fill="rgba(168,85,247,0.06)"/>
                  </svg>
                </div>
              </div>
              <h3 className="text-2xl sm:text-3xl font-semibold text-center mb-3">Honorable</h3>
              <p className="text-gray-400 text-base sm:text-lg text-center leading-relaxed">We do the right thing for our teammates, customers, and those around us, building trust through honest actions and focused outcomes.</p>
            </div>

            <div className="relative bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 sm:p-8 lg:p-10 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)]">
              <div className="flex justify-center mb-6">
                <div className="w-14 h-14 sm:w-16 sm:h-16 flex items-center justify-center rounded-full">
                  <svg viewBox="0 0 64 64" className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <linearGradient id="g2" x1="0%" x2="100%" y1="0%" y2="0%">
                        <stop offset="0%" stopColor="#8b5cf6"/>
                        <stop offset="100%" stopColor="#a855f7"/>
                      </linearGradient>
                    </defs>
                    <path d="M12 52L20 28L28 40L36 16L44 32L52 12" stroke="url(#g2)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
                  </svg>
                </div>
              </div>
              <h3 className="text-2xl sm:text-3xl font-semibold text-center mb-3">Accelerating</h3>
              <p className="text-gray-400 text-base sm:text-lg text-center leading-relaxed">We move quickly and efficiently, driving to create the space for greatness and to overcome whatever obstacles might be lurking in the shadows.</p>
            </div>

            <div className="relative bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 sm:p-8 lg:p-10 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)]">
              <div className="flex justify-center mb-6">
                <div className="w-14 h-14 sm:w-16 sm:h-16 flex items-center justify-center rounded-full">
                  <svg viewBox="0 0 64 64" className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <linearGradient id="g3" x1="0%" x2="100%" y1="0%" y2="100%">
                        <stop offset="0%" stopColor="#8b5cf6"/>
                        <stop offset="100%" stopColor="#a855f7"/>
                      </linearGradient>
                    </defs>
                    <circle cx="32" cy="32" r="24" stroke="url(#g3)" strokeWidth="3" fill="none"/>
                    <path d="M20 32L28 40L44 24" stroke="url(#g3)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
                  </svg>
                </div>
              </div>
              <h3 className="text-2xl sm:text-3xl font-semibold text-center mb-3">Reliable</h3>
              <p className="text-gray-400 text-base sm:text-lg text-center leading-relaxed">We drive clarity via communicating, showing up reliably to create a sense of dependability and ease for our coworkers, customers, and everyone in between.</p>
            </div>

            <div className="relative bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 rounded-2xl p-6 sm:p-8 lg:p-10 border border-[#222631] shadow-[0_6px_30px_rgba(2,6,23,0.6)]">
              <div className="flex justify-center mb-6">
                <div className="w-14 h-14 sm:w-16 sm:h-16 flex items-center justify-center rounded-full">
                  <svg viewBox="0 0 64 64" className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                      <linearGradient id="g4" x1="0%" x2="100%" y1="0%" y2="100%">
                        <stop offset="0%" stopColor="#8b5cf6"/>
                        <stop offset="100%" stopColor="#a855f7"/>
                      </linearGradient>
                    </defs>
                    <path d="M32 12C32 12 20 18 20 28C20 38 32 52 32 52C32 52 44 38 44 28C44 18 32 12 32 12Z" stroke="url(#g4)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
                  </svg>
                </div>
              </div>
              <h3 className="text-2xl sm:text-3xl font-semibold text-center mb-3">Direct</h3>
              <p className="text-gray-400 text-base sm:text-lg text-center leading-relaxed">We are kind-yet-direct, giving feedback to our coworkers such that they may become the best them they can be, and expecting the same in return.</p>
            </div>
          </div>

          <div className="absolute left-1/2 transform -translate-x-1/2 -translate-y-1/2 top-[50%] pointer-events-none z-0 w-[360px] h-[360px] hidden sm:block">
            <svg viewBox="0 0 360 360" className="w-full h-full" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <radialGradient id="centerGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="rgba(168,85,247,0.14)"/>
                  <stop offset="50%" stopColor="rgba(168,85,247,0.06)"/>
                  <stop offset="100%" stopColor="rgba(10,10,12,0)"/>
                </radialGradient>
                <radialGradient id="centerGlow2" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="rgba(236,72,153,0.12)"/>
                  <stop offset="50%" stopColor="rgba(236,72,153,0.04)"/>
                  <stop offset="100%" stopColor="rgba(10,10,12,0)"/>
                </radialGradient>
              </defs>
              <circle cx="120" cy="120" r="80" fill="url(#centerGlow)"/>
              <circle cx="240" cy="180" r="64" fill="url(#centerGlow2)"/>
              <g transform="translate(120,120)">
                <path d="M0,-6 L6,8 L0,2 L -6,8 Z" fill="rgba(255,255,255,0.06)"/>
              </g>
            </svg>
          </div>

          <div className="absolute z-20 left-1/2 top-1/2 transform -translate-x-1/2 -translate-y-1/2 pointer-events-none">
            <svg viewBox="0 0 160 160" className="w-40 h-40 sm:w-48 sm:h-48" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="bolt" x1="0%" x2="100%">
                  <stop offset="0%" stopColor="#fff7"/>
                  <stop offset="100%" stopColor="#ffe1"/>
                </linearGradient>
                <filter id="f1" x="-50%" y="-50%" width="200%" height="200%">
                  <feDropShadow dx="0" dy="6" stdDeviation="10" floodColor="#a855f7" floodOpacity="0.12"/>
                </filter>
              </defs>
              <g filter="url(#f1)" transform="translate(80,80)">
                <path d="M-18,-30 L2,-6 L-6,-6 L18,24 L-2,24 L6,6 L-18,6 Z" fill="url(#bolt)" stroke="rgba(255,255,255,0.12)" strokeWidth="1" />
                <circle cx="0" cy="0" r="8" fill="rgba(255,255,255,0.06)"/>
              </g>
            </svg>
          </div>

          <div className="mt-12 flex justify-center relative z-10">
          <Link 
            to="/careers/all-positions"
            className="inline-block bg-gradient-to-r from-[#8b5cf6] to-[#a855f7] text-white font-semibold px-8 sm:px-10 py-3 sm:py-4 rounded-lg text-base sm:text-lg transition transform hover:scale-[1.03] shadow-[0_10px_30px_rgba(139,92,246,0.16)]"
          >
           See Open Positions
          </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Value;
