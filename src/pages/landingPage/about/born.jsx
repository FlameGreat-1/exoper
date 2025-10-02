import React from "react";
import Globe from "../../../components/ui/globe";

const Born = () => {
  return (
    <div className="relative min-h-screen w-full bg-[#0a0a0f] overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-b from-[#0a0a0f] via-[#12121a] to-[#0a0a0f]" />
      
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-purple-600/20 rounded-full blur-[120px]" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-600/20 rounded-full blur-[120px]" />
      </div>

      <div className="relative z-10 flex flex-col items-center justify-start lg:pt-20 pt-12 pb-16 lg:pb-32 px-4 lg:px-6">
        <div className="max-w-4xl mx-auto text-center mb-8 lg:mb-12">
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold text-white mb-4 lg:mb-6 tracking-tight leading-tight">
            Redefine the Future
            <br />
            of Infrastructure
          </h1>
          
          <p className="text-gray-400 text-base sm:text-lg md:text-xl mb-6 lg:mb-10 max-w-2xl mx-auto px-4">
            We're building something amazing and we want you to be part of it.
          </p>

          <button className="px-6 sm:px-8 py-3 sm:py-4 bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white text-sm sm:text-base font-semibold rounded-lg transition-all duration-300 shadow-lg shadow-purple-500/50 hover:shadow-purple-500/70 transform hover:scale-105">
            See Open Positions
          </button>
        </div>

        <div className="w-full max-w-7xl mx-auto">
          <div className="flex flex-col lg:flex-col items-center lg:items-center gap-8 lg:gap-0">
            
            <div className="w-full lg:max-w-3xl mx-auto text-center lg:mb-16 mb-0 order-2 md:order-1 px-4">
              <p className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-blue-400 text-sm sm:text-base md:text-lg lg:text-xl leading-relaxed font-medium">
                Exoper was born in 2025 to make instantly usable software
                infrastructure. Crafting software should be frictionless -- existing
                tools are not. We're expanding our team across the globe, we aim to ship AI
                solutions that powers businesses, enterprises and government, backed by the best people in the
                industry.
              </p>
            </div>

            <div className="w-full flex justify-center items-center order-1 md:order-2 lg:px-8 px-8 sm:px-12">
              <div className="relative w-full max-w-[320px] sm:max-w-[400px] md:max-w-[500px] lg:max-w-2xl mx-auto">
                <div className="absolute inset-0 bg-gradient-to-r from-purple-600/20 via-pink-500/20 to-blue-500/20 rounded-full blur-3xl" />
                
                <div className="relative flex items-center justify-center w-full overflow-visible">
                  <div className="w-full aspect-square flex items-center justify-center">
                    <div className="w-[90%] h-[90%] flex items-center justify-center">
                      <Globe
                        className="w-full h-full"
                        baseColor="#8b5cf6"
                        markerColor="#ec4899"
                        glowColor="#a855f7"
                        dark={1}
                        scale={1.1}
                        diffuse={1.2}
                        mapSamples={20000}
                        mapBrightness={6}
                      />
                    </div>
                  </div>
                  
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none z-20">
                    <img 
                      src="/images/logo2.png" 
                      alt="Exoper" 
                      className="w-24 h-24 sm:w-28 sm:h-28 md:w-32 md:h-32 lg:w-40 lg:h-40 object-contain drop-shadow-2xl"
                      style={{
                        filter: 'drop-shadow(0 0 20px rgba(139, 92, 246, 0.6))'
                      }}
                    />
                  </div>
                </div>

                <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none">
                  <div className="w-2 h-2 sm:w-3 sm:h-3 bg-pink-500 rounded-full animate-pulse shadow-lg shadow-pink-500/50" />
                </div>
              </div>
            </div>

          </div>
        </div>

        <div className="mt-12 lg:mt-20">
          <button className="px-5 sm:px-6 py-2.5 sm:py-3 bg-transparent border border-gray-700 hover:border-gray-600 text-gray-300 hover:text-white text-sm sm:text-base rounded-lg transition-all duration-300">
            About the Company
          </button>
        </div>
      </div>

      <div className="absolute bottom-0 left-0 w-full h-32 bg-gradient-to-t from-[#0a0a0f] to-transparent pointer-events-none" />
    </div>
  );
};

export default Born;