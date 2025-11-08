import React from 'react';
import { Link } from 'react-router-dom';

const CompanyDropdownCard = () => {
  return (
    <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 backdrop-blur-xl p-4 rounded-2xl shadow-[0_6px_30px_rgba(2,6,23,0.6)] border border-[#222631] w-[500px]">
      <div className="grid grid-cols-2 gap-4">
        
        <Link to="/about" className="group relative overflow-hidden rounded-xl bg-[#0b0b10]/60 p-4 border border-[#222631] hover:border-[#8b5cf6]/50 transition-all duration-300 cursor-pointer hover:shadow-lg hover:shadow-purple-500/10">
          <div className="relative z-10">
            <h3 className="text-white text-base font-semibold mb-1">About</h3>
            <p className="text-gray-400 text-xs leading-relaxed">Learn about our team and mission</p>
          </div>
          
          <div className="relative w-full h-24 mt-3">
            <svg className="absolute inset-0 w-full h-full" viewBox="0 0 400 200" fill="none" xmlns="http://www.w3.org/2000/svg">
              <defs>
                <linearGradient id="gradient1" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.4"/>
                  <stop offset="50%" stopColor="#a855f7" stopOpacity="0.6"/>
                  <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.3"/>
                </linearGradient>
                <linearGradient id="gradient2" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#8b5cf6" stopOpacity="0.3"/>
                  <stop offset="100%" stopColor="#a855f7" stopOpacity="0.4"/>
                </linearGradient>
                <linearGradient id="planeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#8b5cf6"/>
                  <stop offset="100%" stopColor="#a855f7"/>
                </linearGradient>
              </defs>
              
              <path d="M 50 150 Q 150 100, 250 120 T 450 80" stroke="url(#gradient1)" strokeWidth="2" fill="none" opacity="0.4"/>
              <path d="M 30 160 Q 130 110, 230 130 T 430 90" stroke="url(#gradient2)" strokeWidth="1.5" fill="none" opacity="0.3"/>
              
              <circle cx="80" cy="140" r="6" fill="#8b5cf6" opacity="0.9">
                <animate attributeName="opacity" values="0.9;0.5;0.9" dur="3s" repeatCount="indefinite"/>
              </circle>
              
              <circle cx="250" cy="100" r="5" fill="#a855f7" opacity="0.7">
                <animate attributeName="opacity" values="0.7;0.4;0.7" dur="2.5s" repeatCount="indefinite"/>
              </circle>
              
              <circle cx="350" cy="70" r="4" fill="#a855f7" opacity="0.6">
                <animate attributeName="opacity" values="0.6;0.3;0.6" dur="2s" repeatCount="indefinite"/>
              </circle>
              
              <g transform="translate(280, 95) rotate(-15)">
                <path d="M 0 0 L 60 -8 L 62 -6 L 58 8 L 0 4 Z" fill="url(#planeGradient)" opacity="0.8"/>
                <path d="M 15 -8 L 15 -20 L 17 -20 L 17 -8 Z" fill="url(#planeGradient)" opacity="0.7"/>
                <path d="M 45 8 L 52 18 L 50 19 L 43 9 Z" fill="url(#planeGradient)" opacity="0.7"/>
                <path d="M 60 -8 L 70 -10 L 70 -8 L 62 -6 Z" fill="#a855f7" opacity="0.9"/>
              </g>
            </svg>
          </div>
          
          <div className="absolute inset-0 bg-gradient-to-tr from-purple-600/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
        </Link>

        <div className="rounded-xl bg-[#0b0b10]/60 p-4 border border-[#222631]">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-white text-base font-semibold">Careers</h3>
            <span className="bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 text-purple-300 text-xs font-medium px-2 py-0.5 rounded-md border border-[#8b5cf6]/30">16</span>
          </div>
          <p className="text-gray-400 text-xs mb-3 leading-relaxed">Shape the future with us</p>
          
          <div className="space-y-1.5">
            <Link 
              to="/careers/senior-fullstack-engineer" 
              className="block bg-[#0b0b10]/40 hover:bg-[#121421]/60 transition-all duration-200 rounded-lg px-3 py-2 border border-[#222631] hover:border-[#8b5cf6]/30 cursor-pointer group"
            >
              <p className="text-gray-400 text-xs font-normal group-hover:text-white transition-colors">Senior Full-Stack Engineer, Product</p>
            </Link>
            
            <Link 
              to="/careers/backend-engineer" 
              className="block bg-[#0b0b10]/40 hover:bg-[#121421]/60 transition-all duration-200 rounded-lg px-3 py-2 border border-[#222631] hover:border-[#8b5cf6]/30 cursor-pointer group"
            >
              <p className="text-gray-400 text-xs font-normal group-hover:text-white transition-colors">Backend Engineer</p>
            </Link>

            <Link 
              to="/careers/senior-product-marketer" 
              className="block bg-[#0b0b10]/40 hover:bg-[#121421]/60 transition-all duration-200 rounded-lg px-3 py-2 border border-[#222631] hover:border-[#8b5cf6]/30 cursor-pointer group"
            >
              <p className="text-gray-400 text-xs font-normal group-hover:text-white transition-colors">Senior Product Marketer</p>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CompanyDropdownCard;