import React from 'react';
import { Link } from 'react-router-dom';

const PricingDropdownCard = () => {
  return (
    <div className="bg-[#1a1a2e] backdrop-blur-xl p-4 rounded-lg shadow-2xl border border-[#2d2d44] w-[500px]">
      <div className="grid grid-cols-2 gap-4">
        
        <Link to="/pricing" className="group relative overflow-hidden rounded-lg bg-[#13132a] p-4 border border-[#2d2d44] hover:border-[#7c3aed]/50 transition-all duration-300 cursor-pointer hover:shadow-lg hover:shadow-purple-500/10">
          <div className="relative z-10">
            <h3 className="text-white text-base font-medium mb-1">Products</h3>
            <p className="text-gray-400 text-xs">Explore our pricing and plans</p>
          </div>
          
          <div className="relative w-full h-24 mt-3">
            <svg className="absolute inset-0 w-full h-full" viewBox="0 0 400 200" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M 50 150 Q 150 100, 250 120 T 450 80" stroke="url(#gradient1-pricing)" strokeWidth="2" fill="none" opacity="0.4"/>
              <path d="M 30 160 Q 130 110, 230 130 T 430 90" stroke="url(#gradient2-pricing)" strokeWidth="1.5" fill="none" opacity="0.3"/>
              
              <circle cx="80" cy="140" r="6" fill="#8b5cf6" opacity="0.9">
                <animate attributeName="opacity" values="0.9;0.5;0.9" dur="3s" repeatCount="indefinite"/>
              </circle>
              
              <circle cx="250" cy="100" r="5" fill="#a78bfa" opacity="0.7">
                <animate attributeName="opacity" values="0.7;0.4;0.7" dur="2.5s" repeatCount="indefinite"/>
              </circle>
              
              <circle cx="350" cy="70" r="4" fill="#c4b5fd" opacity="0.6">
                <animate attributeName="opacity" values="0.6;0.3;0.6" dur="2s" repeatCount="indefinite"/>
              </circle>
              
              <g transform="translate(280, 95) rotate(-15)">
                <rect x="0" y="0" width="60" height="8" fill="url(#planeGradient-pricing)" opacity="0.8" rx="4"/>
                <rect x="15" y="-20" width="2" height="12" fill="url(#planeGradient-pricing)" opacity="0.7"/>
                <rect x="45" y="8" width="7" height="10" fill="url(#planeGradient-pricing)" opacity="0.7"/>
                <circle cx="65" cy="4" r="3" fill="#a78bfa" opacity="0.9"/>
              </g>
              
              <defs>
                <linearGradient id="gradient1-pricing" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#6366f1" stopOpacity="0.4"/>
                  <stop offset="50%" stopColor="#8b5cf6" stopOpacity="0.6"/>
                  <stop offset="100%" stopColor="#a78bfa" stopOpacity="0.3"/>
                </linearGradient>
                <linearGradient id="gradient2-pricing" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#4338ca" stopOpacity="0.3"/>
                  <stop offset="100%" stopColor="#7c3aed" stopOpacity="0.4"/>
                </linearGradient>
                <linearGradient id="planeGradient-pricing" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#8b5cf6"/>
                  <stop offset="100%" stopColor="#a78bfa"/>
                </linearGradient>
              </defs>
            </svg>
          </div>
          
          <div className="absolute inset-0 bg-gradient-to-tr from-purple-600/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-lg"></div>
        </Link>

        <div className="rounded-lg bg-[#13132a] p-4 border border-[#2d2d44]">
          <div className="flex items-center gap-2 mb-1">
            <h3 className="text-white text-base font-medium">Services</h3>
            <span className="bg-[#7c3aed]/20 text-purple-300 text-xs font-medium px-2 py-0.5 rounded-md border border-[#7c3aed]/30">5</span>
          </div>
          <p className="text-gray-400 text-xs mb-3">Discover what we offer</p>
          
          <div className="space-y-1.5">
            <Link 
              to="/services/ai-development" 
              className="block bg-[#0f0f1e] hover:bg-[#16162d] transition-all duration-200 rounded-md px-3 py-2 border border-[#2d2d44] hover:border-[#7c3aed]/30 cursor-pointer group"
            >
              <p className="text-gray-300 text-xs font-normal group-hover:text-white transition-colors">AI Development</p>
            </Link>
            
            <Link 
              to="/services/cloud-infrastructure" 
              className="block bg-[#0f0f1e] hover:bg-[#16162d] transition-all duration-200 rounded-md px-3 py-2 border border-[#2d2d44] hover:border-[#7c3aed]/30 cursor-pointer group"
            >
              <p className="text-gray-300 text-xs font-normal group-hover:text-white transition-colors">Cloud Infrastructure</p>
            </Link>

            <Link 
              to="/services/custom-software" 
              className="block bg-[#0f0f1e] hover:bg-[#16162d] transition-all duration-200 rounded-md px-3 py-2 border border-[#2d2d44] hover:border-[#7c3aed]/30 cursor-pointer group"
            >
              <p className="text-gray-300 text-xs font-normal group-hover:text-white transition-colors">Custom Software</p>
            </Link>

            <Link 
              to="/services/consulting" 
              className="block bg-[#0f0f1e] hover:bg-[#16162d] transition-all duration-200 rounded-md px-3 py-2 border border-[#2d2d44] hover:border-[#7c3aed]/30 cursor-pointer group"
            >
              <p className="text-gray-300 text-xs font-normal group-hover:text-white transition-colors">Technical Consulting</p>
            </Link>

            <Link 
              to="/services/support" 
              className="block bg-[#0f0f1e] hover:bg-[#16162d] transition-all duration-200 rounded-md px-3 py-2 border border-[#2d2d44] hover:border-[#7c3aed]/30 cursor-pointer group"
            >
              <p className="text-gray-300 text-xs font-normal group-hover:text-white transition-colors">24/7 Support</p>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PricingDropdownCard;