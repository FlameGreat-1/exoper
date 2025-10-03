import React from 'react';
import { Link } from 'react-router-dom';

const PricingDropdownCard = () => {
  return (
    <div className="bg-[#0a0a0a] p-4 rounded-xl shadow-2xl border border-[#2a2a2a] w-[650px]">
      <div className="flex gap-4 bg-gradient-to-b from-[#1a1a1a] to-[#0f0f0f] rounded-2xl p-4 shadow-xl border border-[#2a2a2a]">
        
        <Link to="/pricing" className="flex-1 relative overflow-hidden rounded-xl bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] p-4 border border-[#2a2a2a] hover:border-purple-500/50 transition-colors duration-200 cursor-pointer">
          <h3 className="text-white text-xl font-semibold mb-2">Products</h3>
          <p className="text-gray-400 text-sm mb-4">Explore our pricing and plans</p>
          
          <div className="relative w-full h-36">
            <svg className="absolute inset-0 w-full h-full" viewBox="0 0 400 200" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M 50 150 Q 150 100, 250 120 T 450 80" stroke="url(#gradient1)" strokeWidth="2" fill="none" opacity="0.3"/>
              <path d="M 30 160 Q 130 110, 230 130 T 430 90" stroke="url(#gradient2)" strokeWidth="1.5" fill="none" opacity="0.2"/>
              
              <circle cx="80" cy="140" r="6" fill="#8b5cf6" opacity="0.8">
                <animate attributeName="opacity" values="0.8;0.4;0.8" dur="3s" repeatCount="indefinite"/>
              </circle>
              
              <circle cx="250" cy="100" r="5" fill="#a78bfa" opacity="0.6">
                <animate attributeName="opacity" values="0.6;0.3;0.6" dur="2.5s" repeatCount="indefinite"/>
              </circle>
              
              <circle cx="350" cy="70" r="4" fill="#c4b5fd" opacity="0.5">
                <animate attributeName="opacity" values="0.5;0.25;0.5" dur="2s" repeatCount="indefinite"/>
              </circle>
              
              <g transform="translate(280, 95) rotate(-15)">
                <rect x="0" y="0" width="60" height="8" fill="url(#planeGradient)" opacity="0.7" rx="4"/>
                <rect x="15" y="-20" width="2" height="12" fill="url(#planeGradient)" opacity="0.6"/>
                <rect x="45" y="8" width="7" height="10" fill="url(#planeGradient)" opacity="0.6"/>
                <circle cx="65" cy="4" r="3" fill="#a78bfa" opacity="0.8"/>
              </g>
              
              <defs>
                <linearGradient id="gradient1" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#6366f1" stopOpacity="0.3"/>
                  <stop offset="50%" stopColor="#8b5cf6" stopOpacity="0.5"/>
                  <stop offset="100%" stopColor="#a78bfa" stopOpacity="0.2"/>
                </linearGradient>
                <linearGradient id="gradient2" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#4338ca" stopOpacity="0.2"/>
                  <stop offset="100%" stopColor="#7c3aed" stopOpacity="0.3"/>
                </linearGradient>
                <linearGradient id="planeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="#8b5cf6"/>
                  <stop offset="100%" stopColor="#a78bfa"/>
                </linearGradient>
              </defs>
            </svg>
          </div>
        </Link>

        <div className="flex-1 rounded-xl bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] p-4 border border-[#2a2a2a]">
          <div className="flex items-center gap-3 mb-2">
            <h3 className="text-white text-xl font-semibold">Services</h3>
            <span className="bg-purple-600/30 text-purple-400 text-sm font-medium px-2.5 py-0.5 rounded-md border border-purple-500/30">5</span>
          </div>
          <p className="text-gray-400 text-sm mb-4">Discover what we offer</p>
          
          <div className="space-y-2">
            <Link 
              to="/services/ai-development" 
              className="block bg-[#1f1f1f] hover:bg-[#252525] transition-colors duration-200 rounded-lg px-4 py-3 border border-[#2a2a2a] cursor-pointer"
            >
              <p className="text-gray-300 text-sm font-medium">AI Development</p>
            </Link>
            
            <Link 
              to="/services/cloud-infrastructure" 
              className="block bg-[#1f1f1f] hover:bg-[#252525] transition-colors duration-200 rounded-lg px-4 py-3 border border-[#2a2a2a] cursor-pointer"
            >
              <p className="text-gray-300 text-sm font-medium">Cloud Infrastructure</p>
            </Link>

            <Link 
              to="/services/custom-software" 
              className="block bg-[#1f1f1f] hover:bg-[#252525] transition-colors duration-200 rounded-lg px-4 py-3 border border-[#2a2a2a] cursor-pointer"
            >
              <p className="text-gray-300 text-sm font-medium">Custom Software</p>
            </Link>

            <Link 
              to="/services/consulting" 
              className="block bg-[#1f1f1f] hover:bg-[#252525] transition-colors duration-200 rounded-lg px-4 py-3 border border-[#2a2a2a] cursor-pointer"
            >
              <p className="text-gray-300 text-sm font-medium">Technical Consulting</p>
            </Link>

            <Link 
              to="/services/support" 
              className="block bg-[#1f1f1f] hover:bg-[#252525] transition-colors duration-200 rounded-lg px-4 py-3 border border-[#2a2a2a] cursor-pointer"
            >
              <p className="text-gray-300 text-sm font-medium">24/7 Support</p>
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PricingDropdownCard;
