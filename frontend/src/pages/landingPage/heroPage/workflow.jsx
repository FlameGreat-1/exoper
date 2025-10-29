import React from 'react';
import { Globe, CheckCircle, Database } from 'lucide-react';

export default function NetworkFlow() {
  return (
    <div className="min-h-screen bg-[#0a0a0f] text-white overflow-hidden">
      {/* Main Content Container */}
      <div className="flex h-screen">
        {/* Left Side - Text Content */}
        <div className="w-2/5 flex flex-col justify-center pl-20 pr-12 relative">
          {/* Vertical Line with Circle */}
          <div className="absolute left-20 top-0 bottom-0 w-px">
            <div className="relative h-full">
              <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-3 h-3 bg-purple-500 rounded-full"></div>
              <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-0.5 h-24 bg-gradient-to-b from-purple-600 to-purple-900"></div>
              <div className="absolute top-1/3 left-1/2 -translate-x-1/2 translate-y-24 w-12 h-24 border-l-2 border-b-2 border-purple-900 rounded-bl-3xl"></div>
            </div>
          </div>

          <div className="space-y-6 z-10">
            <div className="inline-block">
              <span className="text-purple-400 text-sm font-medium tracking-wide">Network and Connect</span>
            </div>
            
            <h1 className="text-5xl font-bold leading-tight">
              Interconnect your application<br />
              seamlessly with highly<br />
              performant networking
            </h1>
            
            <p className="text-gray-400 text-lg leading-relaxed max-w-xl">
              Exoper provides automated service discovery, blazing fast networking, and support for any protocol, all out of the box.
            </p>
            
            <div className="flex items-center gap-2 text-white font-medium">
              <span>Learn More</span>
              <span>→</span>
            </div>

            {/* Replaces Icons */}
            <div className="flex items-center gap-4 mt-12 pt-8">
              <span className="text-gray-500 text-sm flex items-center gap-2">
                <svg className="w-4 h-4" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 2a6 6 0 100 12A6 6 0 008 2zM4 8a4 4 0 118 0 4 4 0 01-8 0z"/>
                </svg>
                Replaces
              </span>
              <div className="flex items-center gap-3">
                <div className="w-6 h-6 bg-gray-800 rounded flex items-center justify-center">
                  <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                </div>
                <div className="w-6 h-6 bg-gray-800 rounded flex items-center justify-center">
                  <div className="w-3 h-3 bg-purple-500 rounded"></div>
                </div>
                <div className="w-6 h-6 bg-gray-800 rounded flex items-center justify-center text-green-500 font-bold text-xs">
                  N
                </div>
                <div className="w-6 h-6 bg-gray-800 rounded flex items-center justify-center">
                  <div className="w-3 h-3 bg-blue-400" style={{clipPath: 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)'}}>
                  </div>
                </div>
                <div className="w-6 h-6 bg-gray-800 rounded flex items-center justify-center">
                  <svg className="w-4 h-4 text-blue-400" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M0 0h7v7H0zM9 0h7v7H9zM0 9h7v7H0zM9 9h7v7H9z"/>
                  </svg>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Side - Network Diagram */}
        <div className="w-3/5 relative flex items-center justify-center">
          {/* Globe Icons with Dashed Lines */}
          <div className="absolute top-20 left-32">
            <Globe className="w-12 h-12 text-purple-600 opacity-50" strokeWidth={1} />
            <div className="absolute top-16 left-6 w-px h-32 border-l-2 border-dashed border-purple-900"></div>
          </div>
          
          <div className="absolute top-16 left-1/2 -translate-x-1/2">
            <Globe className="w-12 h-12 text-purple-600 opacity-50" strokeWidth={1} />
            <div className="absolute top-16 left-6 w-px h-24 border-l-2 border-dashed border-purple-900"></div>
          </div>
          
          <div className="absolute top-24 right-32">
            <Globe className="w-12 h-12 text-purple-600 opacity-50" strokeWidth={1} />
            <div className="absolute top-16 left-6 w-px h-32 border-l-2 border-dashed border-purple-900"></div>
          </div>

          {/* Main Flow Container */}
          <div className="relative w-full h-full flex items-center justify-center">
            {/* Ackee Analytics Card - Left */}
            <div className="absolute left-12 top-1/2 -translate-y-1/2 bg-[#1a1a24] border border-gray-800 rounded-lg p-4 w-56">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 bg-teal-500 rounded-lg flex items-center justify-center">
                  <div className="w-4 h-4 bg-teal-300 rounded-full"></div>
                </div>
                <span className="font-medium">ackee analytics</span>
              </div>
              <div className="text-xs text-gray-400 mb-2">ackee-prod.up.Exoper.app</div>
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <CheckCircle className="w-3 h-3" />
                <span>Just deployed</span>
              </div>
            </div>

            {/* Central Shield Icon */}
            <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-20">
              <div className="w-16 h-16 rounded-full bg-[#1a1a24] border-2 border-purple-600 flex items-center justify-center">
                <svg className="w-8 h-8 text-purple-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <path d="M9 12l2 2 4-4"/>
                </svg>
              </div>
            </div>

            {/* Connection Lines - Ackee to Shield */}
            <svg className="absolute left-0 top-0 w-full h-full pointer-events-none" style={{zIndex: 1}}>
              <defs>
                <linearGradient id="grad1" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" style={{stopColor: '#4c1d95', stopOpacity: 0.3}} />
                  <stop offset="100%" style={{stopColor: '#7c3aed', stopOpacity: 0.6}} />
                </linearGradient>
              </defs>
              {/* Ackee to Shield */}
              <path d="M 280 50% L 48% 50%" stroke="url(#grad1)" strokeWidth="2" fill="none" strokeDasharray="5,5"/>
            </svg>

            {/* Frontend Card - Top Right */}
            <div className="absolute right-1/4 top-32 bg-[#1a1a24] border border-gray-800 rounded-lg p-4 w-56">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 bg-yellow-500 rounded-lg flex items-center justify-center text-black font-bold text-sm">
                  JS
                </div>
                <span className="font-medium">frontend</span>
              </div>
              <div className="text-xs text-gray-400 mb-2">frontend-prod.up.Exoper.app</div>
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <CheckCircle className="w-3 h-3" />
                <span>Just deployed</span>
              </div>
            </div>

            {/* Connection Lines - Frontend to Shield */}
            <svg className="absolute left-0 top-0 w-full h-full pointer-events-none" style={{zIndex: 1}}>
              <path d="M 57% 200 L 52% 45%" stroke="url(#grad1)" strokeWidth="2" fill="none" strokeDasharray="5,5"/>
            </svg>

            {/* API Gateway Card - Right Middle */}
            <div className="absolute right-12 top-1/2 -translate-y-8 bg-[#1a1a24] border border-gray-800 rounded-lg p-4 w-56">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 bg-gray-700 rounded-lg flex items-center justify-center">
                  <svg className="w-5 h-5 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="3"/>
                    <path d="M12 1v6m0 6v6M5.6 5.6l4.2 4.2m4.4 4.4l4.2 4.2M1 12h6m6 0h6M5.6 18.4l4.2-4.2m4.4-4.4l4.2-4.2"/>
                  </svg>
                </div>
                <span className="font-medium">api gateway</span>
              </div>
              <div className="text-xs text-gray-400 mb-2">api-prod.up.Exoper.app</div>
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <CheckCircle className="w-3 h-3" />
                <span>Just deployed</span>
              </div>
            </div>

            {/* Connection Lines - Shield to API Gateway */}
            <svg className="absolute left-0 top-0 w-full h-full pointer-events-none" style={{zIndex: 1}}>
              <path d="M 54% 50% L 72% 48%" stroke="url(#grad1)" strokeWidth="2" fill="none" strokeDasharray="5,5"/>
            </svg>

            {/* Message Icon - Center Bottom */}
            <div className="absolute left-1/2 -translate-x-1/2 top-2/3 translate-y-8">
              <div className="w-12 h-12 rounded-full bg-[#1a1a24] border-2 border-gray-800 flex items-center justify-center">
                <svg className="w-6 h-6 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
                </svg>
              </div>
            </div>

            {/* Connection Lines - Shield to Message and beyond */}
            <svg className="absolute left-0 top-0 w-full h-full pointer-events-none" style={{zIndex: 1}}>
              <path d="M 50% 54% L 50% 62%" stroke="url(#grad1)" strokeWidth="2" fill="none" strokeDasharray="5,5"/>
              <path d="M 50% 68% L 50% 75%" stroke="url(#grad1)" strokeWidth="2" fill="none" strokeDasharray="5,5"/>
              <path d="M 54% 48% L 70% 58%" stroke="url(#grad1)" strokeWidth="2" fill="none" strokeDasharray="5,5"/>
            </svg>

            {/* Backend Card - Right Bottom */}
            <div className="absolute right-20 bottom-32 bg-[#1a1a24] border border-gray-800 rounded-lg p-4 w-56">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 bg-gradient-to-br from-yellow-400 to-orange-500 rounded-lg flex items-center justify-center">
                  <div className="w-4 h-4 bg-white rounded"></div>
                </div>
                <span className="font-medium">backend</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <CheckCircle className="w-3 h-3" />
                <span>Just deployed</span>
              </div>
            </div>

            {/* Postgres Card - Bottom Center */}
            <div className="absolute left-1/2 -translate-x-1/2 bottom-20 bg-[#1a1a24] border border-gray-800 rounded-lg p-4 w-56">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                  <Database className="w-5 h-5 text-white" />
                </div>
                <span className="font-medium">postgres</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-gray-500 mb-2">
                <CheckCircle className="w-3 h-3" />
                <span>Just deployed</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-gray-600">
                <Database className="w-3 h-3" />
                <span>pg-data</span>
              </div>
            </div>

            {/* Connection Lines - Backend to Postgres */}
            <svg className="absolute left-0 top-0 w-full h-full pointer-events-none" style={{zIndex: 1}}>
              <path d="M 72% 65% L 58% 78%" stroke="url(#grad1)" strokeWidth="2" fill="none" strokeDasharray="5,5"/>
            </svg>
          </div>

          {/* Bottom gradient line */}
          <div className="absolute bottom-0 left-0 right-0 h-32">
            <div className="absolute bottom-0 left-20 w-96 h-0.5 bg-gradient-to-r from-purple-900 via-blue-900 to-transparent rounded-full opacity-50"></div>
            <div className="absolute bottom-0 left-20 w-64 h-16 border-l-2 border-b-2 border-purple-900 rounded-bl-3xl opacity-50"></div>
          </div>
        </div>
      </div>
    </div>
  );
}