import React from 'react';
import { motion } from 'framer-motion';

interface TechStacksProps {
  className?: string;
}

const TechStacks: React.FC<TechStacksProps> = ({ className = '' }) => {
  const techStacks = [
    {
      name: 'Python',
      gradient: 'from-blue-500 to-blue-700',
      shadowColor: 'rgba(66, 153, 225, 0.5)',
      logo: (
        <svg viewBox="0 0 48 48" className="w-10 h-10">
          <path fill="#3776AB" d="M23.7 2C12.5 2 13.6 6.7 13.6 6.7v4.9h10.3v1.5H9.2S2 12.6 2 23.9c0 11.3 7.2 10.9 7.2 10.9h4.3v-6.1s-.2-7.2 7.1-7.2h10.3s6.9.1 6.9-6.7V8.7S39.7 2 28.5 2h-4.8z"/>
          <path fill="#FFD43B" d="M24.3 46c11.2 0 10.1-4.7 10.1-4.7v-4.9H24.1v-1.5h14.7S46 35.4 46 24.1c0-11.3-7.2-10.9-7.2-10.9h-4.3v6.1s.2 7.2-7.1 7.2H17.1s-6.9-.1-6.9 6.7v6.1S8.3 46 19.5 46h4.8z"/>
        </svg>
      ),
    },
    {
      name: 'AI',
      gradient: 'from-purple-500 to-indigo-600',
      shadowColor: 'rgba(159, 122, 234, 0.5)',
      logo: (
        <svg viewBox="0 0 48 48" className="w-10 h-10">
          <circle cx="24" cy="24" r="20" fill="url(#aiGrad)" />
          <path fill="#fff" d="M24 12v24M12 24h24" strokeWidth="4" stroke="#fff"/>
          <path fill="#fff" d="M16 16l16 16M16 32l16-16" strokeWidth="4" stroke="#fff"/>
          <defs>
            <radialGradient id="aiGrad" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#a78bfa"/>
              <stop offset="100%" stopColor="#4c1d95"/>
            </radialGradient>
          </defs>
        </svg>
      ),
    },
    {
      name: 'JavaScript',
      gradient: 'from-yellow-400 to-yellow-600',
      shadowColor: 'rgba(236, 201, 75, 0.5)',
      logo: (
        <svg viewBox="0 0 48 48" className="w-10 h-10">
          <path fill="#F7DF1E" d="M6 42V6h36v36H6z"/>
          <path d="M29.5 34.2c0 3.8-2.3 5.6-5.8 5.6-3.1 0-5.2-1.6-6.2-3.6l3.4-2c.7 1.2 1.4 2.2 2.9 2.2 1.5 0 2.4-.6 2.4-2.9V21h3.3v13.2zM16.8 34.1c0 3.6-2.1 5.5-5.5 5.5-2.9 0-4.6-1.5-5.5-3.4l3.3-1.9c.6 1.2 1.1 2 2.2 2 1 0 1.7-.4 1.7-2.2V21h3.8v13.1z"/>
        </svg>
      ),
    },
    {
      name: 'React',
      gradient: 'from-cyan-400 to-blue-500',
      shadowColor: 'rgba(56, 189, 248, 0.5)',
      logo: (
        <svg viewBox="0 0 48 48" className="w-10 h-10">
          <circle cx="24" cy="24" r="3" fill="#61DAFB"/>
          <g stroke="#61DAFB" strokeWidth="2" fill="none">
            <ellipse cx="24" cy="24" rx="11" ry="4.5"/>
            <ellipse cx="24" cy="24" rx="11" ry="4.5" transform="rotate(60 24 24)"/>
            <ellipse cx="24" cy="24" rx="11" ry="4.5" transform="rotate(120 24 24)"/>
          </g>
        </svg>
      ),
    },
    {
      name: 'Database',
      gradient: 'from-green-500 to-emerald-700',
      shadowColor: 'rgba(72, 187, 120, 0.5)',
      logo: (
        <svg viewBox="0 0 48 48" className="w-10 h-10">
          <ellipse cx="24" cy="10" rx="14" ry="6" fill="#34D399"/>
          <path fill="#10B981" d="M10 10v10c0 3.3 6.3 6 14 6s14-2.7 14-6V10H10z"/>
          <path fill="#059669" d="M10 20v10c0 3.3 6.3 6 14 6s14-2.7 14-6V20H10z"/>
          <path fill="#047857" d="M10 30v8c0 3.3 6.3 6 14 6s14-2.7 14-6v-8H10z"/>
        </svg>
      ),
    },
    {
        name: 'Docker',
        gradient: 'from-blue-400 to-blue-600',
        shadowColor: 'rgba(66, 153, 225, 0.5)',
        logo: (
          <svg viewBox="0 0 48 48" className="w-10 h-10">
            <path fill="#2496ED" d="M24 43c-11.6 0-21-9.4-21-21s9.4-21 21-21 21 9.4 21 21-9.4 21-21 21z" fillOpacity="0.2"/>
            <path fill="#2496ED" d="M13 26h4v-4h-4v4zm5 0h4v-4h-4v4zm-5-5h4v-4h-4v4zm5 0h4v-4h-4v4zm5 0h4v-4h-4v4zm5-5h4v-4h-4v4zm-5 0h4v-4h-4v4zm10 10c.7 0 1.4-.3 1.9-.8.3-.4.6-.8.7-1.3.2-.6.1-1.2-.2-1.8-.3-.5-.7-.9-1.2-1.2-.5-.3-1.1-.3-1.7-.2-.1-1.1-.6-2.2-1.4-3-.8-.8-1.9-1.3-3-1.4-1.2-.1-2.3.3-3.2 1-.9.8-1.5 1.8-1.6 3-.9-.3-1.9-.2-2.7.3-.8.5-1.4 1.3-1.6 2.2-.2.9 0 1.9.5 2.7.5.8 1.3 1.4 2.2 1.6H33z"/>
          </svg>
        ),
      },
      {
        name: 'AWS',
        gradient: 'from-orange-400 to-orange-600',
        shadowColor: 'rgba(237, 137, 54, 0.5)',
        logo: (
          <svg viewBox="0 0 48 48" className="w-10 h-10">
            <path fill="#FF9900" d="M13.7 23.8c0 .6.1 1 .2 1.3.2.3.4.7.7 1.1.1.1.2.2.2.3s0 .2-.1.3l-1 .7c-.1.1-.2.1-.3.1-.1 0-.3-.1-.4-.2-.2-.2-.4-.5-.5-.7-.1-.3-.3-.6-.4-1-1.1 1.3-2.5 1.9-4.1 1.9-1.2 0-2.1-.3-2.8-1-.7-.7-1-1.5-1-2.6 0-1.2.4-2.1 1.3-2.8.8-.7 2-.1 3.4-1.1.2 0 .3-.1.5-.1.2-.1.3-.1.5-.2v-.8c0-.8-.2-1.4-.5-1.7-.4-.4-.9-.6-1.7-.6-.4 0-.8.1-1.1.2-.3.1-.7.3-1 .5-.2.1-.3.2-.4.2-.1 0-.2.1-.3.1-.3 0-.4-.2-.4-.5v-.8c0-.3 0-.5.1-.6.1-.1.2-.2.5-.4.4-.3.9-.5 1.5-.7.6-.2 1.2-.3 1.9-.3 1.5 0 2.5.3 3.2 1 .7.7 1 1.7 1 3.1v4.1z"/>
            <path fill="#FF9900" d="M40.7 32.7c-4.9 3.6-12.1 5.5-18.2 5.5-8.6 0-16.4-3.2-22.2-8.5-.5-.4 0-1 .5-.7 6.6 3.8 14.7 6.1 23.1 6.1 5.7 0 11.9-1.2 17.6-3.6.9-.4 1.6.6.7 1.2z"/>
            <path fill="#FF9900" d="M42.6 30.6c-.6-.8-4.1-.4-5.7-.2-.5.1-.5-.4-.1-.7 2.8-2 7.4-1.4 7.9-.7.5.7-.1 5.4-2.8 7.7-.4.3-.8.2-.6-.3.6-1.5 1.9-4.9 1.3-5.8z"/>
          </svg>
        ),
      },
      {
        name: 'Node.js',
        gradient: 'from-green-500 to-green-700',
        shadowColor: 'rgba(72, 187, 120, 0.5)',
        logo: (
          <svg viewBox="0 0 48 48" className="w-10 h-10">
            <path fill="#8CC84B" d="M23.9 4c-.7 0-1.3.2-1.9.5L7.9 13.5c-1.1.7-1.9 2-1.9 3.4v18c0 1.4.7 2.7 1.9 3.4l14.1 9c.6.3 1.2.5 1.9.5s1.3-.2 1.9-.5l14.1-9c1.1-.7 1.9-2 1.9-3.4v-18c0-1.4-.7-2.7-1.9-3.4L25.8 4.5c-.6-.3-1.2-.5-1.9-.5z"/>
            <path fill="#fff" d="M24 8.3v31.9c.5 0 1-.1 1.4-.4l14.1-8.9c1.1-.7 1.6-1.9 1.6-3.2V16.5c0-1.3-.5-2.5-1.6-3.2L25.4 4.4c-.4-.3-.9-.4-1.4-.4z" opacity=".2"/>
            <path fill="#fff" d="M14.4 29.9c.2.1.4.1.6.1.2 0 .4 0 .6-.1l1.9-1.1c.4-.2.7-.8.7-1.3v-2.3c0-.5-.3-1-.7-1.3l-1.9-1.1c-.2-.1-.4-.1-.6-.1-.2 0-.4 0-.6.1l-1.9 1.1c-.4.2-.7.8-.7 1.3v2.3c0 .5.3 1 .7 1.3l1.9 1.1zm16.5-16.6c-.2-.1-.4-.1-.6-.1-.2 0-.4 0-.6.1l-1.9 1.1c-.4.2-.7.8-.7 1.3v9.2c0 .4.2.7.5.9.3.2.7.2 1 0l1.9-1.1c.4-.2.7-.8.7-1.3v-9.2c0-.5-.3-1-.7-1.3l-1.6-.6z"/>
          </svg>
        ),
      },
      {
        name: 'FastAPI',
        gradient: 'from-teal-400 to-teal-600',
        shadowColor: 'rgba(56, 178, 172, 0.5)',
        logo: (
          <svg viewBox="0 0 48 48" className="w-10 h-10">
            <path fill="#009688" d="M24 4L6 14v20l18 10 18-10V14L24 4z"/>
            <path fill="#fff" d="M24 24v10m0-20v6m-8 14h16" strokeWidth="4" stroke="#fff"/>
            <path fill="#fff" d="M32 20l-8-6-8 6" strokeWidth="4" stroke="#fff"/>
          </svg>
        ),
      },
      {
        name: 'HTML',
        gradient: 'from-red-500 to-red-700',
        shadowColor: 'rgba(245, 101, 101, 0.5)',
        logo: (
          <svg viewBox="0 0 48 48" className="w-10 h-10">
            <path fill="#E44D26" d="M7.2 6l3 34 13.8 4 13.8-4 3-34H7.2z"/>
            <path fill="#F16529" d="M24 10v30.4l11.2-3.2 2.5-27.2H24z"/>
            <path fill="#EBEBEB" d="M24 25h-5.6l-.4-4.4H24v-4.3h-10.5l.1 1.2 1.1 12.4H24V25zm0 11.5l-.1.1-5-1.4-.3-3.6h-4.5l.6 7 9.2 2.5.1-.1v-4.5z"/>
            <path fill="#fff" d="M23.9 25v4.3h5.3l-.5 5.6-4.8 1.3v4.5l8.8-2.5.1-.8 1-11.2.1-1.2h-10zm0-8.7v4.3h10.4l.1-.9.2-2.2.1-1.2H23.9z"/>
          </svg>
        ),
      },
    ];
  
    const allItems = [...techStacks, ...techStacks];
    return (
        <div className={`w-full overflow-hidden py-6 ${className}`}>
          <div className="relative">
            <motion.div 
              className="flex space-x-16"
              animate={{ x: [0, -50 * techStacks.length] }}
              transition={{ 
                repeat: Infinity, 
                duration: 30,
                ease: "linear"
              }}
            >
              {allItems.map((tech, index) => (
                <div key={`${tech.name}-${index}`} className="flex-none">
                  <div 
                    className={`relative w-20 h-20 rounded-xl bg-gradient-to-br ${tech.gradient} p-0.5 transform transition-transform hover:scale-110 hover:rotate-3`}
                    style={{ 
                      boxShadow: `0 10px 20px ${tech.shadowColor}`,
                      perspective: '1000px'
                    }}
                  >
                    <div className="absolute inset-0 bg-black bg-opacity-20 rounded-xl backdrop-blur-sm"></div>
                    <div className="absolute inset-0.5 bg-gray-900 rounded-lg flex items-center justify-center overflow-hidden">
                      <div className="relative w-12 h-12 flex items-center justify-center">
                        <div className="transform transition-transform hover:rotate-y-45 duration-300" style={{ transformStyle: 'preserve-3d' }}>
                          {tech.logo}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="mt-2 text-center">
                    <span className="text-xs font-medium text-gray-300">{tech.name}</span>
                  </div>
                </div>
              ))}
            </motion.div>
          </div>
        </div>
      );
    };
    
    export default TechStacks;
    
  
