// src/components/ui/Logo.jsx
import React from 'react';

const Logo = ({ className = '' }) => {
  return (
    <svg 
      className={className} 
      width="32" 
      height="32" 
      viewBox="0 0 32 32" 
      fill="none" 
      xmlns="http://www.w3.org/2000/svg"
    >
      <path 
        d="M16 2L3 9L16 16L29 9L16 2Z" 
        fill="url(#paint0_linear)" 
      />
      <path 
        d="M3 9V23L16 30V16L3 9Z" 
        fill="url(#paint1_linear)" 
        fillOpacity="0.8" 
      />
      <path 
        d="M29 9V23L16 30V16L29 9Z" 
        fill="url(#paint2_linear)" 
        fillOpacity="0.9" 
      />
      <defs>
        <linearGradient id="paint0_linear" x1="3" y1="9" x2="29" y2="9" gradientUnits="userSpaceOnUse">
          <stop stopColor="#6C8CFF" />
          <stop offset="1" stopColor="#5D1EB2" />
        </linearGradient>
        <linearGradient id="paint1_linear" x1="3" y1="16" x2="16" y2="30" gradientUnits="userSpaceOnUse">
          <stop stopColor="#6C8CFF" />
          <stop offset="1" stopColor="#5D1EB2" />
        </linearGradient>
        <linearGradient id="paint2_linear" x1="16" y1="16" x2="29" y2="23" gradientUnits="userSpaceOnUse">
          <stop stopColor="#6C8CFF" />
          <stop offset="1" stopColor="#5D1EB2" />
        </linearGradient>
      </defs>
    </svg>
  );
};

export default Logo;
