"use client";

import React from 'react';
import About from './about';
import Value from './value';
import Testimonial from './testimonial';

const AboutCompany = () => {
  return (
    <div className="bg-[#0f0f14] min-h-screen">
      <About />
      <Value />
      <Testimonial />
    </div>
  );
};

export default AboutCompany;
