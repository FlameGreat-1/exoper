"use client";

import React from 'react';
import About from './about';
import Value from './value';
import Testimonial from './testimonial';
import Born from './born';

const AboutCompany = () => {
  return (
    <div className="bg-[#0f0f14] min-h-screen">
      <About />
      <Value />
      <Testimonial />
      <Born />
    </div>
  );
};

export default AboutCompany;
