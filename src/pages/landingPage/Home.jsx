import React from 'react';
import Hero from './heroPage/hero';
import Services1 from './services/services1'; 
import Services2 from './services/services2'; 
import Services3 from './services/services3'; 
import Testimonial from './about/testimonial'; 

const Home = () => {
  return (
    <>
      <Hero />
      <Services1 />
      <Services3 />
      <Services2 />
      <Testimonial /> 
    </>
  );
};

export default Home;
