import React from 'react';
import Hero from './heroPage/hero';
import Services1 from './services/services1'; // Make sure this path is correct
import Services2 from './services/services2'; // Make sure this path is correct

const Home = () => {
  return (
    <>
      <Hero />
      <Services1 />
      <Services2 />
    </>
  );
};

export default Home;
