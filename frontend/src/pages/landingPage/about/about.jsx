import React from "react";

const About = () => {
  return (
    <main className="bg-[#0f0f14] min-h-screen text-white antialiased">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-12 py-12 sm:py-16 lg:py-20">
        <div className="text-center mb-20 sm:mb-24 lg:mb-32">
          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-[64px] leading-[1] font-extrabold tracking-tight">EXOPER—what?</h1>
          <p className="text-gray-400 text-base sm:text-lg mt-3 sm:mt-4 px-4">Get to know a bit about the team and what drives us</p>
        </div>

        <section className="mb-24 sm:mb-32 lg:mb-44">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 sm:gap-12 lg:gap-16 items-center">
            <div className="lg:pr-8 order-1 lg:order-1">
              <h2 className="text-2xl sm:text-3xl font-semibold mb-4 sm:mb-6">We believe...</h2>
              <p className="text-gray-300 text-base sm:text-lg leading-relaxed">
                You should simply be able to work on your core product without having to worry about
                infrastructure and how to deploy it.
              </p>
            </div>

            <div className="relative order-2 lg:order-2">
              <img 
                src="/images/features/robot.png" 
                alt="Deployment workflow illustration" 
                className="w-full h-auto max-w-[500px] sm:max-w-[600px] lg:max-w-[700px] mx-auto"
              />
            </div>
          </div>
        </section>

        <section>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 sm:gap-12 lg:gap-16 items-start">
            <div className="lg:pr-8 order-1 lg:order-1">
              <h2 className="text-2xl sm:text-3xl font-semibold mb-4 sm:mb-6">We want to help...</h2>
              <p className="text-gray-300 text-base sm:text-lg leading-relaxed">
                More great ideas materialize by reducing developer friction around deployments, clusters, Docker, and many other things that can go wrong.
              </p>
            </div>

            <div className="relative order-2 lg:order-2">
              <img 
                src="/images/features/build.png" 
                alt="Infrastructure complexity illustration" 
                className="w-full h-auto max-w-[500px] sm:max-w-[600px] lg:max-w-[700px] mx-auto"
              />
            </div>
          </div>
        </section>
      </div>
    </main>
  );
};

export default About;