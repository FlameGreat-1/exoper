"use client";

import React from 'react';
import { BorderBeam } from "../../../components/ui/border-beam";
import { ThreeDScrollTriggerContainer, ThreeDScrollTriggerRow } from "../../../components/ui/3d-scroll-trigger";

const Testimonial = () => {
  return (
    <div className="bg-[#0a0a0f] min-h-screen text-white overflow-x-hidden w-full">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 sm:py-20 lg:py-24 overflow-hidden">
        
        <div className="text-center mb-12 sm:mb-16">
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-4 sm:mb-5">
            Trusted by the best in business
          </h1>
          <p className="text-gray-400 text-base sm:text-lg mb-4 max-w-3xl mx-auto px-4">
            EXOPER supports great software teams anywhere, they are. Hear from some of the teams, building their products on EXOPER.
          </p>
          <a href="#" className="text-purple-400 hover:text-purple-300 text-sm sm:text-base inline-flex items-center gap-2 transition-colors">
            Read customer stories →
          </a>
        </div>

        <div className="relative mb-32 sm:mb-40 lg:mb-48 overflow-hidden">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[80%] max-w-[600px] aspect-square bg-purple-600/20 rounded-full blur-[120px] pointer-events-none"></div>
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[60%] max-w-[400px] aspect-square bg-blue-600/15 rounded-full blur-[100px] pointer-events-none"></div>
          
          <div className="relative grid grid-cols-1 md:grid-cols-2 gap-5 sm:gap-6 max-w-6xl mx-auto">
            
            <div className="group bg-gradient-to-br from-[#1a1a2e]/90 via-[#16162a]/80 to-[#1a1a2e]/90 backdrop-blur-sm rounded-xl p-6 sm:p-8 border border-[#2a2a3e] hover:border-[#3a3a4e] transition-all duration-300 relative overflow-hidden">
              <BorderBeam 
                size={40} 
                duration={8} 
                colorFrom="#7400ff" 
                colorTo="#9b41ff" 
                opacity={0.7}
                glowIntensity={1}
                pauseOnHover={true}
              />
              <div className="flex items-center gap-3 mb-6">
                <div className="w-8 h-8 bg-white rounded flex items-center justify-center">
                  <img src="/logo1.svg" alt="Amcat" className="w-6 h-6" />
                </div>
                <span className="text-white font-semibold text-lg">Amcat</span>
              </div>
              <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                "EXOPER is where we host all of our backend services along with our databases. It's been an integral part of our infrastructure since the very beginning."
              </p>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden">
                  <img src="/avatar1.jpg" alt="Paul O'Connell" className="w-full h-full object-cover" />
                </div>
                <div>
                  <div className="text-white font-medium text-sm">Paul O'Connell</div>
                  <div className="text-gray-400 text-xs">Founder & CEO of Amcat</div>
                </div>
              </div>
            </div>

            <div className="group bg-gradient-to-br from-[#1a1a2e]/90 via-[#16162a]/80 to-[#1a1a2e]/90 backdrop-blur-sm rounded-xl p-6 sm:p-8 border border-[#2a2a3e] hover:border-[#3a3a4e] transition-all duration-300 relative overflow-hidden">
              <BorderBeam 
                size={40} 
                duration={8} 
                colorFrom="#7400ff" 
                colorTo="#9b41ff" 
                opacity={0.7}
                glowIntensity={1}
                pauseOnHover={true}
                reverse={true}
              />
              <div className="flex items-center gap-3 mb-6">
                <div className="w-8 h-8 bg-white rounded flex items-center justify-center">
                  <img src="/logo-spacex.svg" alt="Spacex" className="w-6 h-6" />
                </div>
                <span className="text-white font-semibold text-lg">Spacex</span>
              </div>
              <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                "Even though we already have an internal Kubernetes cluster and infrastructure-at-scale setup, we decided to go with EXOPER so that we weren't spending time writing YAML files when we could be working on the product."
              </p>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden">
                  <img src="/avatar2.jpg" alt="Paul Boller" className="w-full h-full object-cover" />
                </div>
                <div>
                  <div className="text-white font-medium text-sm">Paul Boller</div>
                  <div className="text-gray-400 text-xs">Backend Architect at Spacex</div>
                </div>
              </div>
            </div>

            <div className="group bg-gradient-to-br from-[#1a1a2e]/90 via-[#16162a]/80 to-[#1a1a2e]/90 backdrop-blur-sm rounded-xl p-6 sm:p-8 border border-[#2a2a3e] hover:border-[#3a3a4e] transition-all duration-300 relative overflow-hidden">
              <BorderBeam 
                size={40} 
                duration={8} 
                colorFrom="#7400ff" 
                colorTo="#9b41ff" 
                opacity={0.7}
                glowIntensity={1}
                pauseOnHover={true}
              />
              <div className="flex items-center gap-3 mb-6">
                <div className="w-8 h-8 bg-white rounded flex items-center justify-center">
                  <img src="/logo2.svg" alt="Resend" className="w-6 h-6" />
                </div>
                <span className="text-white font-semibold text-lg">Resend</span>
              </div>
              <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                "EXOPER is a game changer for us. We're currently serving more than 80,000 developers with a small team... every minute spent on infrastructure is a minute we're not building the best email product in the world.
              </p>
              <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                If it wasn't for EXOPER, I don't think we would be able to grow as fast as we are today."
              </p>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden">
                  <img src="/avatar3.jpg" alt="Zeno Rocha" className="w-full h-full object-cover" />
                </div>
                <div>
                  <div className="text-white font-medium text-sm">Zeno Rocha</div>
                  <div className="text-gray-400 text-xs">Founder & CEO of Resend</div>
                </div>
              </div>
            </div>
            <div className="group bg-gradient-to-br from-[#1a1a2e]/90 via-[#16162a]/80 to-[#1a1a2e]/90 backdrop-blur-sm rounded-xl p-6 sm:p-8 border border-[#2a2a3e] hover:border-[#3a3a4e] transition-all duration-300 relative overflow-hidden">
              <BorderBeam 
                size={40} 
                duration={8} 
                colorFrom="#7400ff" 
                colorTo="#9b41ff" 
                opacity={0.7}
                glowIntensity={1}
                pauseOnHover={true}
                reverse={true}
              />
              <div className="flex items-center gap-3 mb-6">
                <div className="w-8 h-8 bg-white rounded flex items-center justify-center">
                  <img src="/logo3.svg" alt="Paloma" className="w-6 h-6" />
                </div>
                <span className="text-white font-semibold text-lg">Paloma</span>
              </div>
              <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                "The flexibility and agility for automation with EXOPER helps us move fast and continuously deploy to production with confidence."
              </p>
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden">
                  <img src="/avatar4.jpg" alt="Stannis Riviera" className="w-full h-full object-cover" />
                </div>
                <div>
                  <div className="text-white font-medium text-sm">Stannis Riviera</div>
                  <div className="text-gray-400 text-xs">Managing Director of Paloma Group</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="text-center mb-12 sm:mb-16">
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-3 sm:mb-4">
            ...and loved by developers
          </h2>
          <p className="text-gray-400 text-base sm:text-lg">
            Join nearly 5M developers building with EXOPER ↗
          </p>
        </div>
        
        <div className="overflow-hidden w-full">
          <ThreeDScrollTriggerContainer className="mb-8 overflow-hidden">
            <ThreeDScrollTriggerRow baseVelocity={3} direction={1} resetIntervalMs={0}>
              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Liam</div>
                    <div className="text-gray-500 text-xs">@liamtech</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed">
                  Team is an easier option. Deploying literally anything on @EXOPER_app is now possible in minutes instead of days. Obsessed. ⚡
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Benjamin Dolinger</div>
                    <div className="text-gray-500 text-xs">@bendolinger</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed">
                  With other apps, infrastructure, and more work to production is @EXOPER_app. Super excited to work with them.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev3.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Jenn</div>
                    <div className="text-gray-500 text-xs">@jennbuilds</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed">
                  @EXOPER_app for prototypes, utilizing the containerized world, infrastructure-as-code, a custom domain local, connect... and that just becomes what you need...
                </p>
              </div>
              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev4.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Arnav</div>
                    <div className="text-gray-500 text-xs">@arnavbuilds</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  Assisted in organizing my services to @EXOPER_app.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev5.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Team Sparky</div>
                    <div className="text-gray-500 text-xs">@teamsparky</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  This CLI is deploying a small app on @EXOPER_app - has been promising the team for over seven...
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev11.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Jessica Lee</div>
                    <div className="text-gray-500 text-xs">@jessicacodes</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  Just migrated our entire backend to @EXOPER_app and it's been the smoothest deployment experience I've ever had. Highly recommend!
                </p>
              </div>
            </ThreeDScrollTriggerRow>

            <ThreeDScrollTriggerRow baseVelocity={3} direction={-1} resetIntervalMs={0} className="mt-4">
              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev6.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Seb</div>
                    <div className="text-gray-500 text-xs">@sebcodes</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  EXOPER is really really great. Bring rules for making frontend super optimized, developing with confidence, improving my code time and well managing the process.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev7.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Kyle McDermott</div>
                    <div className="text-gray-500 text-xs">@kylemcdermott</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  Damn, @EXOPER_app. Its the first backend I've ever had to deploy that didn't feel like a hassle.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev8.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Jeremy Su</div>
                    <div className="text-gray-500 text-xs">@jeremysu_</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  @EXOPER_app for prototypes, utilizing the best tools and code, to use my code, with the @EXOPER_app, utilizing.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev9.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Emmanuel - zinkdoor</div>
                    <div className="text-gray-500 text-xs">@emmanuel</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  I have been EXOPER makes it super easy to just drop my and up to Docker for automated over deploying a server.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev10.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">Marco Eidinger</div>
                    <div className="text-gray-500 text-xs">@marcoeidinger</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  It easy to love to build on @EXOPER_app.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 pb-6 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[300px] mx-2 flex flex-col min-h-[200px]">
                <div className="flex items-start gap-3 mb-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/dev12.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div>
                    <div className="text-white font-medium text-sm">David Chen</div>
                    <div className="text-gray-500 text-xs">@davidchendev</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  After trying multiple deployment platforms, @EXOPER_app is by far the most developer-friendly. Cut our deployment time by 70% and simplified our workflow.
                </p>
              </div>
            </ThreeDScrollTriggerRow>
          </ThreeDScrollTriggerContainer>
        </div>
      </div>
    </div>
  );
};

export default Testimonial;

              

