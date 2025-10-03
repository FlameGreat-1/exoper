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
            
            <div className="group bg-gradient-to-br from-[#1a1a2e]/90 via-[#16162a]/80 to-[#1a1a2e]/90 backdrop-blur-sm rounded-xl p-6 sm:p-8 border border-[#2a2a3e] hover:border-[#3a3a4e] transition-all duration-300 relative overflow-hidden min-h-[300px] flex flex-col">
              <BorderBeam 
                size={40} 
                duration={8} 
                colorFrom="#7400ff" 
                colorTo="#9b41ff" 
                opacity={0.7}
                glowIntensity={1}
                pauseOnHover={true}
              />
              <div className="flex items-center gap-3 mb-6 flex-shrink-0">
                <div className="w-8 h-8 bg-white rounded flex items-center justify-center flex-shrink-0">
                  <img src="/images/urbix-logo.png" alt="Urbix" className="w-6 h-6" />
                </div>
                <span className="text-white font-semibold text-lg truncate">Urbix</span>
              </div>
              <div className="flex-grow flex flex-col justify-between">
                <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                  "EXOPER is where we host all of our backend services along with our databases. It's been an integral part of our infrastructure since the very beginning."
                </p>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/avatar-2.jpg" alt="Paul O'Connell" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Peter O'Well</div>
                    <div className="text-gray-400 text-xs truncate">Founder & CEO of Urbix</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="group bg-gradient-to-br from-[#1a1a2e]/90 via-[#16162a]/80 to-[#1a1a2e]/90 backdrop-blur-sm rounded-xl p-6 sm:p-8 border border-[#2a2a3e] hover:border-[#3a3a4e] transition-all duration-300 relative overflow-hidden min-h-[300px] flex flex-col">
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
              <div className="flex items-center gap-3 mb-6 flex-shrink-0">
                <div className="w-8 h-8 bg-white rounded flex items-center justify-center flex-shrink-0">
                  <img src="/images/Lunexa.svg" alt="Lunexa" className="w-6 h-6" />
                </div>
                <span className="text-white font-semibold text-lg truncate">Lunexa</span>
              </div>
              <div className="flex-grow flex flex-col justify-between">
                <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                  "Even though we already have an internal Kubernetes cluster and infrastructure-at-scale setup, we decided to go with EXOPER so that we weren't spending time writing YAML files when we could be working on the product."
                </p>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/avatar-1.jpg" alt="Paul Boller" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Marie Christ</div>
                    <div className="text-gray-400 text-xs truncate">Backend Architect at Lunexa</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="group bg-gradient-to-br from-[#1a1a2e]/90 via-[#16162a]/80 to-[#1a1a2e]/90 backdrop-blur-sm rounded-xl p-6 sm:p-8 border border-[#2a2a3e] hover:border-[#3a3a4e] transition-all duration-300 relative overflow-hidden min-h-[340px] flex flex-col">
              <BorderBeam 
                size={40} 
                duration={8} 
                colorFrom="#7400ff" 
                colorTo="#9b41ff" 
                opacity={0.7}
                glowIntensity={1}
                pauseOnHover={true}
              />
              <div className="flex items-center gap-3 mb-6 flex-shrink-0">
                <div className="w-8 h-8 bg-white rounded flex items-center justify-center flex-shrink-0">
                  <img src="/images/BuildHive.jpg" alt="BuildHive" className="w-6 h-6" />
                </div>
                <span className="text-white font-semibold text-lg truncate">BuildHive</span>
              </div>
              <div className="flex-grow flex flex-col justify-between">
                <div className="flex-grow">
                  <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-4">
                    "EXOPER is a game changer for us. We're currently serving more than 80,000 developers with a small team... every minute spent on infrastructure is a minute we're not building the best email product in the world.
                  </p>
                  <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                    If it wasn't for EXOPER, I don't think we would be able to grow as fast as we are today."
                  </p>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/avatar-1.jpg" alt="Xero Richie" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Xero Richie</div>
                    <div className="text-gray-400 text-xs truncate">Founder & CEO of BuildHive</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="group bg-gradient-to-br from-[#1a1a2e]/90 via-[#16162a]/80 to-[#1a1a2e]/90 backdrop-blur-sm rounded-xl p-6 sm:p-8 border border-[#2a2a3e] hover:border-[#3a3a4e] transition-all duration-300 relative overflow-hidden min-h-[300px] flex flex-col">
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
              <div className="flex items-center gap-3 mb-6 flex-shrink-0">
                <div className="w-8 h-8 bg-white rounded flex items-center justify-center flex-shrink-0">
                  <img src="/images/Odookit.png" alt="Odookit" className="w-6 h-6" />
                </div>
                <span className="text-white font-semibold text-lg truncate">Odookit</span>
              </div>
              <div className="flex-grow flex flex-col justify-between">
                <p className="text-gray-200 text-base sm:text-lg leading-relaxed mb-6">
                  "The flexibility and agility for automation with EXOPER helps us move fast and continuously deploy to production with confidence."
                </p>
                <div className="flex items-center gap-3 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/avatar-2.jpg" alt="Stannis Riviera" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Stephen Caris</div>
                    <div className="text-gray-400 text-xs truncate">Managing Director of Odookit Group</div>
                  </div>
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
              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Liam</div>
                    <div className="text-gray-500 text-xs truncate">@liamtech</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  Team is an easier option. Deploying literally anything on @EXOPER_app is now possible in minutes instead of days. Obsessed. ⚡
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Benjamin Dolinger</div>
                    <div className="text-gray-500 text-xs truncate">@bendolinger</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  With other apps, infrastructure, and more work to production is @EXOPER_app. Super excited to work with them.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Jenn</div>
                    <div className="text-gray-500 text-xs truncate">@jennbuilds</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  @EXOPER_app for prototypes, utilizing the containerized world, infrastructure-as-code, a custom domain local, connect... and that just becomes what you need...
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Arnav</div>
                    <div className="text-gray-500 text-xs truncate">@arnavbuilds</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  Assisted in organizing my services to @EXOPER_app.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Team Sparky</div>
                    <div className="text-gray-500 text-xs truncate">@teamsparky</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  This CLI is deploying a small app on @EXOPER_app - has been promising the team for over seven...
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Jessica Lee</div>
                    <div className="text-gray-500 text-xs truncate">@jessicacodes</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  Just migrated our entire backend to @EXOPER_app and it's been the smoothest deployment experience I've ever had. Highly recommend!
                </p>
              </div>
            </ThreeDScrollTriggerRow>

            <ThreeDScrollTriggerRow baseVelocity={3} direction={1} resetIntervalMs={0} className="mt-4">
              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Seb</div>
                    <div className="text-gray-500 text-xs truncate">@sebcodes</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  EXOPER is really really great. Bring rules for making frontend super optimized, developing with confidence, improving my code time and well managing the process.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Kyle McDermott</div>
                    <div className="text-gray-500 text-xs truncate">@kylemcdermott</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  Damn, @EXOPER_app. Its the first backend I've ever had to deploy that didn't feel like a hassle.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Jeremy Su</div>
                    <div className="text-gray-500 text-xs truncate">@jeremysu_</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  @EXOPER_app for prototypes, utilizing the best tools and code, to use my code, with the @EXOPER_app, utilizing.
                </p>
              </div>
              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Emmanuel - zinkdoor</div>
                    <div className="text-gray-500 text-xs truncate">@emmanuel</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  I have been EXOPER makes it super easy to just drop my and up to Docker for automated over deploying a server.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Marco Eidinger</div>
                    <div className="text-gray-500 text-xs truncate">@marcoeidinger</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  It easy to love to build on @EXOPER_app.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">David Chen</div>
                    <div className="text-gray-500 text-xs truncate">@davidchendev</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  After trying multiple deployment platforms, @EXOPER_app is by far the most developer-friendly. Cut our deployment time by 70% and simplified our workflow.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Alex Rivera</div>
                    <div className="text-gray-500 text-xs truncate">@alexcodes</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  @EXOPER_app has completely transformed our deployment workflow. What used to take hours now takes minutes!
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-1.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Sarah Kim</div>
                    <div className="text-gray-500 text-xs truncate">@sarahbuilds</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  The developer experience on @EXOPER_app is unmatched. Clean, fast, and incredibly intuitive.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Mike Johnson</div>
                    <div className="text-gray-500 text-xs truncate">@mikecodes</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  Building with @EXOPER_app feels like magic. Everything just works seamlessly.
                </p>
              </div>

              <div className="bg-[#14141f]/80 backdrop-blur-sm rounded-lg p-5 border border-[#1e1e2e] hover:border-[#2e2e3e] transition-all duration-300 w-[280px] sm:w-[300px] mx-2 flex flex-col min-h-[200px] flex-shrink-0 whitespace-normal">
                <div className="flex items-start gap-3 mb-4 flex-shrink-0">
                  <div className="w-10 h-10 rounded-full bg-gray-700 overflow-hidden flex-shrink-0">
                    <img src="/images/dev-2.jpg" alt="Developer" className="w-full h-full object-cover" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-white font-medium text-sm truncate">Lisa Wang</div>
                    <div className="text-gray-500 text-xs truncate">@lisadev</div>
                  </div>
                </div>
                <p className="text-gray-300 text-sm leading-relaxed flex-grow">
                  @EXOPER_app simplified our entire infrastructure. No more complex configurations!
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

