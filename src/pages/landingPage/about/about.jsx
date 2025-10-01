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
            <div className="lg:pr-8 order-2 lg:order-1">
              <h2 className="text-2xl sm:text-3xl font-semibold mb-4 sm:mb-6">We believe...</h2>
              <p className="text-gray-300 text-base sm:text-lg leading-relaxed">
                You should simply be able to work on your core product without having to worry about
                infrastructure and how to deploy it.
              </p>
            </div>

            <div className="relative order-1 lg:order-2">
              <div className="w-full h-[180px] sm:h-[220px] lg:h-[240px] rounded-xl overflow-hidden shadow-[inset_0_0_60px_rgba(148,20,255,0.06)]" style={{background: 'linear-gradient(180deg, rgba(19,11,21,0) 0%, rgba(41,11,56,0.28) 55%, rgba(26,6,39,0.6) 100%)'}}>
                <svg viewBox="0 0 720 300" className="w-full h-full" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">
                  <defs>
                    <linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="#7c3aed" />
                      <stop offset="50%" stopColor="#a855f7" />
                      <stop offset="100%" stopColor="#ec4899" />
                    </linearGradient>
                    <filter id="soft" x="-20%" y="-20%" width="140%" height="140%">
                      <feDropShadow dx="0" dy="6" stdDeviation="18" floodColor="#6b21a8" floodOpacity="0.12"/>
                    </filter>
                  </defs>

                  <g filter="url(#soft)">
                    <path d="M110 72 L190 72" stroke="url(#g1)" strokeWidth="6" strokeLinecap="round" strokeDasharray="8 6" fill="none"/>
                    <path d="M230 72 L310 72" stroke="url(#g1)" strokeWidth="6" strokeLinecap="round" strokeDasharray="8 6" fill="none"/>
                    <path d="M310 72 L310 152" stroke="url(#g1)" strokeWidth="6" strokeLinecap="round" fill="none"/>
                    <path d="M310 152 L390 152" stroke="url(#g1)" strokeWidth="6" strokeLinecap="round" strokeDasharray="8 6" fill="none"/>
                    <path d="M430 152 L510 152" stroke="url(#g1)" strokeWidth="6" strokeLinecap="round" strokeDasharray="8 6" fill="none"/>
                    <path d="M510 152 L510 232" stroke="url(#g1)" strokeWidth="6" strokeLinecap="round" fill="none"/>

                    <circle cx="110" cy="72" r="18" fill="#0f0f14" stroke="url(#g1)" strokeWidth="4"/>
                    <circle cx="110" cy="72" r="7" fill="url(#g1)"/>
                    <circle cx="310" cy="72" r="18" fill="#0f0f14" stroke="url(#g1)" strokeWidth="4"/>
                    <circle cx="310" cy="152" r="18" fill="#0f0f14" stroke="url(#g1)" strokeWidth="4"/>
                    <circle cx="510" cy="152" r="18" fill="#0f0f14" stroke="url(#g1)" strokeWidth="4"/>
                    <circle cx="510" cy="232" r="18" fill="#0f0f14" stroke="url(#g1)" strokeWidth="4"/>

                    <text x="110" y="36" textAnchor="middle" fill="#a855f7" fontSize="14" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Local</text>
                    <text x="400" y="137" textAnchor="middle" fill="#a855f7" fontSize="14" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Staging</text>
                    <text x="535" y="246" textAnchor="start" fill="#ec4899" fontSize="14" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Production</text>
                  </g>
                </svg>
              </div>
            </div>
          </div>
        </section>

        <section>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 sm:gap-12 lg:gap-16 items-start">
            <div className="lg:pr-8 order-2 lg:order-1">
              <h2 className="text-2xl sm:text-3xl font-semibold mb-4 sm:mb-6">We want to help...</h2>
              <p className="text-gray-300 text-base sm:text-lg leading-relaxed">
                More great ideas materialize by reducing developer friction around deployments, clusters, Docker, and many other things that can go wrong.
              </p>
            </div>

            <div className="relative order-1 lg:order-2">
              <div className="w-full h-[280px] sm:h-[320px] lg:h-[360px] rounded-xl overflow-hidden" style={{background: 'linear-gradient(180deg, rgba(20,6,10,0) 0%, rgba(31,8,12,0.12) 40%, rgba(24,6,8,0.4) 100%)'}}>
                <svg viewBox="0 0 760 420" className="w-full h-full" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">
                  <defs>
                    <linearGradient id="r" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#fb7185"/>
                      <stop offset="28%" stopColor="#ef4444"/>
                      <stop offset="70%" stopColor="#dc2626"/>
                    </linearGradient>
                    <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="0%">
                      <stop offset="0%" stopColor="#9ca3af"/>
                      <stop offset="100%" stopColor="#6b7280"/>
                    </linearGradient>
                  </defs>

                  <g strokeLinecap="round" strokeLinejoin="round" fill="none">
                    <path d="M150 52 L230 52" stroke="url(#r)" strokeWidth="4" strokeDasharray="6 4"/>
                    <path d="M230 52 L230 132" stroke="url(#r)" strokeWidth="4"/>
                    <path d="M230 132 L330 132" stroke="url(#g)" strokeWidth="3" strokeDasharray="6 4"/>
                    <path d="M330 132 L330 202" stroke="url(#g)" strokeWidth="3"/>
                    <path d="M330 202 L250 202" stroke="url(#g)" strokeWidth="3" strokeDasharray="6 4"/>
                    <path d="M250 202 L250 292" stroke="url(#r)" strokeWidth="4" strokeDasharray="6 4"/>
                    <path d="M250 292 L170 292" stroke="url(#r)" strokeWidth="4"/>
                    <path d="M170 292 L170 372" stroke="url(#r)" strokeWidth="4" strokeDasharray="6 4"/>

                    <path d="M350 132 L450 132" stroke="url(#r)" strokeWidth="4" strokeDasharray="6 4"/>
                    <path d="M450 132 L450 222" stroke="url(#r)" strokeWidth="4"/>
                    <path d="M450 222 L370 222" stroke="url(#r)" strokeWidth="4" strokeDasharray="6 4"/>
                    <path d="M370 222 L370 312" stroke="url(#r)" strokeWidth="4"/>

                    <path d="M370 312 L480 312" stroke="url(#r)" strokeWidth="4" strokeDasharray="6 4"/>
                    <path d="M480 312 L480 382" stroke="url(#r)" strokeWidth="4"/>
                    <path d="M500 132 L580 132" stroke="url(#r)" strokeWidth="4" strokeDasharray="6 4"/>
                    <path d="M580 132 L580 222" stroke="url(#r)" strokeWidth="4"/>
                    <path d="M580 222 L660 222" stroke="url(#g)" strokeWidth="3" strokeDasharray="6 4"/>
                    <path d="M660 222 L660 292" stroke="url(#g)" strokeWidth="3"/>

                    <path d="M520 382 L600 382" stroke="url(#g)" strokeWidth="3" strokeDasharray="6 4"/>
                    <path d="M600 382 L600 312" stroke="url(#g)" strokeWidth="3"/>
                    <path d="M320 370 L440 370" stroke="url(#r)" strokeWidth="4" strokeDasharray="6 4"/>

                    <circle cx="230" cy="52" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="230" cy="132" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="330" cy="132" r="10" fill="#0f0f14" stroke="url(#g)" strokeWidth="3"/>
                    <circle cx="330" cy="202" r="10" fill="#0f0f14" stroke="url(#g)" strokeWidth="3"/>
                    <circle cx="250" cy="202" r="10" fill="#0f0f14" stroke="url(#g)" strokeWidth="3"/>
                    <circle cx="250" cy="292" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>

                    <circle cx="350" cy="132" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="450" cy="132" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="450" cy="222" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="370" cy="222" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="370" cy="312" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>

                    <circle cx="500" cy="132" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="580" cy="132" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="580" cy="222" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="660" cy="222" r="10" fill="#0f0f14" stroke="url(#g)" strokeWidth="3"/>
                    <circle cx="660" cy="292" r="10" fill="#0f0f14" stroke="url(#g)" strokeWidth="3"/>

                    <circle cx="480" cy="312" r="10" fill="#0f0f14" stroke="url(#r)" strokeWidth="3"/>
                    <circle cx="520" cy="382" r="10" fill="#0f0f14" stroke="url(#g)" strokeWidth="3"/>
                    <circle cx="600" cy="382" r="10" fill="#0f0f14" stroke="url(#g)" strokeWidth="3"/>
                    <circle cx="600" cy="312" r="10" fill="#0f0f14" stroke="url(#g)" strokeWidth="3"/>

                    <circle cx="170" cy="372" r="12" fill="url(#r)"/>
                    <circle cx="480" cy="382" r="12" fill="url(#r)"/>

                    <text x="150" y="34" textAnchor="middle" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Local</text>
                    <text x="250" y="115" textAnchor="middle" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Staging</text>
                    <text x="330" y="115" textAnchor="middle" fill="#9ca3af" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Local</text>

                    <text x="170" y="185" textAnchor="end" fill="#9ca3af" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">VMs</text>
                    <text x="260" y="280" textAnchor="start" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Database</text>

                    <text x="410" y="115" textAnchor="middle" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Secret Mgmt</text>
                    <text x="460" y="210" textAnchor="start" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Caching</text>
                    <text x="380" y="300" textAnchor="start" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Logging</text>

                    <text x="550" y="115" textAnchor="middle" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Custom Infra</text>
                    <text x="590" y="210" textAnchor="start" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">DNS</text>
                    <text x="670" y="280" textAnchor="start" fill="#9ca3af" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">VM</text>

                    <text x="175" y="405" textAnchor="middle" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">API</text>
                    <text x="380" y="360" textAnchor="middle" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Server</text>
                    <text x="485" y="405" textAnchor="middle" fill="#ef4444" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Production</text>
                    <text x="610" y="370" textAnchor="start" fill="#9ca3af" fontSize="13" fontWeight="600" fontFamily="Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto">Production</text>
                  </g>
                </svg>
              </div>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
};

export default About;