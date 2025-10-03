
import React from 'react';
import { ArrowLeft, MapPin, Clock, Circle } from 'lucide-react';
import { Link } from 'react-router-dom';

const FrontendEngineerJob = () => {
  return (
    <div className="min-h-screen bg-[#0a0b14] text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
        <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8 text-sm">
          <ArrowLeft size={16} />
          ALL POSITIONS
        </button>

        <h1 className="text-4xl lg:text-5xl font-bold mb-12 lg:mb-16">
          Frontend Engineer
        </h1>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12">
          <div className="lg:col-span-4 space-y-4">
            <div className="flex items-center gap-3 text-gray-300">
              <MapPin size={18} />
              <span>Remote (anywhere)</span>
            </div>

            <div className="flex items-center gap-3 text-gray-300">
              <Clock size={18} />
              <span>Full-time</span>
            </div>

            <div className="mt-8 space-y-3">
              <a href="#job-description" className="flex items-center gap-3 text-purple-400 hover:text-purple-300 transition-colors">
                <Circle size={8} className="fill-current" />
                <span>Job description</span>
              </a>

              <a href="#about-role" className="flex items-center gap-3 text-gray-400 hover:text-white transition-colors">
                <Circle size={8} />
                <span>About the role</span>
              </a>

              <a href="#about-you" className="flex items-center gap-3 text-gray-400 hover:text-white transition-colors">
                <Circle size={8} />
                <span>About you</span>
              </a>

              <a href="#things-to-know" className="flex items-center gap-3 text-gray-400 hover:text-white transition-colors">
                <Circle size={8} />
                <span>Things to know</span>
              </a>

              <a href="#benefits" className="flex items-center gap-3 text-gray-400 hover:text-white transition-colors">
                <Circle size={8} />
                <span>Benefits and perks</span>
              </a>

              <a href="#how-we-hire" className="flex items-center gap-3 text-gray-400 hover:text-white transition-colors">
                <Circle size={8} />
                <span>How we hire</span>
              </a>
            </div>

            <Link
              to="/careers/apply?position=Frontend Engineer"
              className="mt-12 w-full bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white font-medium py-3 px-6 rounded-lg transition-all text-center block"
            >
              Apply for this position
            </Link>
          </div>

          <div className="lg:col-span-8 space-y-12">
            <section id="job-description">
              <h2 className="text-2xl font-bold mb-6">Job description</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  We're building a platform that developers love to use every day. Our frontend team creates beautiful, intuitive interfaces that make complex deployment workflows feel simple and delightful.
                </p>
                <p>
                  As a Frontend Engineer, you'll craft exceptional user experiences using modern web technologies. You'll work on features from real-time dashboards to interactive visualizations, ensuring our platform is fast, accessible, and a joy to use.
                </p>
                <p>
                  If you're passionate about building polished user interfaces, care deeply about performance and accessibility, and want your work to impact thousands of developers, let's talk!
                </p>
                <blockquote className="italic border-l-2 border-gray-700 pl-4 my-6">
                  "Design is not just what it looks like and feels like. Design is how it works."
                </blockquote>
                <p className="text-sm">- Steve Jobs</p>
                <p className="mt-6">
                  Explore our design philosophy and frontend architecture on our{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    engineering blog
                  </a>
                  .
                </p>
              </div>
            </section>

            <section id="about-role">
              <h2 className="text-2xl font-bold mb-6">About the role</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>In this role, you will:</p>
                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Build responsive, performant web applications using React, TypeScript, and modern frontend frameworks.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Create reusable component libraries and design systems that ensure consistency across our platform.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Implement real-time features using WebSockets and GraphQL subscriptions for live updates and collaboration.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Optimize application performance through code splitting, lazy loading, and efficient state management.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Collaborate with designers to translate mockups and prototypes into pixel-perfect, interactive experiences.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Ensure accessibility compliance and implement responsive designs that work seamlessly across all devices.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Write comprehensive tests using Jest, React Testing Library, and end-to-end testing frameworks.
                    </span>
                  </li>
                </ul>

                <p className="mt-6">Recent frontend projects our team has shipped:</p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Built a real-time deployment monitoring dashboard with live logs, metrics visualization, and WebSocket-powered updates.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Created an interactive canvas-based infrastructure visualizer that lets users drag-and-drop services and see connections in real-time.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Developed a code editor integration with syntax highlighting, autocomplete, and instant validation using Monaco Editor.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Implemented a powerful search interface with filters, instant results, and keyboard shortcuts for power users.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Redesigned the onboarding flow with interactive tutorials and contextual help that increased activation by 40%.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Built a comprehensive design system with 100+ components, documentation, and Storybook integration.
                    </div>
                  </li>
                </ul>

                <p className="mt-6">
                  This role offers high visibility with your work directly shaping the experience for thousands of developers daily.
                </p>
              </div>
            </section>

            <section id="about-you">
              <h2 className="text-2xl font-bold mb-6">About you</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      3+ years of professional frontend development experience building production web applications.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong expertise in React, TypeScript, and modern JavaScript (ES6+) with deep understanding of component lifecycle and hooks.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Proficiency in CSS-in-JS, Tailwind CSS, or similar styling solutions with strong understanding of responsive design principles.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Experience with state management libraries like Redux, Zustand, or React Query for complex application state.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Knowledge of GraphQL, REST APIs, and async data fetching patterns with proper error handling and loading states.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Understanding of web performance optimization techniques including code splitting, caching, and bundle size management.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Familiarity with accessibility standards (WCAG) and experience building inclusive interfaces for all users.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong attention to detail with a keen eye for design and user experience quality.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Bonus: Experience with animation libraries (Framer Motion, GSAP), data visualization (D3.js, Recharts), or Next.js.
                    </span>
                  </li>
                </ul>

                <p className="mt-6 font-medium">
                  We value diverse perspectives and welcome frontend engineers from all backgrounds who are passionate about craft.
                </p>
              </div>
            </section>

            <section id="things-to-know">
              <h2 className="text-2xl font-bold mb-6">Things to know</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  Working on frontend at a fast-moving startup comes with unique opportunities and challenges:
                </p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We're a distributed team across multiple timezones. Strong async communication and clear documentation are essential.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We ship features rapidly. You'll need to balance moving fast with maintaining code quality and user experience standards.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Our users are developers who notice details. Polish, performance, and thoughtful UX are critical to our success.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      You'll work closely with designers, backend engineers, and product managers to deliver cohesive features end-to-end.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We encourage experimentation and iteration. Not every feature will be perfect on the first try, and that's okay.
                    </span>
                  </li>
                </ul>
              </div>
            </section>

            <section id="benefits">
              <h2 className="text-2xl font-bold mb-6">Benefits and perks</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  Competitive salary with equity, full health benefits for you and your family, equipment allowance, flexible vacation, and more. See our{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    careers page
                  </a>{' '}
                  for complete benefits information.
                </p>

                <p className="mt-6">
                  What makes frontend engineering here special:
                </p>

                <ul className="space-y-4 ml-4 mt-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Modern tech stack</span>: Work with the latest frontend technologies and contribute to architectural decisions.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Design collaboration</span>: Work directly with talented designers in a highly collaborative environment.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Learning budget</span>: Courses, conferences, and professional development fully supported.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">User impact</span>: Your work is used by thousands of developers who provide direct feedback and appreciation.
                    </div>
                  </li>
                </ul>
              </div>
            </section>

            <section id="how-we-hire">
              <h2 className="text-2xl font-bold mb-6">How we hire</h2>
              <div className="space-y-8 text-gray-300 leading-relaxed">
                <p>Our hiring process is straightforward and respectful of your time. Here's what to expect:</p>

                <div className="space-y-6">
                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      1
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Initial conversation</h3>
                      <p>
                        A 30-minute chat to learn about your experience, discuss your favorite projects, and see if we're a good mutual fit.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      2
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Frontend coding challenge</h3>
                      <p className="mb-3">Build a small but meaningful feature:</p>
                      <ul className="space-y-2 ml-4">
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Create a React component or small application based on provided designs and requirements. Focus on code quality and UX.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Implement responsive design, proper state management, and consider accessibility and performance.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Include tests and document your approach, trade-offs, and any improvements you'd make with more time.
                          </span>
                        </li>
                      </ul>
                      <div className="mt-4 space-y-2 ml-4">
                        <p className="font-medium">Technical interview (60 minutes):</p>
                        <p>0-5 minutes: Introductions</p>
                        <p>5-35 minutes: Walk through your solution, discuss design decisions and alternatives</p>
                        <p>35-50 minutes: Frontend concepts and problem-solving discussion</p>
                        <p>50-60 minutes: Your questions about the team and tech stack</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center">
                      <span className="text-lg">💻</span>
                    </div>
                    <div className="flex-1">
                      <p className="text-purple-400 font-medium">
                        Questions about the challenge? Ask away! We want you to do your best work.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      3
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Design and UX discussion</h3>
                      <p className="mb-3">
                        Discuss how you approach building user interfaces, working with designers, and making UX decisions.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Design thinking, attention to detail, and user-centric problem solving.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      4
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Team collaboration interviews</h3>
                      <p className="mb-3">
                        Meet with engineers, designers, and product managers to understand how you work cross-functionally.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Communication skills, collaboration style, and cultural fit.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      5
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Leadership conversation</h3>
                      <p>
                        Meet with engineering leadership to discuss product vision, frontend strategy, and career growth opportunities.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      6
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Offer and onboarding</h3>
                      <p>
                        Review the offer, discuss your first projects, and plan your onboarding with the team.
                      </p>
                    </div>
                  </div>
                </div>

                <p className="mt-8 italic">
                  Remember: Interviews are <span className="underline">conversations</span>, not interrogations. Ask us about our tech stack, design process, code review culture, and how we balance quality with speed.
                </p>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FrontendEngineerJob;