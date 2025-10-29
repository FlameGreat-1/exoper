import React from 'react';
import { ArrowLeft, MapPin, Clock, Circle } from 'lucide-react';
import { Link } from 'react-router-dom';

const BackendEngineerJob = () => {
  return (
    <div className="min-h-screen bg-[#0a0b14] text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
      <Link 
        to="/careers/all-positions" 
        className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8 text-sm"
      >
        <ArrowLeft size={16} />
        ALL POSITIONS
      </Link>

        <h1 className="text-4xl lg:text-5xl font-bold mb-12 lg:mb-16">
          Backend Engineer - Infrastructure
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
              to="/careers/apply?position=Backend Engineer - Infrastructure"
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
                  We're building the infrastructure that powers modern application deployment. Our backend systems handle millions of deployments, process billions of logs, and orchestrate complex distributed workflows across global infrastructure.
                </p>
                <p>
                  As a Backend Engineer, you'll work on critical systems that directly impact developer productivity worldwide. You'll architect scalable solutions, optimize performance at scale, and build the backbone of our platform.
                </p>
                <p>
                  If you love solving complex distributed systems challenges and want to build infrastructure that developers rely on every day, we'd love to talk!
                </p>
                <blockquote className="italic border-l-2 border-gray-700 pl-4 my-6">
                  "The best way to predict the future is to build it."
                </blockquote>
                <p className="text-sm">- Alan Kay</p>
                <p className="mt-6">
                  Learn more about our engineering culture and technical challenges in our{' '}
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
                <p>For this role, you will:</p>
                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Design and build highly scalable microservices using Go and Rust that handle millions of requests per day with 99.99% uptime.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Architect distributed systems that coordinate deployment workflows across multiple cloud providers and regions.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Optimize database performance and design efficient data models for PostgreSQL, Redis, and ClickHouse at massive scale.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Build robust APIs (GraphQL and REST) that serve as the foundation for our platform's capabilities.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Implement monitoring, observability, and alerting systems to ensure service reliability and quick incident response.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Work with Kubernetes, Docker, and infrastructure-as-code tools to manage cloud resources efficiently.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>Participate in on-call rotations to maintain system reliability and respond to critical incidents.</span>
                  </li>
                </ul>

                <p className="mt-6">Recent projects our backend team has shipped:</p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Built a distributed log aggregation system processing 5B+ logs daily with sub-second query performance using ClickHouse.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Designed a multi-region deployment orchestration system with automatic failover and zero-downtime migrations.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Implemented real-time metrics collection and aggregation pipeline handling 100K+ metrics per second.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Created an intelligent resource scheduler that optimizes container placement across our infrastructure reducing costs by 40%.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Built a distributed caching layer that improved API response times by 70% while reducing database load.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Developed a webhook delivery system with automatic retries, exponential backoff, and guaranteed delivery.
                    </div>
                  </li>
                </ul>

                <p className="mt-6">
                  This role offers high impact and autonomy. You'll directly influence our technical architecture and engineering practices.
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
                      Strong experience with backend languages like Go, Rust, or Node.js, with a focus on building high-performance systems.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Deep understanding of distributed systems concepts including consistency, availability, partition tolerance, and consensus algorithms.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Experience designing and scaling databases (PostgreSQL, Redis, or similar) to handle high throughput and large datasets.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Familiarity with containerization (Docker), orchestration (Kubernetes), and cloud platforms (AWS, GCP, or Azure).
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong debugging skills and experience with observability tools like Prometheus, Grafana, or similar monitoring solutions.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Excellent written communication for technical documentation, design proposals, and collaborative problem-solving.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      A passion for writing clean, maintainable code with comprehensive testing and proper error handling.
                    </span>
                  </li>
                </ul>

                <p className="mt-6 font-medium">
                  We welcome engineers from all backgrounds and experience levels who are eager to learn and grow with us.
                </p>
              </div>
            </section>

            <section id="things-to-know">
              <h2 className="text-2xl font-bold mb-6">Things to know</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  We're a fast-growing startup with a unique engineering culture. Here's what that means for you:
                </p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We operate globally with team members across every timezone. This means async communication is key, and you'll need to be proactive about collaboration.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Work-life balance matters. While we're building critical infrastructure, we don't expect 24/7 availability. Clear boundaries and on-call rotations help everyone stay sustainable.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Our team is lean but mighty. With a small engineering team serving thousands of customers, your work has immediate and visible impact.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We value ownership and initiative. You'll have the freedom to make technical decisions and the responsibility to see them through.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We're building for scale from day one. Performance, reliability, and maintainability aren't afterthoughts they're core to everything we build.
                    </span>
                  </li>
                </ul>
              </div>
            </section>

            <section id="benefits">
              <h2 className="text-2xl font-bold mb-6">Benefits and perks</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  We offer competitive compensation including generous equity, comprehensive health coverage for you and your dependents, home office stipend, and flexible time off. Check our{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    careers page
                  </a>{' '}
                  for complete details.
                </p>

                <p className="mt-6">
                  Beyond standard benefits, here's what makes our engineering team special:
                </p>

                <ul className="space-y-4 ml-4 mt-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Deep work time</span>: Minimal meetings means more time for focused engineering work. Most days have zero scheduled meetings.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Modern tech stack</span>: Work with cutting-edge technologies and tools. We invest in the best infrastructure for our team.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Learning budget</span>: Annual budget for courses, conferences, and professional development.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Open source</span>: Contribute to open source as part of your job. Many of our core tools are open source.
                    </div>
                  </li>
                </ul>
              </div>
            </section>

            <section id="how-we-hire">
              <h2 className="text-2xl font-bold mb-6">How we hire</h2>
              <div className="space-y-8 text-gray-300 leading-relaxed">
                <p>Our hiring process is transparent and straightforward. Here's exactly what to expect:</p>

                <div className="space-y-6">
                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      1
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Initial conversation</h3>
                      <p>
                        A relaxed 30-minute chat about your background, what you're looking for, and whether we might be a good fit for each other.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      2
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Technical take-home project</h3>
                      <p className="mb-3">Design and implement a system that demonstrates your backend skills:</p>
                      <ul className="space-y-2 ml-4">
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Build a distributed job queue system with REST API endpoints. The system should handle job submission, processing, retries, and status tracking.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Include proper error handling, logging, and basic monitoring. Deploy it somewhere we can test it (we provide credits if needed).
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Write a brief README explaining your architectural decisions, trade-offs, and how you'd scale it to production.
                          </span>
                        </li>
                      </ul>
                      <div className="mt-4 space-y-2 ml-4">
                        <p className="font-medium">Interview structure (90 minutes):</p>
                        <p>0-10 minutes: Introductions and overview</p>
                        <p>10-45 minutes: Deep dive into your implementation, discussing design decisions and alternatives</p>
                        <p>45-70 minutes: System design discussion - scaling your solution to handle millions of requests</p>
                        <p>70-90 minutes: Your questions for us</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center">
                      <span className="text-lg">💡</span>
                    </div>
                    <div className="flex-1">
                      <p className="text-purple-400 font-medium">
                        Feel free to ask questions before starting the project. We want you to succeed!
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      3
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Architecture deep dive</h3>
                      <p className="mb-3">
                        A technical session with our senior engineers where we discuss real problems we're solving and how you'd approach them.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Problem-solving approach, technical depth, and how you communicate complex ideas.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      4
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Team fit conversations</h3>
                      <p className="mb-3">
                        Meet 3-4 people from different parts of the company to discuss collaboration, culture, and what it's really like to work here.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: How you work with others, communication style, and cultural alignment.
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
                        A 45-minute discussion with our engineering leadership about vision, growth, and long-term opportunities.
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
                        We'll present a detailed offer, answer any remaining questions, and if you accept, start planning your first weeks with us.
                      </p>
                    </div>
                  </div>
                </div>

                <p className="mt-8 italic">
                  Remember: Interviews are <span className="underline">two-way conversations</span>. Ask us anything - about the tech, the team, the challenges, or the culture. We're here to help you make the best decision.
                </p>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
};

export default BackendEngineerJob;