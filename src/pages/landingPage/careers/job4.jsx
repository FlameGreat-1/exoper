import React from 'react';
import { ArrowLeft, MapPin, Clock, Circle } from 'lucide-react';
import { Link } from 'react-router-dom';

const DevOpsEngineerJob = () => {
  return (
    <div className="min-h-screen bg-[#0a0b14] text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
        <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8 text-sm">
          <ArrowLeft size={16} />
          ALL POSITIONS
        </button>

        <h1 className="text-4xl lg:text-5xl font-bold mb-12 lg:mb-16">
          DevOps Engineer - Platform Infrastructure
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
              to="/careers/apply?position=DevOps Engineer"
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
                  Our infrastructure powers thousands of applications deployed globally every day. We're building a platform that makes deployment seamless, reliable, and lightning-fast for developers worldwide.
                </p>
                <p>
                  As a DevOps Engineer, you'll be responsible for designing, implementing, and maintaining the infrastructure that enables this experience. You'll work on automation, observability, security, and performance optimization at scale.
                </p>
                <p>
                  If you're passionate about infrastructure as code, love solving complex operational challenges, and want to build systems that empower developers globally, we want to hear from you!
                </p>
                <blockquote className="italic border-l-2 border-gray-700 pl-4 my-6">
                  "Any fool can write code that a computer can understand. Good programmers write code that humans can understand. Great engineers build systems that run themselves."
                </blockquote>
                <p className="text-sm">- Martin Fowler (adapted)</p>
                <p className="mt-6">
                  Explore our technical approach and infrastructure philosophy on our{' '}
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
                      Design and maintain cloud infrastructure across AWS, GCP, and Azure using Terraform and infrastructure as code best practices.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Build and optimize Kubernetes clusters for high availability, scalability, and cost efficiency across multiple regions.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Develop CI/CD pipelines using GitHub Actions, GitLab CI, or similar tools to automate build, test, and deployment workflows.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Implement comprehensive monitoring, logging, and alerting systems using Prometheus, Grafana, ELK stack, or DataDog.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Manage containerization strategies, Docker image optimization, and registry management for efficient deployments.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Implement security best practices including secrets management, network policies, vulnerability scanning, and compliance automation.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Respond to incidents, perform root cause analysis, and implement preventive measures to improve system reliability.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Participate in on-call rotations to ensure 24/7 platform availability and rapid incident response.
                    </span>
                  </li>
                </ul>

                <p className="mt-6">Recent infrastructure projects our DevOps team has delivered:</p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Migrated 10,000+ workloads to a new multi-region Kubernetes architecture with zero downtime and 99.99% SLA.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Built an automated infrastructure provisioning system that reduced deployment time from hours to minutes using Terraform and Ansible.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Implemented GitOps workflows with ArgoCD and Flux for declarative infrastructure management and automated rollbacks.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Created a comprehensive observability platform processing 1TB+ of logs and metrics daily with sub-second query performance.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Reduced infrastructure costs by 45% through intelligent autoscaling, spot instance management, and resource optimization.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Developed disaster recovery procedures and automated backup systems achieving RPO of 5 minutes and RTO of 15 minutes.
                    </div>
                  </li>
                </ul>

                <p className="mt-6">
                  This role provides significant ownership over critical infrastructure that directly impacts developer experience and platform reliability.
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
                      3+ years of DevOps or Site Reliability Engineering experience managing production infrastructure at scale.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong expertise with Kubernetes, including cluster management, networking, storage, and security configurations.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Proficiency in infrastructure as code tools like Terraform, CloudFormation, or Pulumi with version control best practices.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Experience with at least one major cloud provider (AWS, GCP, Azure) and understanding of cloud-native architectures.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong scripting skills in Python, Bash, or Go for automation and tooling development.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Deep understanding of networking concepts including load balancing, DNS, CDN, service mesh, and security policies.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Experience implementing observability solutions and practicing data-driven incident response and troubleshooting.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong communication skills for documenting systems, writing runbooks, and collaborating with engineering teams.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Bonus: Experience with service mesh (Istio, Linkerd), chaos engineering, or security compliance (SOC2, ISO 27001).
                    </span>
                  </li>
                </ul>

                <p className="mt-6 font-medium">
                  We value diverse experiences and perspectives. If you're passionate about infrastructure and eager to learn, we encourage you to apply.
                </p>
              </div>
            </section>

            <section id="things-to-know">
              <h2 className="text-2xl font-bold mb-6">Things to know</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  Working in DevOps at a high-growth startup means tackling unique challenges. Here's what to expect:
                </p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We're distributed globally with infrastructure running 24/7 across all timezones. Async communication and good documentation are essential.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      On-call is part of the role. We practice fair rotation schedules with proper compensation, handoff procedures, and post-incident reviews.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Our infrastructure serves thousands of customers with diverse workloads. Reliability, performance, and security are non-negotiable.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We move fast but deliberately. Automation and testing are crucial, and we invest in tooling that makes our work sustainable.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      You'll have autonomy to make infrastructure decisions and own outcomes. We trust our engineers to balance innovation with stability.
                    </span>
                  </li>
                </ul>
              </div>
            </section>

            <section id="benefits">
              <h2 className="text-2xl font-bold mb-6">Benefits and perks</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  Competitive salary with equity participation, full health benefits for you and your family, generous equipment allowance, flexible vacation policy, and more. See our{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    careers page
                  </a>{' '}
                  for complete benefits information.
                </p>

                <p className="mt-6">
                  What makes infrastructure engineering here special:
                </p>

                <ul className="space-y-4 ml-4 mt-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Modern infrastructure</span>: Work with cutting-edge cloud-native technologies and contribute to architectural decisions.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Scale and impact</span>: Your work directly affects thousands of developers and millions of deployments daily.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Learning budget</span>: Certifications, training courses, conferences, and professional development fully covered.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Blameless culture</span>: We focus on learning from incidents, not pointing fingers. Psychological safety is paramount.
                    </div>
                  </li>
                </ul>
              </div>
            </section>

            <section id="how-we-hire">
              <h2 className="text-2xl font-bold mb-6">How we hire</h2>
              <div className="space-y-8 text-gray-300 leading-relaxed">
                <p>No surprises. Here's our complete and transparent hiring process:</p>

                <div className="space-y-6">
                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      1
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Introductory call</h3>
                      <p>
                        A casual 30-minute conversation to learn about your experience with infrastructure, what motivates you, and answer any questions you have about the role.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      2
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Infrastructure challenge</h3>
                      <p className="mb-3">Complete a hands-on infrastructure project:</p>
                      <ul className="space-y-2 ml-4">
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Design and implement a highly available web application infrastructure using Kubernetes, including ingress, autoscaling, and monitoring.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Write infrastructure as code (Terraform or similar) with proper state management, documentation, and security considerations.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Include CI/CD pipeline configuration and basic observability setup. Document your architectural decisions and trade-offs.
                          </span>
                        </li>
                      </ul>
                      <div className="mt-4 space-y-2 ml-4">
                        <p className="font-medium">Technical interview (90 minutes):</p>
                        <p>0-10 minutes: Introductions</p>
                        <p>10-50 minutes: Walk through your implementation, discuss design choices and alternatives</p>
                        <p>50-75 minutes: Infrastructure troubleshooting scenarios and system design discussion</p>
                        <p>75-90 minutes: Your questions about our infrastructure and practices</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center">
                      <span className="text-lg">🚀</span>
                    </div>
                    <div className="flex-1">
                      <p className="text-purple-400 font-medium">
                        Need clarification on the challenge? Ask away! We're here to support you.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      3
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Systems thinking session</h3>
                      <p className="mb-3">
                        Discuss real infrastructure challenges we face, how you'd approach incident response, and architectural improvements.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Problem-solving methodology, operational thinking, and communication under pressure.
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
                        Meet with engineers from different teams to understand how DevOps collaborates across the organization.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Cross-functional collaboration skills, empathy for developer experience, and cultural fit.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      5
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Leadership discussion</h3>
                      <p>
                        Meet with engineering leadership to discuss infrastructure strategy, career growth, and long-term vision.
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
                        Review compensation package details, discuss start date, and begin planning your onboarding and first projects.
                      </p>
                    </div>
                  </div>
                </div>

                <p className="mt-8 italic">
                  Remember: This is a <span className="underline">mutual evaluation</span>. Ask us tough questions about on-call, incident response, technical debt, and team dynamics. We want you to make an informed decision.
                </p>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DevOpsEngineerJob;