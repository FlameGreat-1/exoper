import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, MapPin, Clock, Users, Briefcase, ChevronRight } from 'lucide-react';

const AllPositions = () => {
  const jobListings = [
    {
      id: 1,
      title: "Senior Full-Stack Engineer - Product",
      department: "Engineering",
      location: "Remote (anywhere)",
      type: "Full-time",
      description: "Build features end-to-end, from UI to orchestrating workflows with microservices using Temporal.",
      link: "/careers/senior-fullstack-engineer",
      featured: true
    },
    {
      id: 2,
      title: "Backend Engineer - Infrastructure",
      department: "Engineering",
      location: "Remote (anywhere)",
      type: "Full-time",
      description: "Design and build highly scalable microservices using Go and Rust that handle millions of requests per day.",
      link: "/careers/backend-engineer",
      featured: true
    },
    {
      id: 3,
      title: "Senior Product Marketer",
      department: "Marketing",
      location: "Remote (anywhere)",
      type: "Full-time",
      description: "Drive product positioning, messaging, and go-to-market strategies for our developer platform.",
      link: "/careers/senior-product-marketer",
      featured: false
    },
    {
      id: 4,
      title: "DevOps Engineer",
      department: "Engineering",
      location: "Remote (anywhere)",
      type: "Full-time",
      description: "Build and maintain our cloud infrastructure, CI/CD pipelines, and deployment automation.",
      link: "/careers/devops-engineer",
      featured: false
    },
    {
      id: 5,
      title: "Frontend Engineer - Dashboard",
      department: "Engineering",
      location: "Remote (anywhere)",
      type: "Full-time",
      description: "Create intuitive user interfaces and exceptional user experiences for our developer dashboard.",
      link: "/careers/frontend-engineer",
      featured: false
    },
    {
      id: 6,
      title: "Technical Writer",
      department: "Developer Relations",
      location: "Remote (anywhere)",
      type: "Full-time",
      description: "Create comprehensive documentation, tutorials, and guides for our developer community.",
      link: "/careers/technical-writer",
      featured: false
    }
  ];

  const departments = [...new Set(jobListings.map(job => job.department))];

  return (
    <div className="min-h-screen bg-[#0a0b14] text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
        <Link 
          to="/" 
          className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8 text-sm"
        >
          <ArrowLeft size={16} />
          BACK TO HOME
        </Link>

        <div className="mb-12 lg:mb-16">
          <h1 className="text-4xl lg:text-5xl font-bold mb-6">
            Join Our Team
          </h1>
          <p className="text-xl text-gray-300 leading-relaxed max-w-3xl">
            We're building the future of software deployment. Join a team of passionate engineers, 
            designers, and builders who are making developers more productive worldwide.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12">
          <div className="lg:col-span-4 space-y-6">
            <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a]">
              <h3 className="text-xl font-semibold mb-4 text-white">Why Exoper?</h3>
              <div className="space-y-4 text-gray-300 text-sm">
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-purple-500 mt-2 flex-shrink-0"></div>
                  <span>Remote-first culture with global team</span>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-purple-500 mt-2 flex-shrink-0"></div>
                  <span>High impact work affecting millions of developers</span>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-purple-500 mt-2 flex-shrink-0"></div>
                  <span>Competitive compensation and equity</span>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-purple-500 mt-2 flex-shrink-0"></div>
                  <span>Comprehensive health benefits</span>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-2 h-2 rounded-full bg-purple-500 mt-2 flex-shrink-0"></div>
                  <span>Learning and development budget</span>
                </div>
              </div>
            </div>

            <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a]">
              <h3 className="text-xl font-semibold mb-4 text-white">Departments</h3>
              <div className="space-y-2">
                {departments.map((dept) => (
                  <div key={dept} className="flex items-center justify-between py-2">
                    <span className="text-gray-300">{dept}</span>
                    <span className="text-purple-400 text-sm font-medium">
                      {jobListings.filter(job => job.department === dept).length} positions
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="lg:col-span-8">
            <div className="flex items-center justify-between mb-8">
              <h2 className="text-2xl font-bold">Open Positions</h2>
              <div className="flex items-center gap-2 text-gray-400">
                <Briefcase size={18} />
                <span className="text-sm">{jobListings.length} open roles</span>
              </div>
            </div>

            <div className="space-y-4">
              {jobListings.map((job) => (
                <Link
                  key={job.id}
                  to={job.link}
                  className="block bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-6 border border-[#2a2a2a] hover:border-purple-500/50 transition-all duration-200 group"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-xl font-semibold text-white group-hover:text-purple-300 transition-colors">
                          {job.title}
                        </h3>
                        {job.featured && (
                          <span className="bg-purple-600/30 text-purple-400 text-xs font-medium px-2 py-1 rounded-md border border-purple-500/30">
                            Featured
                          </span>
                        )}
                      </div>
                      
                      <p className="text-gray-300 text-sm mb-4 leading-relaxed">
                        {job.description}
                      </p>
                      
                      <div className="flex flex-wrap items-center gap-4 text-sm text-gray-400">
                        <div className="flex items-center gap-2">
                          <Users size={14} />
                          <span>{job.department}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <MapPin size={14} />
                          <span>{job.location}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <Clock size={14} />
                          <span>{job.type}</span>
                        </div>
                      </div>
                    </div>
                    
                    <div className="ml-4 flex-shrink-0">
                      <div className="w-8 h-8 rounded-full bg-purple-600/20 flex items-center justify-center group-hover:bg-purple-600/30 transition-colors">
                        <ChevronRight size={16} className="text-purple-400" />
                      </div>
                    </div>
                  </div>
                </Link>
              ))}
            </div>

            <div className="mt-12 bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-xl p-8 border border-[#2a2a2a] text-center">
              <h3 className="text-2xl font-bold mb-4">Don't see the right role?</h3>
              <p className="text-gray-300 mb-6 leading-relaxed">
                We're always looking for talented individuals who share our passion for building 
                great developer tools. Send us your resume and let us know what you're interested in.
              </p>
              <Link 
                to="/careers/contact"
                className="bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white font-medium py-3 px-8 rounded-lg transition-all"
              >
               Get in Touch
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AllPositions;
