import React from 'react';
import { ArrowLeft, MapPin, Clock, Circle } from 'lucide-react';
import { Link } from 'react-router-dom';

const ProductMarketerJob = () => {
  return (
    <div className="min-h-screen bg-[#0a0b14] text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
        <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8 text-sm">
          <ArrowLeft size={16} />
          ALL POSITIONS
        </button>

        <h1 className="text-4xl lg:text-5xl font-bold mb-12 lg:mb-16">
          Senior Product Marketer
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
              to="/careers/apply?position=Senior product Marketer"
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
                  We're on a mission to empower developers with tools that amplify their capabilities. Our product marketing team plays a crucial role in translating complex technical concepts into compelling narratives that resonate with our community.
                </p>
                <p>
                  As a Senior Product Marketer, you'll shape how developers discover, understand, and adopt our platform. You'll work closely with product, engineering, and growth teams to craft positioning, launch campaigns, and build programs that drive meaningful engagement.
                </p>
                <p>
                  If you're passionate about developer tools, love telling stories that connect with technical audiences, and want to make a real impact, let's connect!
                </p>
                <blockquote className="italic border-l-2 border-gray-700 pl-4 my-6">
                  "Marketing is no longer about the stuff that you make, but about the stories you tell."
                </blockquote>
                <p className="text-sm">- Seth Godin</p>
                <p className="mt-6">
                  Want to see our marketing in action? Check out our{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    blog
                  </a>
                  ,{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    case studies
                  </a>
                  , and{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    community initiatives
                  </a>.
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
                      Develop and execute go-to-market strategies for product launches, ensuring successful adoption and market penetration.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Create compelling product positioning and messaging that differentiates us in the developer tools landscape.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Build and optimize content programs including blog posts, case studies, whitepapers, and technical documentation that drive conversions.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Collaborate with product teams to deeply understand features, use cases, and customer pain points to inform marketing strategy.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Design and execute campaigns across multiple channels including email, social media, community forums, and developer conferences.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Analyze campaign performance, conduct market research, and use data to optimize marketing initiatives and inform product strategy.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Build relationships with developer communities, influencers, and partners to expand our reach and credibility.
                    </span>
                  </li>
                </ul>

                <p className="mt-6">Recent marketing initiatives you might work on:</p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Launch a major product feature with coordinated content across blog, docs, social media, and email campaigns reaching 500K+ developers.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Create a developer education series with tutorials, livestreams, and hands-on workshops that increased activation by 35%.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Build a customer advocacy program featuring case studies and testimonials from leading tech companies and startups.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Develop competitive positioning and battle cards that helped sales close 40% more enterprise deals.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Establish partnerships with developer communities, bootcamps, and open source projects to expand brand awareness.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Launch a technical content hub with deep-dive articles that became the top organic traffic driver, generating 200K monthly visits.
                    </div>
                  </li>
                </ul>

                <p className="mt-6">
                  This is a high-visibility role where your work directly impacts company growth, brand perception, and product adoption.
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
                      5+ years of product marketing experience, preferably in developer tools, SaaS, or technical B2B products.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Deep understanding of developer audiences, including how they discover tools, evaluate solutions, and make purchasing decisions.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Proven track record of successful product launches and go-to-market strategies that drove measurable business results.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Exceptional writing and storytelling skills with the ability to translate technical features into customer benefits and compelling narratives.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong analytical mindset with experience using data and metrics to inform decisions and optimize marketing performance.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Collaborative approach with experience working cross-functionally with product, engineering, sales, and leadership teams.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Self-starter mentality with the ability to manage multiple projects, prioritize effectively, and deliver results in a fast-paced environment.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Bonus: Technical background or experience working closely with engineering teams, familiarity with DevOps and cloud infrastructure.
                    </span>
                  </li>
                </ul>

                <p className="mt-6 font-medium">
                  We value diverse perspectives and welcome marketers from various backgrounds who bring fresh ideas to the table.
                </p>
              </div>
            </section>

            <section id="things-to-know">
              <h2 className="text-2xl font-bold mb-6">Things to know</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  Working at a fast-growing startup means embracing ambiguity and moving quickly. Here's what that looks like:
                </p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We're a globally distributed team spanning multiple continents and timezones, which means flexible async communication is essential.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We move fast and iterate quickly. You'll ship campaigns and content regularly, learn from data, and optimize continuously.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Our marketing team is lean and scrappy. You'll wear multiple hats, from strategy to execution, and have significant autonomy in your work.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We're building for a technical audience that values authenticity, transparency, and substance over hype. Marketing here means deep product knowledge and genuine community engagement.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Your work will be highly visible to our leadership, customers, and the broader developer community. Impact and accountability go hand in hand.
                    </span>
                  </li>
                </ul>
              </div>
            </section>

            <section id="benefits">
              <h2 className="text-2xl font-bold mb-6">Benefits and perks</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  We offer competitive compensation packages including strong base salary, meaningful equity, comprehensive health insurance for you and your family, home office setup budget, and unlimited PTO. Visit our{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    careers page
                  </a>{' '}
                  for full benefits information.
                </p>

                <p className="mt-6">
                  What makes our marketing team unique:
                </p>

                <ul className="space-y-4 ml-4 mt-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Creative freedom</span>: We trust you to experiment, take risks, and find what works. No bureaucracy or endless approval chains.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Direct impact</span>: Your campaigns and content directly influence company growth and product direction. Your voice matters.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Learning and growth</span>: Budget for courses, conferences, certifications, and professional development opportunities.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Community access</span>: Work directly with an engaged developer community and attend industry events and conferences.
                    </div>
                  </li>
                </ul>
              </div>
            </section>

            <section id="how-we-hire">
              <h2 className="text-2xl font-bold mb-6">How we hire</h2>
              <div className="space-y-8 text-gray-300 leading-relaxed">
                <p>We believe in transparency. Here's our complete hiring process:</p>

                <div className="space-y-6">
                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      1
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Get to know you</h3>
                      <p>
                        A 30-minute conversation about your background, marketing philosophy, and what you're looking for in your next role.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      2
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Marketing challenge</h3>
                      <p className="mb-3">Complete a realistic marketing project that showcases your skills:</p>
                      <ul className="space-y-2 ml-4">
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Develop a go-to-market strategy for a new product feature. Include positioning, messaging, target audience analysis, channel strategy, and success metrics.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Create two pieces of content: a blog post announcing the feature and a social media campaign plan to drive awareness.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Submit your work 48 hours before the interview. We'll discuss your approach, decisions, and how you'd measure success.
                          </span>
                        </li>
                      </ul>
                      <div className="mt-4 space-y-2 ml-4">
                        <p className="font-medium">Interview structure (60 minutes):</p>
                        <p>0-5 minutes: Warm up and introductions</p>
                        <p>5-30 minutes: Present your marketing strategy and discuss your approach</p>
                        <p>30-50 minutes: Deep dive into marketing tactics, metrics, and hypothetical scenarios</p>
                        <p>50-60 minutes: Your questions about the role, team, and company</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center">
                      <span className="text-lg">✨</span>
                    </div>
                    <div className="flex-1">
                      <p className="text-purple-400 font-medium">
                        Questions about the challenge? Reach out anytime. We want you to do your best work!
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      3
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Cross-functional collaboration</h3>
                      <p className="mb-3">
                        Meet with product and engineering leads to discuss how you'd work together on launches and campaigns.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Collaboration style, technical aptitude, and ability to work with diverse teams.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      4
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Team conversations</h3>
                      <p className="mb-3">
                        Chat with 3-4 team members from different departments to understand our culture and how we work together.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Cultural fit, communication style, and shared values.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      5
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Executive conversation</h3>
                      <p>
                        Meet with our leadership team to discuss vision, strategy, and where marketing fits in our growth plans.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      6
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Offer and next steps</h3>
                      <p>
                        We'll extend an offer with full details on compensation, equity, and benefits. Then we'll plan your onboarding and first 90 days.
                      </p>
                    </div>
                  </div>
                </div>

                <p className="mt-8 italic">
                  Important note: This process is <span className="underline">collaborative</span>. We're evaluating you, and you're evaluating us. Ask hard questions, be curious, and help us both make the right decision.
                </p>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ProductMarketerJob;