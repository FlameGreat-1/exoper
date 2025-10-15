import React from 'react';
import { ArrowLeft, MapPin, Clock, Circle } from 'lucide-react';
import { Link } from 'react-router-dom';

const SeniorFullStackEngineer = () => {
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
          Senior Full-Stack Engineer - Product
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
              to="/careers/apply?position=Senior Full-Stack Engineer - Product"
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
                  Our core mission at Exoper is to make software engineers higher leverage. We believe that people
                  should be given powerful tools so that they can spend less time setting up to do, and more time
                  doing.
                </p>
                <p>
                  At Exoper, we believe that making tooling more accessible for build and deployment is one of the
                  greatest possible productivity unlocks of our generation. We also believe that the major roadblock
                  between us and our goal is strong interfacing paradigms.
                </p>
                <p>
                  If you're looking to build an operating system for builders, we'd love to talk with you!
                </p>
                <blockquote className="italic border-l-2 border-gray-700 pl-4 my-6">
                  "Computer scientists have so far worked on developing powerful programming languages that make it
                  possible to solve the technical problems of computation. Little effort has gone toward devising the
                  language of interaction."
                </blockquote>
                <p className="text-sm">- Donald Norman</p>
                <p className="mt-6">
                  Curious? Learn more in our blog post about this team and the great work they're doing:{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    Team Spotlight: Product Engineering
                  </a>
                </p>
                <p>
                  Want to learn about our work culture? Here is a three-part blog series that will help you see the unique
                  ways our team works (Parts{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">1</a>,{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">2</a>,{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">3</a>, and{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">4</a>).
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
                      Build features end-to-end, from the UI in our dashboard to orchestrating workflows that interact
                      with our microservices using Temporal.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Craft intuitive interfaces that allow our users to interface with powerful computing paradigms,
                      with help from our design team.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Build TypeScript + GraphQL APIs with strong guarantees around modeling data, allowing both
                      internal and external users to build against.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Write Engineering Requirement Documents to take something from idea, to defined tasks, to
                      implementation, to monitoring it's success.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Experience with, or at least the desire to learn Rust to contribute to our open-source repositories
                      (CLI,{' '}
                      <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                        Exope
                      </a>
                      , etc)
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>You may be on-call from time to time in this role</span>
                  </li>
                </ul>

                <p className="mt-6">Some projects full-stack engineers have worked on in the past</p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                        Rebuild logging infrastructure
                      </a>{' '}
                      to support 1B logs/day, from configuring ClickHouse to developing a brand new observability UI
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Build{' '}
                      <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                        Git for infrastructure
                      </a>{' '}
                      and re-thinking how a project evolves over time
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Build a tool for building user code into a deployable image using Nix packages.{' '}
                      <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                        github.com/Exoperapp/Exope
                      </a>
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Create interfaces to visualize project infrastructure on a 2D canvas
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Add support for migrating deployments with a volume from one region to another using Temporal
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Create a{' '}
                      <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                        marketplace
                      </a>{' '}
                      for users to share re-usable pieces of infrastructure
                    </div>
                  </li>
                </ul>

                <p className="mt-6">
                  This is a high impact, high agency role with direct effect on company culture, trajectory, and outcome.
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
                      An ability to autonomously lead, design, and implement great product experiences, from front to
                      back.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      A strong understanding of frontend architecture to build interactivity-rich systems for fetching,
                      mutating, and rendering data effectively
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Experience managing complex asynchronous backend jobs for something like a build/deploy
                      pipeline.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      A desire to be a part of the entire project development process. From research gathering and
                      planning, to implementation and monitoring
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Great written and verbal communication skills for expressing ideas, designs, and potential
                      solutions in mostly-asynchronous manner
                    </span>
                  </li>
                </ul>

                <p className="mt-6 font-medium">
                  We value and love to work with diverse persons from all backgrounds
                </p>
              </div>
            </section>

            <section id="things-to-know">
              <h2 className="text-2xl font-bold mb-6">Things to know</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  For better or worse, we're a startup; our team dynamics are different from companies of different
                  sizes and stages.
                </p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We're distributed ALL across the globe, and that's only going to be more and more distributed. As
                      a result, stuff is ALWAYS happening.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We do NOT expect you to work all the time, but you'll have to be diligent about your boundaries
                      because the end of your day may overlap with the start of someone else's.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We're a small team, with high ownership, who are not only passionate about what we do, but seek
                      to be exceptional as well. At the time of writing we're 21, serving hundreds of thousands of users.
                      There's a lot of stuff going on, and a lot of ambiguity.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We want you to own it. We believe that ownership is a key to growth, and part of that growth is
                      not only being able to make the choices, but owning the success, or failure, that comes with
                      those choices.
                    </span>
                  </li>
                </ul>
              </div>
            </section>

            <section id="benefits">
              <h2 className="text-2xl font-bold mb-6">Benefits and perks</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  At Exoper, we provide best in class benefits. Great salary, full health benefits including dependents,
                  strong equity grants, equipment stipend, and much more. For more details, check back on the main{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    careers page
                  </a>
                  .
                </p>

                <p className="mt-6">
                  Beyond compensation, there are a few things that we believe that make working at Exoper truly
                  unique:
                </p>

                <ul className="space-y-4 ml-4 mt-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Autonomy</span>: We have very few meetings. Just a Monday and a Friday to go over the Company
                    </div>
                  </li>
                </ul>
              </div>
            </section>

            <section id="how-we-hire">
              <h2 className="text-2xl font-bold mb-6">How we hire</h2>
              <div className="space-y-8 text-gray-300 leading-relaxed">
                <p>No tricks. No surprises. Here's the entire process.</p>

                <div className="space-y-6">
                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      1
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Talk with us about the role</h3>
                      <p>
                        This is completely open ended and we're just trying to see who you are, what you want to do,
                        and where you wanna go.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      2
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Work on a small project to discuss in the interview</h3>
                      <p className="mb-3">Asychronously implement the following:</p>
                      <ul className="space-y-2 ml-4">
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Build an application to spin up and spin down a container using our GQL API. Please
                            deploy on Exoper before the interview and we will review the code during your interview.
                            The app needs to have a UI component and not just a backend that uses the API.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            You will submit your solution before the interview and sit down with a member of the
                            team and go over the above. We'll poke into your solution, as well as get you acquainted
                            with a member of the team.
                          </span>
                        </li>
                      </ul>
                      <div className="mt-4 space-y-2 ml-4">
                        <p className="font-medium">Interview Structure to expect when you review with the team (60 Minutes):</p>
                        <p>Prework (submitted before your interview): Create your app</p>
                        <p>0-5 minutes: Introductions</p>
                        <p>5-35 minutes: Walking through the code, talking about how you'd extend it</p>
                        <p>35-50 minutes: Noodling on technology, frameworks, how you think about product</p>
                        <p>50-60 minutes: Time for you to ask your interviewers question</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center">
                      <span className="text-lg">😊</span>
                    </div>
                    <div className="flex-1">
                      <p className="text-purple-400 font-medium">
                        You can, and SHOULD ask us questions ahead of time. Ask away!
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      3
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Review your solution with the Team</h3>
                      <p className="mb-3">
                        You'll sit down with someone on the team and go over the above. We'll poke into your solution,
                        as well as get you acquainted with two more members of the team.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Learn about your problem solving skills, how you break down a problem and how you
                        present a solution.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      4
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Meet the Team</h3>
                      <p className="mb-3">
                        You'll meet the Team, which will be comprised of 4 people from vastly different sections of the
                        company.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: How you work with the rest of the team and communicate.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      5
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Chat with CEO</h3>
                      <p>
                        Sit down with our founder and CEO for 30 minutes. This is a 1:1, open ended conversation.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      6
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Offer call</h3>
                      <p>
                        Finally, we'll present the offers, hammer out the details about your position, tee up
                        onboarding, and start our journey together.
                      </p>
                    </div>
                  </div>
                </div>

                <p className="mt-8 italic">
                  Final Note: The interview goes <span className="underline">both ways</span>. Once again, please ask us things. Many things! Hard things.
                  That's what we're here for.
                </p>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SeniorFullStackEngineer;