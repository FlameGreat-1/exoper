import React from 'react';
import { ArrowLeft, MapPin, Clock, Circle } from 'lucide-react';
import { Link } from 'react-router-dom';

const MLEngineerJob = () => {
  return (
    <div className="min-h-screen bg-[#0a0b14] text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-12">
        <button className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-8 text-sm">
          <ArrowLeft size={16} />
          ALL POSITIONS
        </button>

        <h1 className="text-4xl lg:text-5xl font-bold mb-12 lg:mb-16">
          Senior ML Engineer - AI Platform
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
              to="/careers/apply?position=ML Engineer"
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
                  We're building intelligent systems that help developers build better software faster. Our ML platform powers features from intelligent code suggestions to automated deployment optimization, serving millions of predictions daily.
                </p>
                <p>
                  As a Senior ML Engineer, you'll design, train, and deploy machine learning models at scale. You'll work on challenging problems in natural language processing, predictive analytics, and recommendation systems that directly impact developer productivity.
                </p>
                <p>
                  If you're excited about applying cutting-edge ML techniques to real-world problems and want to see your models impact thousands of developers, we'd love to talk!
                </p>
                <blockquote className="italic border-l-2 border-gray-700 pl-4 my-6">
                  "Machine learning is the next frontier in building intelligent systems that augment human capabilities."
                </blockquote>
                <p className="text-sm">- Andrew Ng</p>
                <p className="mt-6">
                  Learn about our ML approach and technical challenges on our{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    AI research blog
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
                      Design and implement machine learning models using PyTorch, TensorFlow, or JAX for production deployment at scale.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Build end-to-end ML pipelines including data collection, feature engineering, model training, evaluation, and monitoring.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Develop NLP systems for code understanding, documentation generation, and intelligent developer assistance features.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Optimize model inference for low-latency predictions, implementing techniques like model quantization, distillation, and caching.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Build recommendation systems and ranking algorithms that personalize developer experiences and improve engagement.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Implement MLOps practices including experiment tracking, model versioning, A/B testing, and automated retraining pipelines.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Collaborate with product and engineering teams to identify ML opportunities and translate business requirements into technical solutions.
                    </span>
                  </li>
                </ul>

                <p className="mt-6">Recent ML projects our team has shipped:</p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Built a transformer-based code completion model trained on 10B+ tokens, achieving 45% acceptance rate with sub-100ms latency.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Developed an intelligent resource prediction system using time-series forecasting that reduced deployment costs by 30%.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Created an anomaly detection model for infrastructure monitoring that identifies issues 15 minutes before they impact users.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Implemented a personalized project recommendation engine using collaborative filtering and content-based approaches.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Built an automated code review assistant using fine-tuned language models that catches 60% of common bugs.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      Developed a semantic search system using embeddings that improved documentation discovery by 3x.
                    </div>
                  </li>
                </ul>

                <p className="mt-6">
                  This role offers high impact with direct influence on product features used by thousands of developers daily.
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
                      5+ years of experience building and deploying machine learning models in production environments.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong foundation in machine learning fundamentals including deep learning, optimization, and statistical methods.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Expertise with ML frameworks like PyTorch, TensorFlow, or JAX, and experience with distributed training.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Proficiency in Python and experience with data processing libraries like pandas, NumPy, and scikit-learn.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Experience with NLP techniques including transformers, embeddings, and fine-tuning large language models.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Knowledge of MLOps tools like MLflow, Weights & Biases, or similar for experiment tracking and model management.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Understanding of model deployment patterns including REST APIs, batch inference, and real-time serving architectures.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Strong problem-solving skills with ability to formulate business problems as ML tasks and evaluate trade-offs.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Bonus: Publications in ML conferences, contributions to open-source ML projects, or experience with LLMs and prompt engineering.
                    </span>
                  </li>
                </ul>

                <p className="mt-6 font-medium">
                  We welcome ML engineers from diverse backgrounds who bring unique perspectives to solving complex problems.
                </p>
              </div>
            </section>

            <section id="things-to-know">
              <h2 className="text-2xl font-bold mb-6">Things to know</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  Working on ML at a startup means balancing research with practical engineering. Here's what that means:
                </p>

                <ul className="space-y-4 ml-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We're a distributed team across multiple timezones. Async collaboration and good documentation are critical for success.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We prioritize shipping production-ready models over perfect research. Impact and iteration speed matter more than novelty.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      Our ML team is small but growing. You'll have significant ownership and influence over technical direction and architecture.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We work closely with product and engineering teams. Being able to communicate ML concepts to non-ML audiences is essential.
                    </span>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <span>
                      We invest in good infrastructure and tooling. You'll spend time building ML platforms and tools that make the team more productive.
                    </span>
                  </li>
                </ul>
              </div>
            </section>

            <section id="benefits">
              <h2 className="text-2xl font-bold mb-6">Benefits and perks</h2>
              <div className="space-y-4 text-gray-300 leading-relaxed">
                <p>
                  Competitive compensation with equity, comprehensive health coverage for you and dependents, equipment and home office budget, flexible time off, and more. Check our{' '}
                  <a href="#" className="text-purple-400 hover:text-purple-300 underline">
                    careers page
                  </a>{' '}
                  for complete benefits details.
                </p>

                <p className="mt-6">
                  What makes ML engineering here special:
                </p>

                <ul className="space-y-4 ml-4 mt-4">
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">GPU budget</span>: Access to powerful compute resources for training and experimentation without bureaucracy.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Research time</span>: Dedicated time to explore new techniques, read papers, and experiment with cutting-edge approaches.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Conference budget</span>: Attend ML conferences like NeurIPS, ICML, ACL, or present your work at industry events.
                    </div>
                  </li>
                  <li className="flex gap-3">
                    <span className="text-gray-500 mt-1.5">-</span>
                    <div>
                      <span className="font-medium">Open source</span>: Contribute to and open source ML tools and models as part of your work.
                    </div>
                  </li>
                </ul>
              </div>
            </section>

            <section id="how-we-hire">
              <h2 className="text-2xl font-bold mb-6">How we hire</h2>
              <div className="space-y-8 text-gray-300 leading-relaxed">
                <p>Our process is transparent and focused on evaluating real ML skills. Here's what to expect:</p>

                <div className="space-y-6">
                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      1
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">Introduction call</h3>
                      <p>
                        A 30-minute conversation to understand your ML background, projects you're proud of, and what you're looking for in your next role.
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      2
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">ML take-home project</h3>
                      <p className="mb-3">Work on a realistic ML problem:</p>
                      <ul className="space-y-2 ml-4">
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Build a model to solve a prediction or classification task using a provided dataset. Choose your approach and framework.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Include data exploration, feature engineering, model selection, evaluation metrics, and a simple inference API.
                          </span>
                        </li>
                        <li className="flex gap-2">
                          <span className="text-gray-500">◦</span>
                          <span>
                            Document your approach, experiments tried, results, and how you'd improve the system in production.
                          </span>
                        </li>
                      </ul>
                      <div className="mt-4 space-y-2 ml-4">
                        <p className="font-medium">Technical interview (90 minutes):</p>
                        <p>0-10 minutes: Introductions and overview</p>
                        <p>10-45 minutes: Present your solution, discuss experiments and model choices</p>
                        <p>45-75 minutes: ML concepts deep dive and problem-solving scenarios</p>
                        <p>75-90 minutes: Your questions about our ML infrastructure and projects</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4 items-start">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center">
                      <span className="text-lg">🤖</span>
                    </div>
                    <div className="flex-1">
                      <p className="text-purple-400 font-medium">
                        Have questions about the dataset or requirements? Don't hesitate to ask!
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-purple-500 flex items-center justify-center font-bold text-sm">
                      3
                    </div>
                    <div className="flex-1">
                      <h3 className="text-white font-semibold text-lg mb-2">ML system design</h3>
                      <p className="mb-3">
                        Discuss how you'd design ML systems for production, including training pipelines, model serving, and monitoring.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: System thinking, MLOps knowledge, and understanding of production ML challenges.
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
                        Meet with engineers and product managers to discuss how you work with cross-functional teams.
                      </p>
                      <p className="text-purple-400 italic">
                        Looking for: Communication skills, collaboration approach, and ability to explain complex ML concepts.
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
                        Meet with engineering leadership to discuss ML strategy, research opportunities, and career growth.
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
                        Review the offer details, discuss your first projects, and plan your onboarding with the team.
                      </p>
                    </div>
                  </div>
                </div>

                <p className="mt-8 italic">
                  Remember: This is a <span className="underline">two-way evaluation</span>. Ask us about our ML infrastructure, data access, model deployment process, and how we balance research with product needs.
                </p>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
};

export default MLEngineerJob;