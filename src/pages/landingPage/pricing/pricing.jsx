import React from 'react';
import { Check, Cpu, HardDrive, Database, Network } from 'lucide-react';

const Pricing = () => {
  return (
    <div className="min-h-screen bg-[#0a0b14] text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 lg:py-16">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 lg:gap-16 mb-16 lg:mb-24">
          <div className="space-y-6">
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold leading-tight">
              Pay only for what your app uses, by the second
            </h1>
            <p className="text-lg sm:text-xl text-gray-400 leading-relaxed">
              Say goodbye to overprovisioning, without optimizing box sizes. Exoper only charges you for what your app uses.
            </p>
          </div>
          
          <div className="relative">
            <div className="relative bg-gradient-to-br from-[#1a1a2e] to-[#0a0a0a] rounded-2xl p-6 border border-[#2a2a3e] overflow-hidden">
              <style>
                {`
                  @keyframes wave-complex {
                    0% {
                      transform: translateX(0) translateY(0) scale(1) rotate(0deg);
                      opacity: 1;
                    }
                    25% {
                      transform: translateX(-15px) translateY(-5px) scale(1.03) rotate(-0.5deg);
                      opacity: 0.95;
                    }
                    50% {
                      transform: translateX(-20px) translateY(0) scale(1.05) rotate(0deg);
                      opacity: 0.9;
                    }
                    75% {
                      transform: translateX(-15px) translateY(5px) scale(1.03) rotate(0.5deg);
                      opacity: 0.95;
                    }
                    100% {
                      transform: translateX(0) translateY(0) scale(1) rotate(0deg);
                      opacity: 1;
                    }
                  }
                  .wave-animate {
                    animation: wave-complex 10s ease-in-out infinite;
                    transform-origin: center center;
                  }
                `}
              </style>
              <img 
                src="/public/images/features/gpu-usage.png" 
                alt="GPU Usage Chart" 
                className="w-full h-auto object-contain rounded-lg wave-animate"
                loading="lazy"
              />
              
              <div className="absolute top-8 left-8 bg-[#1a1a2e]/90 backdrop-blur-sm border border-[#2a2a3e] rounded-lg px-4 py-2">
                <p className="text-xs text-gray-400">Only pay for</p>
                <p className="text-xs text-gray-400">active CPU</p>
                <p className="text-xs text-gray-400">and memory</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-12">
          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-2xl p-6 sm:p-8 border border-[#2a2a2a]">
            <div className="mb-6">
              <h3 className="text-xl font-semibold mb-2">Free</h3>
              <div className="flex items-baseline gap-2 mb-1">
                <span className="text-4xl sm:text-5xl font-bold">$0</span>
                <span className="text-gray-400 text-sm">per month</span>
              </div>
            </div>
            
            <p className="text-gray-400 text-sm mb-6">
              Perfect for getting started and deploying small apps on Exoper
            </p>
            
            <div className="space-y-3 mb-8">
              <div className="flex items-start gap-3">
                <Check size={18} className="text-gray-400 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Start with a 30-day free trial with $5 credits, then $1 per month</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-gray-400 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Up to 0.5 GB RAM, 1 vCPU per service</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-gray-400 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">0.5 GB of volume storage</span>
              </div>
            </div>
            
            <button className="w-full bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white font-medium py-3 px-6 rounded-lg transition-all">
              Deploy a new project
            </button>
            <p className="text-xs text-gray-500 text-center mt-3">No credit card required</p>
          </div>

          <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-2xl p-6 sm:p-8 border border-[#2a2a2a]">
            <div className="mb-6">
              <h3 className="text-xl font-semibold mb-2">Hobby</h3>
              <div className="flex items-baseline gap-2 mb-1">
                <span className="text-4xl sm:text-5xl font-bold">$5</span>
                <span className="text-gray-400 text-sm">minimum usage</span>
              </div>
            </div>
            
            <p className="text-gray-400 text-sm mb-6">
              For hobbyist developers building side projects
            </p>
            
            <div className="space-y-3 mb-8">
              <div className="flex items-start gap-3">
                <Check size={18} className="text-blue-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Includes $5 of monthly usage credits</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-blue-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">After credits are used, you'll only be charged for extra resource usage</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-blue-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Up to 8 GB RAM / 8 vCPU per service</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-blue-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Single developer workspace</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-blue-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Community support</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-blue-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Global regions</span>
              </div>
            </div>
            
            <button className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-3 px-6 rounded-lg transition-all">
              Deploy with Hobby
            </button>
          </div>

          <div className="bg-gradient-to-br from-[#2a1a3a] to-[#1a0a2a] rounded-2xl p-6 sm:p-8 border border-[#3a2a4a]">
            <div className="mb-6">
              <h3 className="text-xl font-semibold mb-2">Pro</h3>
              <div className="flex items-baseline gap-2 mb-1">
                <span className="text-4xl sm:text-5xl font-bold">$20</span>
                <span className="text-gray-400 text-sm">minimum usage</span>
              </div>
            </div>
            
            <p className="text-gray-400 text-sm mb-6">
              For professional developers and teams shipping production applications
            </p>
            
            <div className="space-y-3 mb-8">
              <div className="flex items-start gap-3">
                <Check size={18} className="text-purple-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Includes $20 of monthly usage credits</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-purple-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">After credits are used, you'll only be charged for extra resource usage</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-purple-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Up to 32 GB RAM / 32 vCPU per service</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-purple-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Unlimited workspace seats included</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-purple-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Priority support</span>
              </div>
              <div className="flex items-start gap-3">
                <Check size={18} className="text-purple-500 mt-0.5 flex-shrink-0" />
                <span className="text-sm text-gray-300">Concurrent global regions</span>
              </div>
            </div>
            
            <button className="w-full bg-gradient-to-r from-purple-600 to-purple-500 hover:from-purple-500 hover:to-purple-400 text-white font-medium py-3 px-6 rounded-lg transition-all">
              Deploy with Pro
            </button>
          </div>
        </div>

        <div className="bg-gradient-to-br from-[#1a1a1a] to-[#0a0a0a] rounded-2xl p-6 sm:p-8 border border-[#2a2a2a] mb-12">
          <div className="mb-6">
            <h3 className="text-2xl font-semibold mb-2">Enterprise</h3>
            <div className="flex items-baseline gap-2 mb-1">
              <span className="text-4xl sm:text-5xl font-bold">Custom</span>
            </div>
          </div>
          
          <p className="text-gray-400 text-sm mb-6 max-w-2xl">
            For teams shipping at scale with compliance and support needs
          </p>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <div className="flex items-start gap-3">
              <Check size={18} className="text-gray-500 mt-0.5 flex-shrink-0" />
              <span className="text-sm text-gray-300">90-day log history</span>
            </div>
            <div className="flex items-start gap-3">
              <Check size={18} className="text-gray-500 mt-0.5 flex-shrink-0" />
              <span className="text-sm text-gray-300">HIPAA BAAs</span>
            </div>
            <div className="flex items-start gap-3">
              <Check size={18} className="text-gray-500 mt-0.5 flex-shrink-0" />
              <span className="text-sm text-gray-300">Support SLOs</span>
            </div>
            <div className="flex items-start gap-3">
              <Check size={18} className="text-gray-500 mt-0.5 flex-shrink-0" />
              <span className="text-sm text-gray-300">Dedicated VMs</span>
            </div>
          </div>
          
          <button className="bg-gray-700 hover:bg-gray-600 text-white font-medium py-3 px-8 rounded-lg transition-all">
            Contact Sales
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="text-center">
            <div className="flex justify-center mb-3">
              <Cpu className="text-purple-400" size={24} />
            </div>
            <h4 className="text-sm font-medium text-gray-400 mb-2">CPU</h4>
            <p className="text-xs text-gray-500">$0.00000772 per vCPU / sec</p>
          </div>

          <div className="text-center">
            <div className="flex justify-center mb-3">
              <Database className="text-purple-400" size={24} />
            </div>
            <h4 className="text-sm font-medium text-gray-400 mb-2">Memory</h4>
            <p className="text-xs text-gray-500">$0.00000386 per GB / sec</p>
          </div>

          <div className="text-center">
            <div className="flex justify-center mb-3">
              <HardDrive className="text-purple-400" size={24} />
            </div>
            <h4 className="text-sm font-medium text-gray-400 mb-2">Volumes</h4>
            <p className="text-xs text-gray-500">$0.00000006 per GB / sec</p>
          </div>

          <div className="text-center">
            <div className="flex justify-center mb-3">
              <Network className="text-purple-400" size={24} />
            </div>
            <h4 className="text-sm font-medium text-gray-400 mb-2">Egress</h4>
            <p className="text-xs text-gray-500">$0.05 per GB</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Pricing;