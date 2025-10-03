import React from 'react';
import { Check } from 'lucide-react';

const PricingDetails = () => {
  const tiers = [
    { name: 'Free', cta: 'Deploy Now', color: 'bg-gradient-to-r from-purple-600 to-purple-500' },
    { name: 'Hobby', cta: 'Deploy with Hobby', color: 'bg-gradient-to-r from-blue-600 to-blue-500' },
    { name: 'Pro', cta: 'Deploy with Pro', color: 'bg-gradient-to-r from-purple-600 to-purple-500' },
    { name: 'Enterprise', cta: 'Contact Sales', color: 'bg-gradient-to-r from-gray-700 to-gray-600' }
  ];

  const resources = [
    { name: 'Projects', values: ['5 during trial, then 1', '50', '100', 'Unlimited'] },
    { name: 'Services per project', values: ['5 during trial, then 3', '50', '100', 'Unlimited'] },
    { name: 'CPU per service', values: ['Up to 2 vCPU during trial, then up to 1 vCPU', 'Up to 8 vCPU', 'Up to 32 vCPU', 'Beyond 32 vCPU'] },
    { name: 'RAM per service', values: ['Up to 1 GB during trial, then up to 0.5 GB', 'Up to 8 GB', 'Up to 32 GB', '64 GB'] },
    { name: 'Ephemeral disk', values: ['1 GB', '100 GB', '100 GB', '100 GB'] },
    { name: 'Volume storage', values: ['0.5 GB', '5 GB', '250 GB', '2 TB'] },
    { name: 'Volumes per project', values: ['3 during trial, then 1', '10', '10, can be increased', 'Unlimited'] },
    { name: 'Cron jobs per project', values: ['Free Trial only', '50', '100', 'Unlimited'] },
    { name: 'Build image size', values: ['4 GB', '100 GB', 'Unlimited', 'Unlimited'] }
  ];

  const scaling = [
    { name: 'Vertical autoscaling', values: [true, true, true, true] },
    { name: 'Horizontal scaling via replicas', values: [true, true, true, true] },
    { name: 'Replicas per service', values: ['2 during the free trial, then 1', '5', '50', '50+'] }
  ];

  const collaboration = [
    { name: 'Team members', values: ['3 during trial, then 1', '3', 'Unlimited', 'Unlimited'] },
    { name: 'Team roles', values: ['-', '-', 'Admin, Member, Deployer', 'Admin, Member, Deployer'] },
    { name: 'Real-time project canvas', values: [true, true, true, true] }
  ];

  const buildDeploy = [
    { name: 'Preview environments', values: [true, true, true, true] },
    { name: 'GitHub repo deployment', values: [true, true, true, true] },
    { name: 'Docker image deployment', values: [true, true, true, true] },
    { name: 'Local repo deployment with the Exoper CLI', values: [true, true, true, true] },
    { name: 'Custom Dockerfile support', values: [true, true, true, true] },
    { name: 'Concurrent builds', values: ['3 during trial, then 1', '3', '10', '10+'] },
    { name: 'Config as code (TOML/JSON)', values: [true, true, true, true] },
    { name: 'Build timeout', values: ['20 mins during trial, then 10 mins', '40 mins', '90 mins', '90+ mins'] },
    { name: 'Service variables and secrets management', values: [true, true, true, true] },
    { name: 'One-click rollbacks', values: [true, true, true, true] },
    { name: 'Redeploy or restart', values: [true, true, true, true] },
    { name: 'Configurable restart policy', values: [true, true, true, true] },
    { name: 'Healthcheck endpoints', values: [true, true, true, true] }
  ];

  const databases = [
    { name: 'Deploy any open-source database', values: [true, true, true, true] },
    { name: 'Built-in database and volume backups', values: [false, false, true, true] },
    { name: 'IOPS', values: ['3,000 read/write operations per second', '3,000 read/write operations per second', '3,000 read/write operations per second', 'custom'] },
    { name: 'Disk usage metrics', values: [true, true, true, true] }
  ];

  const networking = [
    { name: 'Free Exoper domains', values: [true, true, true, true] },
    { name: 'Custom domains', values: ['1 trial, then 0', '2', '20', 'Unlimited'] },
    { name: 'Service domains', values: ['2', '4', '20', 'Unlimited'] },
    { name: 'Global regions', values: ['Trial only, unavailable on the free plan', true, true, true] },
    { name: 'Concurrent regions', values: [false, false, true, true] },
    { name: 'Private networking', values: [true, true, true, true] },
    { name: 'Wildcard domains', values: ['Trial only, unavailable on the free plan', true, true, true] },
    { name: 'Up to 100 Gbps private transfer', values: [true, true, true, true] },
    { name: 'Up to 10 Gbps public transfer', values: [true, true, true, true] },
    { name: 'Multiple IPv6 protocols', values: [true, true, true, true] },
    { name: 'TCP proxy', values: [true, true, true, true] },
    { name: 'HTTP proxy', values: [true, true, true, true] },
    { name: 'DDoS protection', values: [true, true, true, true] }
  ];

  const observability = [
    { name: 'Build/Deploy logs', values: [true, true, true, true] },
    { name: 'CPU/RAM/Disk/Network metrics', values: [true, true, true, true] },
    { name: 'Log retention', values: ['7 days during trial, then 3', '7 days', '30 days', '90 days'] },
    { name: 'Log filtering, querying and structured logging', values: [true, true, true, true] },
    { name: 'Webhooks', values: [true, true, true, true] },
    { name: 'Configurable alerts', values: [true, true, true, true] },
    { name: 'Email alerts', values: [true, true, true, true] }
  ];

  const compliance = [
    { name: 'Hard and soft limits', values: [true, true, true, true] },
    { name: 'SOC 2 compliance', values: [false, false, true, true] },
    { name: 'HIPAA BAA', values: [false, false, false, true] }
  ];

  const support = [
    { name: 'Community support', values: [true, true, true, true] },
    { name: 'Priority support', values: [false, false, true, true] }
  ];

  const addons = [
    {
      icon: '📊',
      title: '90-Day Log History',
      description: 'Extended log retention for better historical analysis and auditing.',
      price: '$200'
    },
    {
      icon: '➕',
      title: 'HIPAA BAAs',
      description: 'HIPAA Business Associate Agreements for compliant health data handling.',
      price: '$1,000'
    },
    {
      icon: '💬',
      title: 'Enterprise Support',
      description: 'Prioritized support with SLOs, direct access to our on-call team for critical issues, and a dedicated Slack Connect channel.',
      price: '$2,000'
    },
    {
      icon: '🖥️',
      title: 'Dedicated VMs',
      description: 'Custom dedicated infrastructure for enhanced performance and control.',
      price: '$10,000'
    }
  ];

  const CheckIcon = () => (
    <div className="flex justify-center">
      <div className="w-5 h-5 rounded-full bg-emerald-500/20 flex items-center justify-center">
        <Check className="w-3 h-3 text-emerald-400" strokeWidth={3} />
      </div>
    </div>
  );

  const Section = ({ title, items }) => (
    <div className="mb-12">
      <h2 className="text-white text-lg md:text-xl font-semibold mb-6 px-4 md:px-0">{title}</h2>
      <div className="space-y-0">
        {items.map((item, idx) => (
          <div
            key={idx}
            className={`grid grid-cols-5 gap-2 md:gap-4 py-4 px-4 md:px-0 ${
              idx % 2 === 0 ? 'bg-gray-900/30' : ''
            }`}
          >
            <div className="col-span-1 flex items-center text-gray-300 text-xs md:text-sm leading-tight">
              {item.name}
            </div>
            {item.values.map((value, vIdx) => (
              <div key={vIdx} className="col-span-1 flex items-center justify-center">
                {typeof value === 'boolean' ? (
                  value ? (
                    <CheckIcon />
                  ) : (
                    <span className="text-gray-600 text-xs">-</span>
                  )
                ) : (
                  <span className="text-gray-300 text-[10px] md:text-sm text-center leading-tight">{value}</span>
                )}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-950 via-gray-900 to-gray-950">
      <div className="max-w-7xl mx-auto py-8 md:py-16 px-2 md:px-4">
        <h1 className="text-3xl md:text-4xl font-bold text-white text-center mb-12 px-4">
          Compare features
        </h1>

        <div className="mb-8 md:mb-12 px-2 md:px-0">
          <div className="grid grid-cols-5 gap-1.5 md:gap-4">
            <div className="col-span-1"></div>
            {tiers.map((tier, idx) => (
              <div key={idx} className="col-span-1 flex flex-col items-center">
                <h3 className="text-white text-[11px] md:text-base font-semibold mb-2 md:mb-3 text-center leading-tight">
                  {tier.name}
                </h3>
                <button
                  className={`${tier.color} text-white text-[9px] md:text-sm font-medium px-1.5 md:px-6 py-1.5 md:py-2.5 rounded-md md:rounded-lg hover:opacity-90 transition-opacity w-full leading-tight`}
                >
                  {tier.cta}
                </button>
              </div>
            ))}
          </div>
        </div>

        <Section title="Resources & limits" items={resources} />
        <Section title="Scaling" items={scaling} />
        <Section title="Collaboration" items={collaboration} />
        <Section title="Build & Deploy" items={buildDeploy} />
        <Section title="Databases & Storage" items={databases} />
        <Section title="Networking" items={networking} />
        <Section title="Observability" items={observability} />
        <Section title="Compliance & Security" items={compliance} />
        <Section title="Support" items={support} />

        <div className="mt-16 md:mt-24 px-4">
          <h2 className="text-2xl md:text-3xl font-bold text-white text-center mb-16 md:mb-20">
            Commonly Asked Questions
          </h2>

          <div className="max-w-4xl mx-auto mb-24 md:mb-32">
            <style>{`
              details summary .icon::before {
                content: '+';
              }
              details[open] summary .icon::before {
                content: '−';
              }
            `}</style>
            <div className="space-y-0">
              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>Which plan is right for me?</span>
                </summary>
                <div className="pb-4 ml-8 space-y-3 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <div className="flex gap-3">
                    <span>•</span>
                    <p>Hobby is for indie hackers and developers to build and deploy personal projects</p>
                  </div>
                  <div className="flex gap-3">
                    <span>•</span>
                    <p>Pro is for professional developers and their teams shipping to production.</p>
                  </div>
                  <div className="flex gap-3">
                    <span>•</span>
                    <p>Enterprise is for dev teams building and deploying production applications with large instance size, SLA, and/or compliance needs.</p>
                  </div>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>How do I get started with the free Trial?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>To start your free trial, sign up for a Exoper account and add a payment method. You'll immediately get access to trial resources which include higher limits for projects, services, and compute resources.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>How does the Trial work?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>The Trial gives you $5 of free credit and increased resource limits to test Exoper's full capabilities. After the trial ends or credits are used, you'll need to subscribe to a paid plan to continue using those resources.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>How does the Hobby plan included usage work?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>The Hobby plan includes $5 of usage each month. This covers your compute, memory, and network usage. Any usage beyond the included $5 will be billed at standard rates.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>Does included usage on Hobby accumulate?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>No, the included usage does not roll over. Each month you receive $5 of included usage, and any unused portion expires at the end of the billing period.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>How can I get a receipt?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>When you make a payment, you will receive an email with your invoice and receipt attached. You can also find your billing history in <span className="underline cursor-pointer hover:text-white transition-colors">Account → Billing</span>.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>How to add company details on my invoice?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>You can add your company details by going to Account → Billing → Invoice Settings. Here you can add your company name, address, VAT number, and other relevant billing information that will appear on your invoices.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>What payment methods are accepted?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>Exoper accepts all major credit and debit cards including Visa, Mastercard, and American Express. We process payments securely through Stripe.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>Can I try Exoper without a credit card?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>Yes, you can use Exoper's Free plan without adding a credit card. However, to access trial resources and paid plans, you'll need to add a payment method.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>Can I upgrade or downgrade at any time?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>Yes, you can upgrade or downgrade your plan at any time. Changes take effect immediately, and billing is prorated based on your usage and the time remaining in your billing period.</p>
                </div>
              </details>

              <details className="group">
                <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                  <span className="icon text-purple-400 mt-1 text-xl"></span>
                  <span>What happens when I cancel my subscription?</span>
                </summary>
                <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                  <p>When you cancel your subscription, you'll retain access to your paid plan features until the end of your current billing period. After that, your account will be downgraded to the Free plan with its associated limits.</p>
                </div>
              </details>
            </div>

            <p className="text-gray-400 text-sm md:text-base mt-8 text-center md:text-left">
              For more information, <span className="underline cursor-pointer hover:text-white transition-colors">check out the docs</span>.
            </p>
          </div>

          <h2 className="text-2xl md:text-3xl font-bold text-white text-center mb-4">
            Unlock more as you grow
          </h2>
          <p className="text-gray-400 text-center mb-12 text-sm md:text-base">
            Commit to a minimum monthly spend to unlock all features up to your spend.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 md:gap-6 max-w-4xl mx-auto">
            {addons.map((addon, idx) => (
              <div
                key={idx}
                className="bg-gray-900/50 border border-gray-800 rounded-xl p-6 hover:border-gray-700 transition-colors"
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-4">
                    <div className="text-3xl">{addon.icon}</div>
                    <div>
                      <h3 className="text-white font-semibold text-base md:text-lg mb-2">
                        {addon.title}
                      </h3>
                      <p className="text-gray-400 text-xs md:text-sm leading-relaxed">
                        {addon.description}
                      </p>
                    </div>
                  </div>
                  <div className="text-white font-bold text-lg md:text-xl whitespace-nowrap ml-4">
                    {addon.price}
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="text-center mt-16 md:mt-20">
            <h3 className="text-xl md:text-2xl font-bold text-white mb-4">
              Want it now? Unlock instantly
              <br className="hidden md:block" /> with a monthly commitment.
            </h3>
            <button className="bg-gradient-to-r from-purple-600 to-purple-500 text-white font-medium px-8 py-3 rounded-lg hover:opacity-90 transition-opacity mt-6">
              Contact Sales
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PricingDetails;