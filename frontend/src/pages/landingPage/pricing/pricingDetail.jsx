import React from 'react';
import { Check } from 'lucide-react';

const PricingDetails = () => {
  const tiers = [
    { name: 'Starter', cta: 'Start Free Trial', color: 'bg-gradient-to-r from-purple-600 to-purple-500' },
    { name: 'Professional', cta: 'Deploy with Professional', color: 'bg-gradient-to-r from-blue-600 to-blue-500' },
    { name: 'Enterprise', cta: 'Deploy with Enterprise', color: 'bg-gradient-to-r from-purple-600 to-purple-500' },
    { name: 'Custom', cta: 'Contact Sales', color: 'bg-gradient-to-r from-gray-700 to-gray-600' }
  ];

  const resources = [
    { name: 'AI Requests per month', values: ['10,000', '500,000 included', '5,000,000 included', 'Unlimited'] },
    { name: 'Model endpoints monitored', values: ['1', 'Up to 5', 'Unlimited', 'Unlimited'] },
    { name: 'Threat detection scans', values: ['Basic (10K/month)', 'Advanced (500K/month)', 'Full suite (5M/month)', 'Unlimited'] },
    { name: 'Audit log retention', values: ['7 days', '30 days', '90 days', 'Unlimited'] },
    { name: 'Request throughput', values: ['100 req/sec', '1,000 req/sec', '10,000 req/sec', 'Custom'] },
    { name: 'Compliance frameworks', values: ['Basic templates', 'GDPR templates', 'EU AI Act, HIPAA, SOC 2', 'Custom frameworks'] },
    { name: 'Data residency options', values: ['Single region', 'Multi-region', 'Multi-region + choice', 'On-premises available'] },
    { name: 'Audit storage (WORM)', values: ['Not included', '10 GB', '100 GB', 'Unlimited'] }
  ];

  const security = [
    { name: 'Prompt injection detection', values: [true, true, true, true] },
    { name: 'PII scanning & redaction', values: [true, true, true, true] },
    { name: 'ML anomaly detection', values: [false, true, true, true] },
    { name: 'Adversarial attack testing', values: [false, false, true, true] },
    { name: 'Red-team sandbox', values: [false, false, true, true] },
    { name: 'Custom threat rules', values: [false, true, true, true] },
    { name: 'Real-time threat blocking', values: [true, true, true, true] },
    { name: 'Output sanitization', values: [true, true, true, true] }
  ];

  const gateway = [
    { name: 'Zero-trust API gateway', values: [true, true, true, true] },
    { name: 'Multi-tenant isolation', values: [false, true, true, true] },
    { name: 'Rate limiting & quotas', values: [true, true, true, true] },
    { name: 'Load balancing', values: ['Basic', 'Advanced', 'Advanced', 'Custom'] },
    { name: 'Request authentication (mTLS, OIDC)', values: [true, true, true, true] },
    { name: 'Policy engine (OPA)', values: [false, true, true, true] },
    { name: 'Edge WASM filters', values: [false, false, true, true] },
    { name: 'DDoS protection', values: [true, true, true, true] }
  ];

  const collaboration = [
    { name: 'Team seats', values: ['1', 'Up to 5', 'Unlimited', 'Unlimited'] },
    { name: 'Role-based access control', values: [false, true, true, true] },
    { name: 'Audit trail access', values: ['View only', 'View & export', 'Full access', 'Full access'] },
    { name: 'Admin control plane', values: [false, true, true, true] }
  ];

  const deployment = [
    { name: 'Cloud deployment (managed)', values: [true, true, true, true] },
    { name: 'Multi-region deployment', values: [false, true, true, true] },
    { name: 'Concurrent regions', values: [false, false, true, true] },
    { name: 'On-premises deployment', values: [false, false, false, true] },
    { name: 'Kubernetes/Helm packaging', values: [false, false, true, true] },
    { name: 'HSM support', values: [false, false, false, true] },
    { name: 'Custom infrastructure', values: [false, false, false, true] },
    { name: 'Air-gapped deployment', values: [false, false, false, true] }
  ];

  const observability = [
    { name: 'Real-time monitoring dashboard', values: [true, true, true, true] },
    { name: 'Threat detection alerts', values: [true, true, true, true] },
    { name: 'Request/response logging', values: [true, true, true, true] },
    { name: 'Metrics & traces (OpenTelemetry)', values: [false, true, true, true] },
    { name: 'SIEM integration', values: [false, false, true, true] },
    { name: 'Custom webhooks', values: [false, true, true, true] },
    { name: 'Anomaly detection reports', values: [false, true, true, true] }
  ];

  const compliance = [
    { name: 'Compliance templates', values: ['Basic', 'GDPR', 'EU AI Act, GDPR, HIPAA, SOC 2', 'Custom'] },
    { name: 'Automated compliance mapping', values: [false, true, true, true] },
    { name: 'Audit report generation', values: [false, true, true, true] },
    { name: 'HIPAA BAA', values: [false, false, true, true] },
    { name: 'SOC 2 compliance', values: [false, false, true, true] },
    { name: 'Data sovereignty controls', values: [false, true, true, true] }
  ];

  const support = [
    { name: 'Community support', values: [true, true, true, true] },
    { name: 'Email support', values: [false, true, true, true] },
    { name: 'Priority support', values: [false, true, true, true] },
    { name: 'Support SLOs', values: [false, false, true, true] },
    { name: 'Dedicated account manager', values: [false, false, false, true] },
    { name: '24/7 on-call support', values: [false, false, false, true] },
    { name: 'Slack Connect channel', values: [false, false, false, true] }
  ];

  const addons = [
    {
      icon: '🔐',
      title: 'Extended Audit Retention (1 year)',
      description: 'Keep immutable audit logs for 365 days with cryptographic verification for regulatory compliance.',
      price: '$500'
    },
    {
      icon: '🏥',
      title: 'HIPAA BAA + Compliance Pack',
      description: 'HIPAA Business Associate Agreement with automated compliance monitoring and reporting.',
      price: '$1,500'
    },
    {
      icon: '🛡️',
      title: 'Advanced Threat Intelligence',
      description: 'Premium threat feeds, custom ML models, and dedicated red-team testing for your AI systems.',
      price: '$2,500'
    },
    {
      icon: '🖥️',
      title: 'Dedicated Infrastructure',
      description: 'Isolated VMs, HSM integration, and custom deployment architecture for maximum control.',
      price: '$15,000'
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

        <Section title="Resources & Limits" items={resources} />
        <Section title="Threat Detection & Security" items={security} />
        <Section title="API Gateway & Access Control" items={gateway} />
        <Section title="Collaboration" items={collaboration} />
        <Section title="Deployment Options" items={deployment} />
        <Section title="Observability & Monitoring" items={observability} />
        <Section title="Compliance & Governance" items={compliance} />
        <Section title="Support" items={support} />

        <div className="mt-16 md:mt-24 px-4">
          <h2 className="text-2xl md:text-3xl font-bold text-white text-center mb-4">
            Unlock more as you grow
          </h2>
          <p className="text-gray-400 text-center mb-12 text-sm md:text-base">
            Add enterprise-grade capabilities with flexible add-ons
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
              Need custom solutions?
              <br className="hidden md:block" /> Contact our team for tailored pricing.
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