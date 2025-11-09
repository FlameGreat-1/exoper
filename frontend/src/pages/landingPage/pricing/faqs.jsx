import React from 'react';

const FAQs = () => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-950 via-gray-900 to-gray-950">
      <div className="max-w-7xl mx-auto py-8 md:py-16 px-4 md:px-6">
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
                  <p>Starter is for development teams testing AI security and compliance workflows in non-production environments.</p>
                </div>
                <div className="flex gap-3">
                  <span>•</span>
                  <p>Professional is for organizations deploying production AI applications with security monitoring and basic compliance needs.</p>
                </div>
                <div className="flex gap-3">
                  <span>•</span>
                  <p>Enterprise is for large organizations with high-volume AI workloads, advanced threat detection, and strict regulatory compliance requirements (HIPAA, SOC 2, EU AI Act).</p>
                </div>
                <div className="flex gap-3">
                  <span>•</span>
                  <p>Custom is for organizations requiring on-premises deployment, dedicated infrastructure, or specialized compliance frameworks.</p>
                </div>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>How do I get started with the free trial?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>To start your free trial, sign up for an Exoper account. You'll immediately get access to 10,000 AI request credits for 30 days with basic threat detection capabilities. No credit card required to start.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>How does the trial work?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>The trial gives you 10,000 AI request credits and access to basic threat detection features for 30 days. You can monitor 1 model endpoint and test prompt injection detection, PII scanning, and basic security workflows. After the trial ends, you'll need to subscribe to a paid plan to continue using the platform.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>How does the Professional plan included usage work?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>The Professional plan includes $299 of usage each month, which covers up to 500,000 AI requests with threat detection. Any usage beyond the included credits will be billed at standard rates: $0.0012 per AI request and $0.0002 per threat scan.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>Does included usage on Professional accumulate?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>No, the included usage does not roll over. Each month you receive $299 of included usage, and any unused portion expires at the end of the billing period.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>What counts as an AI request?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>An AI request is any input/output interaction with your AI models that passes through Exoper's security gateway. This includes requests to external LLMs (OpenAI, Anthropic), internal models, or any AI endpoint you've configured for monitoring. Each request is scanned for threats and logged for compliance.</p>
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
                <p>Exoper accepts all major credit and debit cards including Visa, Mastercard, and American Express. Enterprise customers can also arrange for invoiced billing with NET 30 payment terms. We process payments securely through Stripe.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>Can I try Exoper without a credit card?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>Yes, you can start with the Starter plan's free trial without adding a credit card. You'll get 10,000 AI request credits for 30 days to test the platform. To access paid plans and higher limits, you'll need to add a payment method.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>Can I upgrade or downgrade at any time?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>Yes, you can upgrade or downgrade your plan at any time. Changes take effect immediately, and billing is prorated based on your usage and the time remaining in your billing period. Your audit logs and configurations are preserved when changing plans.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>What happens when I cancel my subscription?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>When you cancel your subscription, you'll retain access to your paid plan features until the end of your current billing period. After that, your account will be downgraded to the Starter plan. Your audit logs will be retained according to your plan's retention period, and you can export them before downgrading.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>Do you offer discounts for startups or non-profits?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>Yes, we offer special pricing for qualifying startups, non-profits, and educational institutions. Contact our sales team at sales@exoper.com with details about your organization to learn more about our discount programs.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>How is data sovereignty handled?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>Professional and Enterprise plans support multi-region deployment, allowing you to choose where your data is processed and stored. Enterprise and Custom plans offer full data residency controls to meet GDPR, EU AI Act, and other regional compliance requirements. On-premises deployment is available for Custom plans.</p>
              </div>
            </details>

            <details className="group">
              <summary className="flex items-start gap-3 cursor-pointer list-none text-white font-medium text-base md:text-lg py-4 border-b border-gray-800">
                <span className="icon text-purple-400 mt-1 text-xl"></span>
                <span>What compliance certifications does Exoper have?</span>
              </summary>
              <div className="pb-4 ml-8 text-gray-300 text-sm md:text-base border-b border-gray-800 mt-2">
                <p>Exoper is SOC 2 Type II certified and GDPR compliant. Enterprise plans include HIPAA BAAs and support for EU AI Act compliance requirements. We maintain comprehensive audit trails with cryptographic verification for all AI transactions. Custom compliance frameworks are available for Custom plan customers.</p>
              </div>
            </details>
          </div>

          <p className="text-gray-400 text-sm md:text-base mt-8 text-center md:text-left">
            For more information, <span className="underline cursor-pointer hover:text-white transition-colors">check out the docs</span> or <span className="underline cursor-pointer hover:text-white transition-colors">contact our support team</span>.
          </p>
        </div>
      </div>
    </div>
  );
};

export default FAQs;