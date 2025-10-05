import React from 'react';
import { motion } from 'framer-motion';

interface CompaniesProps {
  className?: string;
}

const Companies: React.FC<CompaniesProps> = ({ className = '' }) => {
  const companies = [
    { name: '2robots', logo: '/images/companies/2robots.png', size: 'normal' },
    { name: 'Arcol', logo: '/images/companies/arcol.png', size: 'normal' },
    { name: 'Chatbase', logo: '/images/companies/chatbase.png', size: 'normal' },
    { name: 'CivitAI', logo: '/images/companies/civitAI.png', size: 'normal' },
    { name: 'Clust', logo: '/images/companies/clust.png', size: 'small' },
    { name: 'Cognition', logo: '/images/companies/cognition.png', size: 'normal' },
    { name: 'Cursor', logo: '/images/companies/cursor.png', size: 'normal' },
    { name: 'Dua', logo: '/images/companies/dua.png', size: 'small' },
    { name: 'Magic', logo: '/images/companies/magic.png', size: 'normal' },
    { name: 'Mendable', logo: '/images/companies/mendable.png', size: 'normal' },
    { name: 'OpenAI', logo: '/images/companies/openAI.png', size: 'normal' },
    { name: 'Paloma', logo: '/images/companies/paloma.png', size: 'normal' },
    { name: 'Peerlist', logo: '/images/companies/peerlist.png', size: 'normal' },
    { name: 'Perplexity', logo: '/images/companies/perplexity.png', size: 'normal' },
    { name: 'Replit', logo: '/images/companies/replit.png', size: 'normal' },
    { name: 'Resend', logo: '/images/companies/resend.png', size: 'normal' },
    { name: 'Rox', logo: '/images/companies/rox.png', size: 'small' },
    { name: 'ShipAid', logo: '/images/companies/shipaid.png', size: 'normal' },
    { name: 'Zillow', logo: '/images/companies/zillow.png', size: 'normal' },
  ];

  const allItems = [...companies, ...companies];
  
  return (
    <div className={`w-full overflow-hidden py-8 ${className}`}>
      <div className="relative">
        <motion.div 
          className="flex space-x-20"
          animate={{ x: [0, -50 * companies.length] }}
          transition={{ 
            repeat: Infinity, 
            duration: 30,
            ease: "linear"
          }}
        >
          {allItems.map((company, index) => (
            <div key={`${company.name}-${index}`} className="flex-none flex items-center justify-center">
              <div 
                className={`flex items-center justify-center transform transition-transform hover:scale-110 duration-300 ${
                  company.size === 'small' ? 'w-12 h-12' : 'w-24 h-24'
                }`}
              >
                <img 
                  src={company.logo} 
                  alt={company.name}
                  className="w-full h-full object-contain"
                />
              </div>
            </div>
          ))}
        </motion.div>
      </div>
    </div>
  );
};

export default Companies;