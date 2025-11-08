import React from 'react';
import { Link } from 'react-router-dom';
import { Gift, BookOpen, Wrench } from 'lucide-react';

const ResourcesDropdownCard = () => {
  return (
    <div className="bg-[linear-gradient(180deg,#121421_0%,#0f1320_60%)]/95 backdrop-blur-xl p-4 rounded-2xl shadow-[0_6px_30px_rgba(2,6,23,0.6)] border border-[#222631] w-[500px]">
      <div className="grid grid-cols-3 gap-3">
        
        <Link 
          to="/resources/freebies" 
          className="group relative overflow-hidden rounded-xl bg-[#0b0b10]/60 p-4 border border-[#222631] hover:border-[#8b5cf6]/50 transition-all duration-300 cursor-pointer hover:shadow-lg hover:shadow-purple-500/10 flex flex-col items-center text-center"
        >
          <div className="p-2.5 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30 mb-3">
            <Gift className="w-5 h-5 text-purple-400" />
          </div>
          <h3 className="text-white text-sm font-semibold mb-1">Freebies</h3>
          <p className="text-gray-400 text-xs leading-relaxed">Free resources</p>
          <div className="absolute inset-0 bg-gradient-to-tr from-purple-600/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
        </Link>

        <Link 
          to="/resources/articles" 
          className="group relative overflow-hidden rounded-xl bg-[#0b0b10]/60 p-4 border border-[#222631] hover:border-[#8b5cf6]/50 transition-all duration-300 cursor-pointer hover:shadow-lg hover:shadow-purple-500/10 flex flex-col items-center text-center"
        >
          <div className="p-2.5 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30 mb-3">
            <BookOpen className="w-5 h-5 text-purple-400" />
          </div>
          <h3 className="text-white text-sm font-semibold mb-1">Articles</h3>
          <p className="text-gray-400 text-xs leading-relaxed">Insights & tips</p>
          <div className="absolute inset-0 bg-gradient-to-tr from-purple-600/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
        </Link>

        <Link 
          to="/resources/tools" 
          className="group relative overflow-hidden rounded-xl bg-[#0b0b10]/60 p-4 border border-[#222631] hover:border-[#8b5cf6]/50 transition-all duration-300 cursor-pointer hover:shadow-lg hover:shadow-purple-500/10 flex flex-col items-center text-center"
        >
          <div className="p-2.5 bg-gradient-to-r from-[#8b5cf6]/20 to-[#a855f7]/20 rounded-lg border border-[#8b5cf6]/30 mb-3">
            <Wrench className="w-5 h-5 text-purple-400" />
          </div>
          <h3 className="text-white text-sm font-semibold mb-1">Tools</h3>
          <p className="text-gray-400 text-xs leading-relaxed">Dev utilities</p>
          <div className="absolute inset-0 bg-gradient-to-tr from-purple-600/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
        </Link>

      </div>
    </div>
  );
};

export default ResourcesDropdownCard;