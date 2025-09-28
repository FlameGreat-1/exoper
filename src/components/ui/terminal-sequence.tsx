import { useState, useEffect } from 'react';
import TerminalCard from './terminal-card';

interface TerminalSequenceProps {
  commands: string[];
  cycleTime?: number;
}

const TerminalSequence: React.FC<TerminalSequenceProps> = ({ commands, cycleTime = 12000 }) => {
  const [currentIndex, setCurrentIndex] = useState(0);
  
  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentIndex((prevIndex) => (prevIndex + 1) % commands.length);
    }, cycleTime);
    
    return () => clearInterval(interval);
  }, [commands, cycleTime]);
  
  // Using a key forces a complete re-render of the TerminalCard
  return (
    <div key={currentIndex}>
      <TerminalCard
        command={commands[currentIndex]}
        language="javascript"
        className="shadow-xl dark:shadow-gray-900/30 rounded-xl overflow-hidden"
      />
    </div>
  );
};

export default TerminalSequence;
