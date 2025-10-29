"use client";

import React, { useEffect, useState, useRef } from "react";
import { Copy, Terminal, Check } from "lucide-react";
import { cn } from "../../lib/utils/utils";
import { motion } from "framer-motion";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/cjs/styles/prism";

type TerminalCardProps = {
  command: string;
  commands?: string[];
  language?: string;
  className?: string;
  cycleTime?: number;
};

const TerminalCard: React.FC<TerminalCardProps> = ({ 
  command = "", 
  commands = [], 
  language = "tsx", 
  className,
  cycleTime = 12000
}) => {
  const [copied, setCopied] = useState(false);
  const [displayedText, setDisplayedText] = useState("");
  const [index, setIndex] = useState(0);
  const [isComplete, setIsComplete] = useState(false);
  const [commandIndex, setCommandIndex] = useState(0);
  
  const allCommands = commands.length > 0 ? commands : [command];
  const currentCommand = allCommands[commandIndex];
  const previousCommandRef = useRef(currentCommand);

  useEffect(() => {
    if (currentCommand !== previousCommandRef.current) {
      setDisplayedText("");
      setIndex(0);
      setIsComplete(false);
      previousCommandRef.current = currentCommand;
    }
  }, [currentCommand]);

  useEffect(() => {
    let timeout: NodeJS.Timeout;

    if (index < currentCommand.length) {
      timeout = setTimeout(() => {
        setDisplayedText((prev) => prev + currentCommand.charAt(index));
        setIndex((prev) => prev + 1);
      }, 40);
    } else {
      setIsComplete(true);
      
      if (allCommands.length > 1) {
        timeout = setTimeout(() => {
          const nextIndex = (commandIndex + 1) % allCommands.length;
          
          setDisplayedText("");
          setIndex(0);
          setIsComplete(false);
          
          setCommandIndex(nextIndex);
        }, 4000);
      } else {
        timeout = setTimeout(() => {
          setDisplayedText("");
          setIndex(0);
          setIsComplete(false);
        }, 2000);
      }
    }

    return () => clearTimeout(timeout);
  }, [index, currentCommand, allCommands.length, commandIndex]);

  const handleCopy = () => {
    navigator.clipboard.writeText(currentCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  // Function to apply VS Code-like syntax coloring to typing text
  const colorizeText = (text: string) => {
    // VS Code color scheme
    const colors = {
      comment: '#6A9955',      // Green for comments
      keyword: '#569CD6',       // Blue for keywords
      string: '#CE9178',        // Orange for strings
      function: '#DCDCAA',      // Yellow for functions
      variable: '#9CDCFE',      // Light blue for variables
      property: '#9CDCFE',      // Light blue for properties
      number: '#B5CEA8',        // Light green for numbers
    };

    // Split by lines to preserve structure
    const lines = text.split('\n');
    
    return lines.map((line, lineIndex) => {
      // Comment lines
      if (line.trim().startsWith('//')) {
        return <div key={lineIndex} style={{ color: colors.comment }}>{line}</div>;
      }
      
      // Process the line for syntax highlighting
      let processedLine = line;
      const segments: React.ReactNode[] = [];
      let lastIndex = 0;
      
      // Keywords
      const keywords = ['const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while'];
      keywords.forEach(keyword => {
        const regex = new RegExp(`\\b${keyword}\\b`, 'g');
        let match;
        while ((match = regex.exec(line)) !== null) {
          if (match.index > lastIndex) {
            segments.push(line.substring(lastIndex, match.index));
          }
          segments.push(<span key={`${lineIndex}-${match.index}`} style={{ color: colors.keyword }}>{match[0]}</span>);
          lastIndex = match.index + match[0].length;
        }
      });
      
      // Strings
      const stringRegex = /"[^"]*"|'[^']*'/g;
      let stringMatch;
      while ((stringMatch = stringRegex.exec(line)) !== null) {
        if (stringMatch.index > lastIndex) {
          segments.push(line.substring(lastIndex, stringMatch.index));
        }
        segments.push(<span key={`str-${lineIndex}-${stringMatch.index}`} style={{ color: colors.string }}>{stringMatch[0]}</span>);
        lastIndex = stringMatch.index + stringMatch[0].length;
      }
      
      // Function calls (word followed by parenthesis)
      const functionRegex = /\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g;
      let funcMatch;
      while ((funcMatch = functionRegex.exec(line)) !== null) {
        if (funcMatch.index > lastIndex) {
          segments.push(line.substring(lastIndex, funcMatch.index));
        }
        segments.push(<span key={`func-${lineIndex}-${funcMatch.index}`} style={{ color: colors.function }}>{funcMatch[1]}</span>);
        segments.push('(');
        lastIndex = funcMatch.index + funcMatch[0].length;
      }
      
      if (lastIndex < line.length) {
        segments.push(line.substring(lastIndex));
      }
      
      return <div key={lineIndex}>{segments.length > 0 ? segments : line}</div>;
    });
  };

  return (
    <div
      className={cn(
        "border rounded-lg backdrop-blur-md min-w-[300px] max-w-full",
        "bg-white/70 border-gray-300 text-black",
        "dark:bg-white/10 dark:border-gray-400/30 dark:text-white",
        className
      )}
    >
      <div className="flex items-center justify-between px-3 py-2 bg-gray-100 dark:bg-[#202425] rounded-t-lg text-sm font-semibold text-gray-700 dark:text-gray-400">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-blue-500" />
          Terminal
        </div>
        <button
          className="p-1 border rounded transition hover:border-gray-600 dark:hover:border-white text-gray-600 dark:text-gray-400 hover:text-black dark:hover:text-white"
          onClick={handleCopy}
          aria-label="Copy to clipboard"
        >
          {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>

      <div className="rounded-b-lg text-sm font-mono p-3 bg-black text-white dark:bg-black overflow-hidden">
        {isComplete ? (
          <SyntaxHighlighter
            language={language}
            style={oneDark}
            customStyle={{ 
              background: "transparent", 
              margin: 0, 
              padding: 0,
              overflow: "hidden"
            }}
            wrapLines={true}
            wrapLongLines={true}
          >
            {currentCommand}
          </SyntaxHighlighter>
        ) : (
          <motion.pre className="whitespace-pre-wrap" style={{ color: '#D4D4D4' }}>
            {colorizeText(displayedText)}
            <motion.span
              className="inline-block w-1 bg-white ml-1"
              animate={{ opacity: [0, 1] }}
              transition={{ duration: 0.6, repeat: Infinity }}
            />
          </motion.pre>
        )}
      </div>
    </div>
  );
};

export default TerminalCard;