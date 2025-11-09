// App.jsx
import { Outlet } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { SmoothCursor } from './components/ui/smooth-cursor';
import Header from './components/header/Header';
import Footer from './components/footer/Footer';
import './styles/global.css';

export default function App() {
  const [isMobile, setIsMobile] = useState(false);
  
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768);
    };
    
    checkMobile();
    window.addEventListener('resize', checkMobile);
    
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  return (
    <div className="min-h-screen bg-background text-foreground">
      {!isMobile && (
        <SmoothCursor 
          color="var(--color-primary)"
          size={12}
          showTrail={true}
          trailLength={5}
          glowEffect={true}
        />
      )}
      <Header />
      <main className="w-full">
        <Outlet />
      </main>
      <Footer />
    </div>
  );
}
