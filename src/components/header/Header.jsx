// components/header/Header.jsx
import React, { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { HamburgerMenuOverlay } from "../ui/hamburger-menu-overlay";

const NAV = [
  { label: "Home", href: "/" },
  {
    label: "About",
    href: "/about",
    children: [
      { label: "Who I am", href: "/about#who" },
      { label: "Process", href: "/about#process" },
      { label: "Testimonials", href: "/about#testimonials" },
    ],
  },
  { label: "Projects", href: "/projects" },
  { label: "Consult Me", href: "/consult" },
  {
    label: "Learn From Me",
    href: "/learn",
    children: [
      { label: "Courses", href: "/learn/courses" },
      { label: "Workshops", href: "/learn/workshops" },
      { label: "Guides", href: "/learn/guides" },
    ],
  },
  {
    label: "Resources",
    href: "/resources",
    children: [
      { label: "Freebies", href: "/resources/freebies" },
      { label: "Articles", href: "/resources/articles" },
      { label: "Tools", href: "/resources/tools" },
    ],
  },
];

const Header = () => {
  const location = useLocation();
  const [isMobile, setIsMobile] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [openDropdown, setOpenDropdown] = useState(null);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const headerRef = useRef(null);

  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth < 768);
    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    const onScroll = () => {
      setIsScrolled(window.scrollY > 16);
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    setOpenDropdown(null);
    setIsMenuOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") {
        setOpenDropdown(null);
        setIsMenuOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const isActive = (href) => {
    if (!href) return false;
    if (href === "/") return location.pathname === "/";
    return location.pathname === href || location.pathname.startsWith(href + "/");
  };

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 z-50 px-3 py-2 bg-primary text-white rounded-md shadow-lg"
      >
        Skip to content
      </a>

      {isMobile && (
        <HamburgerMenuOverlay
          items={NAV}
          buttonTop="18px"
          buttonRight="18px"
          buttonSize="md"
          buttonColor="linear-gradient(90deg,#8b3cf0,#ff44cc)"
          overlayBackground="linear-gradient(180deg,#0b0210 0%, #1f032a 60%)"
          textColor="#fff"
          fontSize="md"
          enableBlur={true}
          zIndex={1200}
          currentPath={location.pathname}
        />
      )}

      <header
        ref={headerRef}
        className={`fixed top-0 left-0 w-full z-50 transition-all duration-300 ${
          isScrolled
            ? "bg-slate-900/90 dark:bg-black/70 backdrop-blur-md shadow-sm py-2"
            : "bg-transparent py-3"
        }`}
        aria-label="Primary site header"
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between gap-6">
            <div className="flex items-center gap-6 flex-shrink-0">
              <Link to="/" aria-label="Flamo — Home" className="flex items-center">
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#ff2dd4] to-[#6b3cff] font-extrabold tracking-tight text-2xl md:text-3xl">
                  Flamo
                </span>
              </Link>
            </div>

            <nav
              className="hidden md:flex flex-1 justify-center"
              role="navigation"
              aria-label="Primary"
            >
              <ul className="inline-flex items-center space-x-6">
                {NAV.map((item, idx) => {
                  const hasChildren = Array.isArray(item.children);
                  const active = isActive(item.href) || (hasChildren && item.children.some((c) => isActive(c.href)));
                  return (
                    <li key={item.label} className="relative group">
                      {hasChildren ? (
                        <>
                          <button
                            onMouseEnter={() => setOpenDropdown(idx)}
                            onMouseLeave={() => setOpenDropdown(null)}
                            onFocus={() => setOpenDropdown(idx)}
                            onBlur={() => setOpenDropdown(null)}
                            aria-haspopup="true"
                            aria-expanded={openDropdown === idx}
                            className={`uppercase tracking-widest text-sm font-semibold transition-colors px-2 py-2 rounded-md focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#8b3cf0] ${
                              active
                                ? "text-[#ff2dd4]"
                                : "text-slate-200 hover:text-[#ff2dd4] dark:text-slate-300"
                            }`}
                          >
                            {item.label}
                          </button>

                          <AnimatePresence>
                            {openDropdown === idx && (
                              <motion.ul
                                initial={{ opacity: 0, y: -6 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -6 }}
                                transition={{ duration: 0.16 }}
                                onMouseEnter={() => setOpenDropdown(idx)}
                                onMouseLeave={() => setOpenDropdown(null)}
                                className="absolute left-1/2 -translate-x-1/2 mt-3 w-56 bg-slate-800/90 backdrop-blur rounded-lg shadow-lg ring-1 ring-black ring-opacity-5 py-2 z-50"
                                role="menu"
                                aria-label={`${item.label} submenu`}
                              >
                                {item.children.map((child) => (
                                  <li key={child.href}>
                                    <Link
                                      to={child.href}
                                      role="menuitem"
                                      className={`block px-4 py-2 text-sm font-medium transition-colors ${
                                        isActive(child.href)
                                          ? "text-white bg-slate-900"
                                          : "text-slate-200 hover:text-white hover:bg-slate-700/40"
                                      }`}
                                    >
                                      {child.label}
                                    </Link>
                                  </li>
                                ))}
                              </motion.ul>
                            )}
                          </AnimatePresence>
                        </>
                      ) : (
                        <Link
                          to={item.href}
                          className={`uppercase tracking-widest text-sm font-semibold px-2 py-2 rounded-md transition-colors ${
                            active
                              ? "text-[#ff2dd4]"
                              : "text-slate-200 hover:text-[#ff2dd4] dark:text-slate-300"
                          }`}
                          aria-current={active ? "page" : undefined}
                        >
                          {item.label}
                        </Link>
                      )}
                    </li>
                  );
                })}
              </ul>
            </nav>

            <div className="flex items-center justify-end flex-shrink-0 space-x-4">
              <Link
                to="/start-project"
                className="hidden md:inline-flex items-center px-4 md:px-6 py-2.5 rounded-full text-sm md:text-base font-semibold bg-gradient-to-r from-[#8b3cf0] to-[#ff2dd4] text-white shadow-lg transform-gpu transition-transform duration-200 hover:scale-[1.03] focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#8b3cf0]"
                aria-label="Start a project"
              >
                START A PROJECT
                <span className="ml-3 inline-block transform rotate-0">→</span>
              </Link>

              <button
                className="md:hidden inline-flex items-center justify-center p-2 rounded-md text-slate-200 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#8b3cf0]"
                aria-label="Open menu"
                onClick={() => setIsMenuOpen((s) => !s)}
              >
                <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" aria-hidden>
                  <path d="M4 6h16M4 12h16M4 18h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="h-16 md:h-20" />

      <AnimatePresence>
        {isMenuOpen && isMobile && (
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className="md:hidden fixed top-16 left-0 right-0 z-40 bg-slate-900/95 backdrop-blur py-4 shadow-lg"
          >
            <div className="px-4">
              <ul className="space-y-2">
                {NAV.map((item) => (
                  <li key={item.label}>
                    <Link
                      to={item.href}
                      onClick={() => setIsMenuOpen(false)}
                      className="block px-3 py-2 rounded-md text-white font-medium"
                    >
                      {item.label}
                    </Link>
                    {item.children && (
                      <ul className="pl-4 mt-1 space-y-1">
                        {item.children.map((c) => (
                          <li key={c.href}>
                            <Link to={c.href} onClick={() => setIsMenuOpen(false)} className="block px-3 py-1 rounded-md text-slate-300 text-sm">
                              {c.label}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
                <li className="pt-2">
                  <Link
                    to="/start-project"
                    onClick={() => setIsMenuOpen(false)}
                    className="block w-full text-center px-4 py-2 rounded-full bg-gradient-to-r from-[#8b3cf0] to-[#ff2dd4] text-white font-semibold"
                  >
                    START A PROJECT
                  </Link>
                </li>
              </ul>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};

export default Header;
