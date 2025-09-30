import React, { useEffect, useRef, useState, useCallback } from "react";
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

const LogoComponent = ({ className = "", alt = "Exoper Logo" }) => {
  const [triedPng, setTriedPng] = useState(false);
  const [failed, setFailed] = useState(false);

  const onError = useCallback(
    (e) => {
      if (!triedPng) {
        e.currentTarget.src = "/images/logo.png";
        setTriedPng(true);
        return;
      }
      setFailed(true);
    },
    [triedPng]
  );

  if (failed) {
    return (
      <div className={className} aria-hidden="true">
        <span className="sr-only">{alt}</span>
      </div>
    );
  }

  return (
    <img
      src="/images/logo.svg"
      alt={alt}
      className={`${className} bg-transparent block transform-gpu origin-left`}
      style={{ transformOrigin: "left center" }}
      loading="eager"
      decoding="async"
      onError={onError}
      draggable="false"
      role="img"
      aria-label={alt}
    />
  );
};

const Header = () => {
  const location = useLocation();
  const [isMobile, setIsMobile] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [openDropdown, setOpenDropdown] = useState(null);
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
  }, [location.pathname]);

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") {
        setOpenDropdown(null);
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
          buttonColor="linear-gradient(90deg, #8B5CF6, #3B82F6)"
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
            ? "bg-gray-900/90 backdrop-blur-md shadow-sm py-2"
            : "bg-black/40 backdrop-blur-sm py-3"
        }`}
        aria-label="Primary site header"
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between gap-6">
            <div className="flex items-center gap-3 flex-shrink-0" style={{ minWidth: 0 }}>
              <Link to="/" aria-label="Exoper — Home" className="flex items-center gap-3">
                <LogoComponent className="h-10 sm:h-12 md:h-14 w-auto scale-150" alt="Exoper Logo" />
                <span
                  className="text-white font-extrabold uppercase tracking-widest text-xl sm:text-2xl md:text-3xl bg-clip-text text-transparent"
                  style={{
                    backgroundImage:
                      "linear-gradient(90deg, rgba(255,255,255,1) 0%, rgba(200,200,200,0.9) 50%, rgba(255,255,255,1) 100%)",
                  }}
                >
                  XOPER
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
                  const active =
                    isActive(item.href) ||
                    (hasChildren && item.children.some((c) => isActive(c.href)));
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

            <div className="flex items-center justify-end flex-shrink-0">
              <Link
                to="/start-project"
                className="hidden md:inline-flex items-center px-4 md:px-6 py-2.5 rounded-full text-sm md:text-base font-semibold bg-gradient-to-r from-[#8b3cf0] to-[#ff2dd4] text-white shadow-lg transform-gpu transition-transform duration-200 hover:scale-[1.03] focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#8b3cf0]"
                aria-label="Start a project"
              >
                START A PROJECT
                <span className="ml-3 inline-block transform rotate-0">→</span>
              </Link>
            </div>
          </div>
        </div>
      </header>

      <div className="h-16 md:h-20" />
    </>
  );
};

export default Header;
