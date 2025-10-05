import React, { useEffect, useRef, useState, useCallback } from "react";
import { Link, useLocation } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { HamburgerMenuOverlay } from "../ui/hamburger-menu-overlay";
import CompanyDropdownCard from "../ui/company/aboutCard";
import PricingDropdownCard from "../ui/company/pricingCard";
import { ChevronDown } from "lucide-react";

const NAV = [
  { label: "Home", href: "/" },
  { label: "Services", href: "/services" },
  {
    label: "Company",
    href: "/about",
    hasCustomDropdown: true,
    children: [
      { label: "About", href: "/about" },
      { label: "Senior Full-Stack Engineer, Product", href: "/careers/senior-fullstack-engineer" },
      { label: "Backend Engineer", href: "/careers/backend-engineer" },
      { label: "Senior Product Marketer", href: "/careers/senior-product-marketer" },
    ],
  },
  {
    label: "Pricing",
    href: "/pricing",
    hasCustomDropdown: true,
    children: [
      { label: "Products", href: "/pricing" },
      { label: "AI Development", href: "/services/ai-development" },
      { label: "Cloud Infrastructure", href: "/services/cloud-infrastructure" },
      { label: "Custom Software", href: "/services/custom-software" },
      { label: "Technical Consulting", href: "/services/consulting" },
      { label: "24/7 Support", href: "/services/support" },
    ],
  },
  { label: "Products", href: "/products" },
  { label: "Process", href: "/process" },
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

const MOBILE_NAV_ITEMS = [
  { label: "Home", href: "/" },
  { label: "Services", href: "/services" },
  {
    label: "Company",
    href: "/about",
    children: [
      { label: "About", href: "/about" },
      { label: "Senior Full-Stack Engineer, Product", href: "/careers/senior-fullstack-engineer" },
      { label: "Backend Engineer", href: "/careers/backend-engineer" },
      { label: "Senior Product Marketer", href: "/careers/senior-product-marketer" },
    ],
  },
  {
    label: "Pricing",
    href: "/pricing",
    children: [
      { label: "Products", href: "/pricing" },
      { label: "AI Development", href: "/services/ai-development" },
      { label: "Cloud Infrastructure", href: "/services/cloud-infrastructure" },
      { label: "Custom Software", href: "/services/custom-software" },
      { label: "Technical Consulting", href: "/services/consulting" },
      { label: "24/7 Support", href: "/services/support" },
    ],
  },
  { label: "Products", href: "/products" },
  { label: "Process", href: "/process" },
  {
    label: "Resources",
    href: "/resources",
    children: [
      { label: "Freebies", href: "/resources/freebies" },
      { label: "Articles", href: "/resources/articles" },
      { label: "Tools", href: "/resources/tools" },
    ],
  },
  {
    label: "Sign In",
    href: "/signin",
  },
  {
    label: "Book Demo",
    href: "/book-demo",
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
  const [viewportWidth, setViewportWidth] = useState(0);
  const headerRef = useRef(null);

  useEffect(() => {
    const onResize = () => {
      const width = window.innerWidth;
      setViewportWidth(width);
      setIsMobile(width < 1024);
    };
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

  const getDropdownPosition = (idx, label) => {
    const isNarrowViewport = viewportWidth < 1200;
    const isLastItems = idx >= NAV.length - 2;
    
    if (label === "Pricing" && isNarrowViewport) {
      return "right-0";
    }
    if (label === "Resources" && isNarrowViewport) {
      return "right-0";
    }
    if (isLastItems && isNarrowViewport) {
      return "right-0";
    }
    return "left-0";
  };

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 z-50 px-3 py-2 bg-primary text-white rounded-md shadow-lg"
      >
        Skip to content
      </a>
      <header
        ref={headerRef}
        className={`fixed top-0 left-0 w-full z-50 transition-all duration-300 ${
          isScrolled ? "bg-black py-1.5 shadow-sm" : "bg-black py-2"
        }`}
        aria-label="Primary site header"
      >
        <div className="w-full px-2 sm:px-4 lg:px-6 xl:px-8">
          <div className="flex items-center justify-between gap-2 min-w-0">
            <div className="flex items-center gap-2 flex-shrink-0" style={{ minWidth: 0 }}>
              <Link to="/" aria-label="Exoper — Home" className="flex items-center gap-1">
                <LogoComponent 
                  className={`${viewportWidth < 1200 ? 'h-8 w-auto scale-125' : 'h-10 sm:h-12 md:h-14 w-auto scale-150'}`} 
                  alt="Exoper Logo" 
                />
                <span
                  className={`text-white font-extrabold uppercase tracking-widest bg-clip-text text-transparent whitespace-nowrap ${
                    viewportWidth < 1200 ? 'text-lg' : 'text-xl sm:text-2xl md:text-3xl'
                  }`}
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
              className="hidden lg:flex flex-1 justify-center mx-2"
              role="navigation"
              aria-label="Primary"
            >
              <ul className="inline-flex items-center space-x-1 xl:space-x-2">
                {NAV.map((item, idx) => {
                  const hasChildren = Array.isArray(item.children);
                  const hasCustomDropdown = item.hasCustomDropdown;
                  const active =
                    isActive(item.href) ||
                    (hasChildren && item.children.some((c) => isActive(c.href)));
                  return (
                    <li key={item.label} className="relative group flex-shrink-0">
                      {hasCustomDropdown ? (
                        <>
                          <button
                            onMouseEnter={() => setOpenDropdown(idx)}
                            onMouseLeave={() => setOpenDropdown(null)}
                            onFocus={() => setOpenDropdown(idx)}
                            onBlur={() => setOpenDropdown(null)}
                            aria-haspopup="true"
                            aria-expanded={openDropdown === idx}
                            className={`flex items-center gap-1 uppercase tracking-widest font-semibold transition-colors rounded-md bg-black focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#8b3cf0] whitespace-nowrap ${
                              viewportWidth < 1200 ? 'text-xs px-2 py-1.5' : 'text-sm px-3 py-2'
                            } ${
                              active
                                ? "text-white"
                                : "text-white hover:text-[#ff2dd4]"
                            }`}
                          >
                            {item.label}
                            <ChevronDown className={viewportWidth < 1200 ? "w-2.5 h-2.5" : "w-3 h-3"} />
                          </button>

                          <AnimatePresence>
                            {openDropdown === idx && (
                              <motion.div
                                initial={{ opacity: 0, y: -6 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -6 }}
                                transition={{ duration: 0.16 }}
                                onMouseEnter={() => setOpenDropdown(idx)}
                                onMouseLeave={() => setOpenDropdown(null)}
                                className={`absolute mt-2 z-50 ${getDropdownPosition(idx, item.label)}`}
                                style={{
                                  transform: viewportWidth < 1200 && getDropdownPosition(idx, item.label) === "right-0" 
                                    ? "translateX(-10px)" 
                                    : "none"
                                }}
                              >
                                {item.label === "Company" && <CompanyDropdownCard />}
                                {item.label === "Pricing" && <PricingDropdownCard />}
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </>
                      ) : hasChildren ? (
                        <>
                          <button
                            onMouseEnter={() => setOpenDropdown(idx)}
                            onMouseLeave={() => setOpenDropdown(null)}
                            onFocus={() => setOpenDropdown(idx)}
                            onBlur={() => setOpenDropdown(null)}
                            aria-haspopup="true"
                            aria-expanded={openDropdown === idx}
                            className={`flex items-center gap-1 uppercase tracking-widest font-semibold transition-colors rounded-md bg-black focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#8b3cf0] whitespace-nowrap ${
                              viewportWidth < 1200 ? 'text-xs px-2 py-1.5' : 'text-sm px-3 py-2'
                            } ${
                              active
                                ? "text-white"
                                : "text-white hover:text-[#ff2dd4]"
                            }`}
                          >
                            {item.label}
                            <ChevronDown className={viewportWidth < 1200 ? "w-2.5 h-2.5" : "w-3 h-3"} />
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
                                className={`absolute mt-2 bg-black rounded-lg shadow-lg ring-1 ring-gray-700 ring-opacity-50 py-2 z-50 ${getDropdownPosition(idx, item.label)} ${
                                  viewportWidth < 1200 ? 'w-48' : 'w-56'
                                }`}
                                role="menu"
                                aria-label={`${item.label} submenu`}
                                style={{
                                  transform: viewportWidth < 1200 && getDropdownPosition(idx, item.label) === "right-0" 
                                    ? "translateX(-10px)" 
                                    : getDropdownPosition(idx, item.label) === "left-0" 
                                    ? "translateX(-50%)" 
                                    : "none",
                                  left: getDropdownPosition(idx, item.label) === "left-0" ? "50%" : "auto"
                                }}
                              >
                                {item.children.map((child) => (
                                  <li key={child.href}>
                                    <Link
                                      to={child.href}
                                      role="menuitem"
                                      className={`block px-4 py-2 font-medium transition-colors ${
                                        viewportWidth < 1200 ? 'text-xs' : 'text-sm'
                                      } ${
                                        isActive(child.href)
                                          ? "text-white bg-gray-900"
                                          : "text-white hover:text-[#ff2dd4] hover:bg-gray-800"
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
                          className={`uppercase tracking-widest font-semibold rounded-md bg-black transition-colors whitespace-nowrap ${
                            viewportWidth < 1200 ? 'text-xs px-2 py-1.5' : 'text-sm px-3 py-2'
                          } ${
                            active
                              ? "text-white"
                              : "text-white hover:text-[#ff2dd4]"
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

            <div className="hidden lg:flex items-center gap-1.5 xl:gap-3 flex-shrink-0">
              <Link
                to="/signin"
                className={`font-semibold uppercase tracking-wide bg-black text-white rounded-md hover:bg-gray-900 transition-colors border border-gray-700 whitespace-nowrap ${
                  viewportWidth < 1200 ? 'px-2.5 py-1.5 text-xs' : 'px-4 py-2 text-sm'
                }`}
              >
                Sign In
              </Link>
              <Link
                to="/book-demo"
                className={`font-semibold uppercase tracking-wide bg-black text-white rounded-md hover:bg-gray-900 transition-colors border border-gray-700 whitespace-nowrap ${
                  viewportWidth < 1200 ? 'px-2.5 py-1.5 text-xs' : 'px-4 py-2 text-sm'
                }`}
              >
                Book Demo
              </Link>
            </div>

            {isMobile && (
              <div className="lg:hidden">
                <HamburgerMenuOverlay
                  items={MOBILE_NAV_ITEMS}
                  buttonTop="30px"
                  buttonLeft="calc(100% - 30px)"
                  buttonSize="md"
                  buttonColor="linear-gradient(90deg, #8B5CF6, #3B82F6, #8B5CF6)"
                  overlayBackground="linear-gradient(180deg,#0b0210 0%, #1f032a 60%)"
                  textColor="#fff"
                  fontSize="md"
                  enableBlur={true}
                  zIndex={1200}
                  currentPath={location.pathname}
                  className="w-12 h-12 relative"
                  menuAlignment="center"
                  staggerDelay={0.05}
                  animationDuration={0.8}
                />
              </div>
            )}
          </div>
        </div>
      </header>

      <div className="h-14 lg:h-16 xl:h-20" />
    </>
  );
};

export default Header;

