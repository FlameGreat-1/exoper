import React, { useEffect, useRef, useState, useCallback } from "react";
import { Link, useLocation } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { HamburgerMenuOverlay } from "../ui/hamburger-menu-overlay";
import CompanyDropdownCard from "../ui/company/aboutCard";
import PricingDropdownCard from "../ui/company/pricingCard";
import ResourcesDropdownCard from "../ui/company/resourcesCard";
import { ChevronDown } from "lucide-react";

const NAV = [
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
    hasCustomDropdown: true,
    children: [
      { label: "Freebies", href: "/resources/freebies" },
      { label: "Articles", href: "/resources/articles" },
      { label: "Tools", href: "/resources/tools" },
    ],
  },
];

const MOBILE_NAV_ITEMS = [
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
      <header
        ref={headerRef}
        className={`fixed top-0 left-0 w-full z-50 transition-all duration-300 ${
          isScrolled ? "bg-black py-2 shadow-sm" : "bg-black py-3"
        }`}
        aria-label="Primary site header"
      >
        <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between gap-2 lg:gap-4">
            <div className="flex items-center gap-2 lg:gap-3 flex-shrink-0" style={{ minWidth: 0 }}>
              <Link to="/" aria-label="Exoper — Home" className="flex items-center gap-1 lg:gap-1.5">
                <LogoComponent className="h-8 md:h-10 lg:h-12 xl:h-14 w-auto scale-150" alt="Exoper Logo" />
                <span
                  className="text-white font-extrabold uppercase tracking-widest text-lg md:text-xl lg:text-2xl xl:text-3xl bg-clip-text text-transparent whitespace-nowrap"
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
              className="hidden md:flex flex-1 justify-start ml-2 lg:ml-8 min-w-0"
              role="navigation"
              aria-label="Primary"
            >
              <ul className="inline-flex items-center space-x-1 lg:space-x-2 xl:space-x-4 flex-wrap">
                {NAV.map((item, idx) => {
                  const hasChildren = Array.isArray(item.children);
                  const hasCustomDropdown = item.hasCustomDropdown;
                  const active =
                    isActive(item.href) ||
                    (hasChildren && item.children.some((c) => isActive(c.href)));
                  return (
                    <li key={item.label} className="relative group">
                      {hasCustomDropdown ? (
                        <>
                          <button
                            onMouseEnter={() => setOpenDropdown(idx)}
                            onMouseLeave={() => setOpenDropdown(null)}
                            onFocus={() => setOpenDropdown(idx)}
                            onBlur={() => setOpenDropdown(null)}
                            aria-haspopup="true"
                            aria-expanded={openDropdown === idx}
                            className={`flex items-center gap-1 uppercase tracking-widest text-xs lg:text-sm font-semibold transition-colors px-2 lg:px-3 py-2 rounded-md bg-black focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#8b3cf0] whitespace-nowrap ${
                              active
                                ? "text-white"
                                : "text-white hover:text-[#ff2dd4]"
                            }`}
                          >
                            {item.label}
                            <ChevronDown className="w-3 h-3 flex-shrink-0" />
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
                                className="absolute left-0 mt-3 z-50"
                                style={{
                                  left: item.label === "Pricing" || item.label === "Resources" ? "auto" : "0",
                                  right: item.label === "Pricing" || item.label === "Resources" ? "0" : "auto",
                                  maxWidth: "calc(100vw - 2rem)",
                                }}
                              >
                                {item.label === "Company" && <CompanyDropdownCard />}
                                {item.label === "Pricing" && <PricingDropdownCard />}
                                {item.label === "Resources" && <ResourcesDropdownCard />}
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
                            className={`flex items-center gap-1 uppercase tracking-widest text-xs lg:text-sm font-semibold transition-colors px-2 lg:px-3 py-2 rounded-md bg-black focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-[#8b3cf0] whitespace-nowrap ${
                              active
                                ? "text-white"
                                : "text-white hover:text-[#ff2dd4]"
                            }`}
                          >
                            {item.label}
                            <ChevronDown className="w-3 h-3 flex-shrink-0" />
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
                                className="absolute left-1/2 -translate-x-1/2 mt-3 w-56 bg-black rounded-lg shadow-lg ring-1 ring-gray-700 ring-opacity-50 py-2 z-50"
                                style={{
                                  maxWidth: "calc(100vw - 2rem)",
                                }}
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
                          className={`uppercase tracking-widest text-xs lg:text-sm font-semibold px-2 lg:px-3 py-2 rounded-md bg-black transition-colors whitespace-nowrap ${
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

            <div className="hidden md:flex items-center gap-2 lg:gap-3 flex-shrink-0 ml-auto">
              <Link
                to="/signin"
                className="px-2 lg:px-4 py-2 text-xs lg:text-sm font-semibold uppercase tracking-wide bg-black text-white rounded-md hover:bg-gray-900 transition-colors border border-gray-700 whitespace-nowrap"
              >
                Sign In
              </Link>
              <Link
                to="/book-demo"
                className="px-2 lg:px-4 py-2 text-xs lg:text-sm font-semibold uppercase tracking-wide bg-black text-white rounded-md hover:bg-gray-900 transition-colors border border-gray-700 whitespace-nowrap"
              >
                Book Demo
              </Link>
            </div>

            {isMobile && (
              <div className="md:hidden">
                <HamburgerMenuOverlay
                  items={MOBILE_NAV_ITEMS}
                  buttonTop="24px"
                  buttonLeft="calc(100% - 24px)"
                  buttonSize="sm"
                  buttonColor="linear-gradient(90deg, #8B5CF6, #3B82F6, #8B5CF6)"
                  overlayBackground="linear-gradient(180deg,#0b0210 0%, #1f032a 60%)"
                  textColor="#fff"
                  fontSize="md"
                  enableBlur={true}
                  zIndex={1200}
                  currentPath={location.pathname}
                  className="w-10 h-10 relative"
                  menuAlignment="center"
                  staggerDelay={0.05}
                  animationDuration={0.8}
                />
              </div>
            )}
          </div>
        </div>
      </header>

      <div className="h-14 md:h-16 lg:h-20" />
    </>
  );
};

export default Header;