"use client";
import React, { useState, useEffect, useRef } from "react";
import { Menu, X, ChevronDown } from "lucide-react";

export interface MenuItem {
  label: string;
  href?: string;
  onClick?: () => void;
  icon?: React.ReactNode;
  children?: MenuItem[];
}

export interface HamburgerMenuOverlayProps {
  items: MenuItem[];
  buttonTop?: string;
  buttonLeft?: string;
  buttonSize?: "sm" | "md" | "lg";
  buttonColor?: string;
  overlayBackground?: string;
  textColor?: string;
  fontSize?: "sm" | "md" | "lg" | "xl" | "2xl";
  fontFamily?: string;
  fontWeight?: "normal" | "medium" | "semibold" | "bold";
  animationDuration?: number;
  staggerDelay?: number;
  menuAlignment?: "left" | "center" | "right";
  className?: string;
  buttonClassName?: string;
  menuItemClassName?: string;
  keepOpenOnItemClick?: boolean;
  customButton?: React.ReactNode;
  ariaLabel?: string;
  onOpen?: () => void;
  onClose?: () => void;
  menuDirection?: "vertical" | "horizontal";
  enableBlur?: boolean;
  zIndex?: number;
  currentPath?: string;
}

const cn = (...classes: (string | undefined | false)[]) => {
  return classes.filter(Boolean).join(" ");
};

export const HamburgerMenuOverlay: React.FC<HamburgerMenuOverlayProps> = ({
  items = [],
  buttonTop = "60px",
  buttonLeft = "60px",
  buttonSize = "md",
  buttonColor = "#6c8cff",
  overlayBackground = "#6c8cff",
  textColor = "#ffffff",
  fontSize = "md",
  fontFamily = '"Krona One", monospace',
  fontWeight = "bold",
  animationDuration = 1.5,
  staggerDelay = 0.1,
  menuAlignment = "left",
  className,
  buttonClassName,
  menuItemClassName,
  keepOpenOnItemClick = false,
  customButton,
  ariaLabel = "Navigation menu",
  onOpen,
  onClose,
  menuDirection = "vertical",
  enableBlur = false,
  zIndex = 1000,
  currentPath = "",
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [buttonPosition, setButtonPosition] = useState({ x: buttonLeft, y: buttonTop });
  const [expandedItems, setExpandedItems] = useState<{[key: string]: boolean}>({});
  const navRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  const buttonSizes = {
    sm: "w-10 h-10",
    md: "w-12 h-12",
    lg: "w-16 h-16",
  };

  const fontSizes = {
    sm: "text-xl md:text-2xl",
    md: "text-2xl md:text-3xl",
    lg: "text-3xl md:text-4xl",
    xl: "text-4xl md:text-5xl",
    "2xl": "text-5xl md:text-6xl",
  };

  useEffect(() => {
    const updatePosition = () => {
      if (buttonRef.current) {
        const rect = buttonRef.current.getBoundingClientRect();
        setButtonPosition({
          x: `${rect.left + rect.width / 2}px`,
          y: `${rect.top + rect.height / 2}px`,
        });
      }
    };

    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition);

    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition);
    };
  }, []);

  const toggleMenu = () => {
    const newState = !isOpen;
    setIsOpen(newState);

    if (newState) {
      document.body.style.overflow = "hidden";
      onOpen?.();
    } else {
      document.body.style.overflow = "";
      setExpandedItems({});
      onClose?.();
    }
  };

  const toggleDropdown = (label: string) => {
    setExpandedItems(prev => ({
      ...prev,
      [label]: !prev[label]
    }));
  };

  const handleItemClick = (item: MenuItem, hasChildren: boolean) => {
    if (hasChildren) {
      toggleDropdown(item.label);
      return;
    }

    if (item.onClick) {
      item.onClick();
    }

    if (item.href && !item.onClick) {
      window.location.href = item.href;
    }

    if (!keepOpenOnItemClick) {
      setIsOpen(false);
      document.body.style.overflow = "";
      setExpandedItems({});
      onClose?.();
    }
  };

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        setIsOpen(false);
        document.body.style.overflow = "";
        setExpandedItems({});
        onClose?.();
      }
    };

    document.addEventListener("keydown", handleEscape);
    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.style.overflow = "";
    };
  }, [isOpen, onClose]);

  const isActive = (href?: string) => {
    if (!href || !currentPath) return false;
    if (href === "/") return currentPath === "/";
    return currentPath === href || currentPath.startsWith(href + "/");
  };

  return (
    <>
      <style>
        {`
          @import url('https://fonts.googleapis.com/css2?family=Krona+One:wght@400&display=swap');
          
          .hamburger-overlay-${zIndex} {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background: ${overlayBackground};
            z-index: ${zIndex};
            clip-path: circle(0px at ${buttonPosition.x} ${buttonPosition.y});
            transition: clip-path ${animationDuration}s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            ${enableBlur ? "backdrop-filter: blur(10px);" : ""}
            pointer-events: none;
          }
          
          .hamburger-overlay-${zIndex}.open {
            clip-path: circle(150% at ${buttonPosition.x} ${buttonPosition.y});
            pointer-events: auto;
          }
          
          .hamburger-button-${zIndex} {
            position: fixed;
            left: ${buttonLeft};
            top: ${buttonTop};
            transform: translate(-50%, -50%);
            border-radius: 20px;
            z-index: ${zIndex + 1};
            background: ${buttonColor};
            border: none;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
          }
          
          .hamburger-button-${zIndex}:hover {
            transform: translate(-50%, -50%) scale(1.1);
          }
          
          .hamburger-button-${zIndex}:focus {
            outline: 2px solid ${textColor};
            outline-offset: 2px;
          }
          
          .menu-items-${zIndex} {
            width: 100%;
            max-width: 600px;
            padding: 2rem;
            ${menuDirection === "horizontal" ? "display: flex; flex-wrap: wrap; gap: 1rem; justify-content: center;" : ""}
            ${menuAlignment === "center" ? "text-align: center;" : ""}
            ${menuAlignment === "right" ? "text-align: right;" : ""}
          }
          
          .menu-item-${zIndex} {
            position: relative;
            list-style: none;
            padding: 1rem 0;
            cursor: pointer;
            transform: translateX(-200px);
            opacity: 0;
            transition: all 0.3s ease;
            font-family: ${fontFamily};
            font-weight: ${fontWeight};
            color: ${textColor};
            ${menuDirection === "horizontal" ? "display: inline-block; margin: 0 1rem;" : ""}
          }
          
          .menu-item-${zIndex}.visible {
            transform: translateX(0);
            opacity: 1;
          }
          
          .menu-item-${zIndex}.active {
            color: #ff2dd4;
          }
          
          .menu-item-${zIndex}::before {
            content: "";
            position: absolute;
            left: -20%;
            top: 50%;
            transform: translate(-50%, -50%) translateX(-50%);
            width: 25%;
            height: 8px;
            border-radius: 10px;
            background: ${textColor};
            opacity: 0;
            transition: all 0.25s ease;
            pointer-events: none;
          }
          
          .menu-item-${zIndex}:hover::before,
          .menu-item-${zIndex}.active::before {
            opacity: 1;
            transform: translate(-50%, -50%) translateX(0);
          }
          
          .menu-item-${zIndex} .menu-item-content {
            opacity: 0.7;
            transition: opacity 0.25s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
          }
          
          .menu-item-${zIndex}:hover .menu-item-content,
          .menu-item-${zIndex}.active .menu-item-content {
            opacity: 1;
          }
          
          .menu-item-${zIndex}:focus {
            outline: 2px solid ${textColor};
            outline-offset: 2px;
            border-radius: 4px;
          }

          .submenu-${zIndex} {
            max-height: 0;
            overflow: hidden;
            opacity: 0;
            transition: max-height 0.3s ease, opacity 0.3s ease;
            padding-left: 2rem;
          }

          .submenu-${zIndex}.expanded {
            max-height: 500px;
            opacity: 1;
          }

          .submenu-item-${zIndex} {
            padding: 0.75rem 0;
            font-size: 0.9em;
            opacity: 0.8;
            transition: opacity 0.25s ease;
            cursor: pointer;
          }

          .submenu-item-${zIndex}:hover {
            opacity: 1;
          }

          .submenu-item-${zIndex}.active {
            color: #ff2dd4;
            opacity: 1;
          }

          .chevron-icon-${zIndex} {
            transition: transform 0.3s ease;
            display: inline-block;
            margin-left: 0.5rem;
          }

          .chevron-icon-${zIndex}.rotated {
            transform: rotate(180deg);
          }
          
          @media (max-width: 480px) {
            .menu-items-${zIndex} {
              ${menuDirection === "horizontal" ? "flex-direction: column; gap: 0;" : ""}
              padding: 1rem;
            }
            
            .menu-item-${zIndex} {
              ${menuDirection === "horizontal" ? "display: block; margin: 0;" : ""}
              padding: 0.75rem 0;
            }
          }
        `}
      </style>

      <div
        ref={navRef}
        className={cn(`hamburger-overlay-${zIndex}`, isOpen && "open")}
        aria-hidden={!isOpen}
      >
        <ul className={cn(`menu-items-${zIndex}`)}>
          {items.map((item, index) => {
            const hasChildren = Array.isArray(item.children) && item.children.length > 0;
            const isExpanded = expandedItems[item.label];
            const itemActive = isActive(item.href) || (hasChildren && item.children?.some((c) => isActive(c.href)));

            return (
              <li key={index}>
                <div
                  className={cn(
                    `menu-item-${zIndex}`,
                    fontSizes[fontSize],
                    isOpen && "visible",
                    itemActive && "active",
                    menuItemClassName
                  )}
                  style={{
                    transitionDelay: isOpen ? `${index * staggerDelay}s` : "0s",
                  }}
                  onClick={() => handleItemClick(item, hasChildren)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      handleItemClick(item, hasChildren);
                    }
                  }}
                  tabIndex={isOpen ? 0 : -1}
                  role="button"
                  aria-label={hasChildren ? `Toggle ${item.label} submenu` : `Navigate to ${item.label}`}
                  aria-expanded={hasChildren ? isExpanded : undefined}
                >
                  <span className="menu-item-content">
                    {item.icon && <span className="menu-icon">{item.icon}</span>}
                    <span>{item.label}</span>
                    {hasChildren && (
                      <ChevronDown 
                        className={cn(`chevron-icon-${zIndex}`, isExpanded && "rotated")}
                        size={16}
                      />
                    )}
                  </span>
                </div>

                {hasChildren && (
                  <div className={cn(`submenu-${zIndex}`, isExpanded && "expanded")}>
                    {item.children?.map((child, childIndex) => (
                      <div
                        key={childIndex}
                        className={cn(
                          `submenu-item-${zIndex}`,
                          isActive(child.href) && "active"
                        )}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleItemClick(child, false);
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            e.stopPropagation();
                            handleItemClick(child, false);
                          }
                        }}
                        tabIndex={isOpen && isExpanded ? 0 : -1}
                        role="button"
                        aria-label={`Navigate to ${child.label}`}
                      >
                        <span>
                          {child.icon && <span className="menu-icon">{child.icon}</span>}
                          {child.label}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </div>

      <button
        ref={buttonRef}
        className={cn(
          `hamburger-button-${zIndex}`,
          buttonSizes[buttonSize],
          buttonClassName
        )}
        onClick={toggleMenu}
        aria-label={ariaLabel}
        aria-expanded={isOpen}
        aria-controls="navigation-menu"
      >
        {customButton || (
          <div className="relative w-full h-full flex items-center justify-center">
            <Menu
              className={cn(
                "absolute transition-all duration-300",
                isOpen
                  ? "opacity-0 rotate-45 scale-0"
                  : "opacity-100 rotate-0 scale-100"
              )}
              size={buttonSize === "sm" ? 16 : buttonSize === "md" ? 20 : 24}
              color={textColor}
            />
            <X
              className={cn(
                "absolute transition-all duration-300",
                isOpen
                  ? "opacity-100 rotate-0 scale-100"
                  : "opacity-0 -rotate-45 scale-0"
              )}
              size={buttonSize === "sm" ? 16 : buttonSize === "md" ? 20 : 24}
              color={textColor}
            />
          </div>
        )}
      </button>
    </>
  );
};

export default HamburgerMenuOverlay;