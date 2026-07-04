/**
 * Inline SVG icons (Lucide-style outline, 1.5px stroke, 24x24 viewBox).
 *
 * Why hand-written, not emoji: emoji rasterize differently per OS,
 * carry colors we cannot control, and fight the single-accent
 * design discipline. These icons inherit ``currentColor`` so the
 * design tokens drive every glyph.
 *
 * Why hand-written, not lucide-react package: zero dependency cost
 * for ~10 glyphs. Adopt the package if the count exceeds 30.
 */
import type { SVGProps } from "react";

type Props = SVGProps<SVGSVGElement> & { size?: number };

/* All icons in this module are decorative — they sit next to a
 * text label that already names the action ("Approve", "Send",
 * "New mission"). Therefore the SVGs MUST be hidden from assistive
 * tech (audit fix 2026-06-10, finding L2 + C2 a11y batch). The
 * focus stays on the surrounding <button>'s text or aria-label.
 *
 * If a caller needs a non-decorative icon (icon-only button with
 * no text), they should pass aria-hidden={false} AND wrap the use
 * site with an aria-label on the parent button.
 */
function Svg({ size = 18, children, ...rest }: Props & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconInbox = (p: Props) => (
  <Svg {...p}>
    <path d="M22 12h-6l-2 3h-4l-2-3H2" />
    <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
  </Svg>
);

export const IconTarget = (p: Props) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="10" />
    <circle cx="12" cy="12" r="6" />
    <circle cx="12" cy="12" r="2" />
  </Svg>
);

export const IconBriefcase = (p: Props) => (
  <Svg {...p}>
    <rect x="2" y="7" width="20" height="14" rx="2" />
    <path d="M8 7V5a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    <path d="M2 13h20" />
  </Svg>
);

export const IconScroll = (p: Props) => (
  <Svg {...p}>
    <path d="M19 17V5a2 2 0 0 0-2-2H4" />
    <path d="M22 17a3 3 0 0 1-3 3H5a3 3 0 0 1-3-3" />
    <path d="M5 17H2v-2a2 2 0 0 1 2-2h15" />
  </Svg>
);

export const IconScale = (p: Props) => (
  <Svg {...p}>
    <path d="M16 16h6l-3-9-3 9z" />
    <path d="M2 16h6l-3-9-3 9z" />
    <path d="M7 21h10" />
    <path d="M12 3v18" />
    <path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2" />
  </Svg>
);

export const IconStar = (p: Props) => (
  <Svg {...p}>
    <path d="M12 3l2.9 5.9 6.5.9-4.7 4.6 1.1 6.5L12 18.8 6.2 21.9l1.1-6.5L2.6 9.8l6.5-.9L12 3z" />
  </Svg>
);

export const IconKey = (p: Props) => (
  <Svg {...p}>
    <circle cx="8" cy="15" r="4" />
    <path d="m10.85 12.15 7.32-7.32" />
    <path d="M18 8l4-4" />
    <path d="m20 6 2-2" />
  </Svg>
);

export const IconChat = (p: Props) => (
  <Svg {...p}>
    <path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z" />
  </Svg>
);

export const IconCheck = (p: Props) => (
  <Svg {...p}><polyline points="20 6 9 17 4 12" /></Svg>
);

export const IconHash = (p: Props) => (
  <Svg {...p}>
    <line x1="4" y1="9" x2="20" y2="9" />
    <line x1="4" y1="15" x2="20" y2="15" />
    <line x1="10" y1="3" x2="8" y2="21" />
    <line x1="16" y1="3" x2="14" y2="21" />
  </Svg>
);

export const IconX = (p: Props) => (
  <Svg {...p}>
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </Svg>
);

export const IconClock = (p: Props) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="10" />
    <polyline points="12 6 12 12 16 14" />
  </Svg>
);

export const IconBraces = (p: Props) => (
  <Svg {...p}>
    <path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5c0 1.1.9 2 2 2h1" />
    <path d="M16 21h1a2 2 0 0 0 2-2v-5c0-1.1.9-2 2-2a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1" />
  </Svg>
);

export const IconCopy = (p: Props) => (
  <Svg {...p}>
    <rect x="9" y="9" width="13" height="13" rx="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </Svg>
);

export const IconSearch = (p: Props) => (
  <Svg {...p}>
    <circle cx="11" cy="11" r="8" />
    <line x1="21" y1="21" x2="16.65" y2="16.65" />
  </Svg>
);

// Layout / Kanban board — Blackboard primary view
export const IconLayout = (p: Props) => (
  <Svg {...p}>
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <line x1="3" y1="9" x2="21" y2="9" />
    <line x1="9" y1="21" x2="9" y2="9" />
  </Svg>
);

// Sliders — Rules / policy authoring
export const IconSliders = (p: Props) => (
  <Svg {...p}>
    <line x1="4" y1="21" x2="4" y2="14" />
    <line x1="4" y1="10" x2="4" y2="3" />
    <line x1="12" y1="21" x2="12" y2="12" />
    <line x1="12" y1="8" x2="12" y2="3" />
    <line x1="20" y1="21" x2="20" y2="16" />
    <line x1="20" y1="12" x2="20" y2="3" />
    <line x1="1" y1="14" x2="7" y2="14" />
    <line x1="9" y1="8" x2="15" y2="8" />
    <line x1="17" y1="16" x2="23" y2="16" />
  </Svg>
);

// Zap — auto-execute / fire indicator on Blackboard cards
export const IconZap = (p: Props) => (
  <Svg {...p}>
    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
  </Svg>
);

// Users — Agent directory (helpers + contacts + LAN peers)
export const IconUsers = (p: Props) => (
  <Svg {...p}>
    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
    <circle cx="9" cy="7" r="4" />
    <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
    <path d="M16 3.13a4 4 0 0 1 0 7.75" />
  </Svg>
);

// UserPlus — "Add agent" affordance
export const IconUserPlus = (p: Props) => (
  <Svg {...p}>
    <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
    <circle cx="8.5" cy="7" r="4" />
    <line x1="20" y1="8" x2="20" y2="14" />
    <line x1="23" y1="11" x2="17" y2="11" />
  </Svg>
);

// Send — chat composer
export const IconSend = (p: Props) => (
  <Svg {...p}>
    <line x1="22" y1="2" x2="11" y2="13" />
    <polygon points="22 2 15 22 11 13 2 9 22 2" />
  </Svg>
);

// Wifi — LAN discovery indicator
export const IconWifi = (p: Props) => (
  <Svg {...p}>
    <path d="M5 12.55a11 11 0 0 1 14.08 0" />
    <path d="M1.42 9a16 16 0 0 1 21.16 0" />
    <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
    <line x1="12" y1="20" x2="12.01" y2="20" />
  </Svg>
);

// Plus — "create / add new" affordance. Used by the Blackboard
// "New process" and MissionList "New mission" entry buttons added
// per user audit 2026-06-10 ("需要有添加/发起任务功能").
export const IconPlus = (p: Props) => (
  <Svg {...p}>
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  </Svg>
);
