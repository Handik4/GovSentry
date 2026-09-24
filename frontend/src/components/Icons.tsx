import type { ReactNode, SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Icon({ size = 20, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconShield = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 3l7 3v5.5c0 4.4-3 8.2-7 9.5-4-1.3-7-5.1-7-9.5V6l7-3z" />
    <path d="M9 12l2 2 4-4" />
  </Icon>
);
export const IconBytes = (p: IconProps) => (
  <Icon {...p}>
    <path d="M8 6l-5 6 5 6M16 6l5 6-5 6" />
    <path d="M13.5 4l-3 16" />
  </Icon>
);
export const IconScale = (p: IconProps) => (
  <Icon {...p}>
    <path d="M12 4v16M7 20h10M5 8h14" />
    <path d="M5 8l-3 6a3 3 0 006 0L5 8zM19 8l-3 6a3 3 0 006 0l-3-6z" />
  </Icon>
);
export const IconNodes = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="5" r="2.2" />
    <circle cx="5" cy="18" r="2.2" />
    <circle cx="19" cy="18" r="2.2" />
    <path d="M10.9 6.9L6.1 16M13.1 6.9l4.8 9.1M7.2 18h9.6" />
  </Icon>
);
export const IconLock = (p: IconProps) => (
  <Icon {...p}>
    <rect x="4.5" y="10.5" width="15" height="10" rx="2.2" />
    <path d="M8 10.5V7.5a4 4 0 018 0v3" />
    <path d="M12 14.5v2.5" />
  </Icon>
);
export const IconTarget = (p: IconProps) => (
  <Icon {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <circle cx="12" cy="12" r="4.5" />
    <circle cx="12" cy="12" r="1" fill="currentColor" />
  </Icon>
);
export const IconVault = (p: IconProps) => (
  <Icon {...p}>
    <rect x="3.5" y="4.5" width="17" height="15" rx="2.5" />
    <circle cx="12" cy="12" r="3.5" />
    <path d="M12 8.5V7M12 17v-1.5M15.5 12H17M7 12h1.5" />
  </Icon>
);
export const IconPulse = (p: IconProps) => (
  <Icon {...p}>
    <path d="M3 12h4l2.5-6 4 12 2.5-6H21" />
  </Icon>
);
export const IconCopy = (p: IconProps) => (
  <Icon {...p}>
    <rect x="8.5" y="8.5" width="11" height="11" rx="2" />
    <path d="M15.5 8.5V6a1.5 1.5 0 00-1.5-1.5H6A1.5 1.5 0 004.5 6v8A1.5 1.5 0 006 15.5h2.5" />
  </Icon>
);
export const IconCheck = (p: IconProps) => (
  <Icon {...p}>
    <path d="M5 12.5l4.5 4.5L19 7.5" />
  </Icon>
);
export const IconExternal = (p: IconProps) => (
  <Icon {...p}>
    <path d="M14 4.5h5.5V10M19.5 4.5L11 13" />
    <path d="M17.5 13.5v4a2 2 0 01-2 2h-9a2 2 0 01-2-2v-9a2 2 0 012-2h4" />
  </Icon>
);
export const IconClose = (p: IconProps) => (
  <Icon {...p}>
    <path d="M6 6l12 12M18 6L6 18" />
  </Icon>
);
export const IconMenu = (p: IconProps) => (
  <Icon {...p}>
    <path d="M4 7h16M4 12h16M4 17h16" />
  </Icon>
);
export const IconGithub = ({ size = 18, ...rest }: IconProps) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden {...rest}>
    <path d="M12 2a10 10 0 00-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.46-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.61.07-.61 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.64 0 0 .84-.27 2.75 1.02a9.56 9.56 0 015 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.37.2 2.39.1 2.64.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0012 2z" />
  </svg>
);

/** Illuminated radar-in-shield mark. The sweep rotates unless motion is reduced. */
export function LogoMark({ size = 38 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" aria-hidden className="shrink-0 drop-shadow-[0_0_14px_rgba(56,189,248,0.55)]">
      <defs>
        <linearGradient id="gs-shield" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#7dd3fc" />
          <stop offset="1" stopColor="#0369a1" />
        </linearGradient>
        <linearGradient id="gs-face" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#0c1f3d" />
          <stop offset="1" stopColor="#050a16" />
        </linearGradient>
        <radialGradient id="gs-sweep" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0" stopColor="#22d3ee" stopOpacity="0.9" />
          <stop offset="1" stopColor="#22d3ee" stopOpacity="0" />
        </radialGradient>
        <clipPath id="gs-clip">
          <path d="M24 7.5l13 5.2v9.6c0 8.1-5.4 15-13 17.7-7.6-2.7-13-9.6-13-17.7v-9.6l13-5.2z" />
        </clipPath>
      </defs>
      <path d="M24 3l17 6.8v12.5c0 10.4-7 19.4-17 22.7C14 41.7 7 32.7 7 22.3V9.8L24 3z" fill="url(#gs-shield)" />
      <path d="M24 7.5l13 5.2v9.6c0 8.1-5.4 15-13 17.7-7.6-2.7-13-9.6-13-17.7v-9.6l13-5.2z" fill="url(#gs-face)" />
      <g clipPath="url(#gs-clip)">
        <circle cx="24" cy="23" r="12" fill="none" stroke="#38bdf8" strokeOpacity="0.35" />
        <circle cx="24" cy="23" r="7" fill="none" stroke="#38bdf8" strokeOpacity="0.45" />
        <g className="radar-sweep" style={{ transformOrigin: "24px 23px" }}>
          <path d="M24 23L24 9A14 14 0 0 1 36.1 16z" fill="url(#gs-sweep)" />
        </g>
        <circle cx="30.5" cy="17.5" r="1.8" fill="#fb4f6a" />
        <circle cx="24" cy="23" r="1.6" fill="#e0f2fe" />
      </g>
    </svg>
  );
}
