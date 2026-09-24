import type { CSSProperties } from "react";
import type { Classification, IncidentStatus } from "./types";

export const VERDICT_TEXT: Record<Classification, string> = {
  ALIGNED: "text-aligned",
  SUSPICIOUS_OMISSION: "text-suspicious",
  CRITICAL_MALICIOUS_PAYLOAD: "text-critical",
};

export const VERDICT_BADGE: Record<Classification, string> = {
  ALIGNED: "border-emerald-400/40 bg-gradient-to-r from-emerald-400/15 to-sky-400/10 text-aligned",
  SUSPICIOUS_OMISSION: "border-orange-400/50 bg-orange-400/15 text-suspicious",
  CRITICAL_MALICIOUS_PAYLOAD: "border-rose-400/50 bg-gradient-to-r from-rose-500/20 to-amber-400/15 text-critical",
};

/** Ring color for the pulsing halo, fed to the `halo` keyframes via --halo. */
export const VERDICT_HALO: Record<Classification, CSSProperties> = {
  ALIGNED: { ["--halo" as string]: "rgb(52 211 153 / 0.45)" },
  SUSPICIOUS_OMISSION: { ["--halo" as string]: "rgb(251 146 60 / 0.5)" },
  CRITICAL_MALICIOUS_PAYLOAD: { ["--halo" as string]: "rgb(251 79 106 / 0.55)" },
};

export const VERDICT_GLOW: Record<Classification, string> = {
  ALIGNED: "drop-shadow-[0_0_14px_rgba(52,211,153,0.55)]",
  SUSPICIOUS_OMISSION: "drop-shadow-[0_0_14px_rgba(251,146,60,0.55)]",
  CRITICAL_MALICIOUS_PAYLOAD: "drop-shadow-[0_0_16px_rgba(251,79,106,0.65)]",
};

const LIVE: IncidentStatus[] = ["PENDING_CHALLENGE", "APPEALED", "CONFIRMED", "DISMISSED", "INCONCLUSIVE"];
export const isLive = (s: IncidentStatus) => LIVE.includes(s);
