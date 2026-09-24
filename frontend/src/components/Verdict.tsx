import { VERDICT_GLYPH, VERDICT_LABEL } from "../lib/copy";
import type { Classification } from "../lib/types";
import { VERDICT_BADGE, VERDICT_HALO } from "../lib/verdictStyle";

export function VerdictBadge({
  verdict,
  size = "sm",
  live = false,
}: {
  verdict: Classification;
  size?: "sm" | "md";
  live?: boolean;
}) {
  return (
    <span
      style={VERDICT_HALO[verdict]}
      className={`inline-flex items-center gap-1.5 rounded-full border font-semibold ${VERDICT_BADGE[verdict]} ${
        live ? "halo" : ""
      } ${size === "md" ? "px-3 py-1 text-sm" : "px-2.5 py-0.5 text-xs"}`}
    >
      <span aria-hidden className="font-display text-[1.15em] leading-none">
        {VERDICT_GLYPH[verdict]}
      </span>
      {VERDICT_LABEL[verdict]}
    </span>
  );
}
