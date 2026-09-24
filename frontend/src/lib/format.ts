const ATTO = 10n ** 18n;

/** Format an atto-GEN amount (string or bigint) as GEN with up to 4 decimals. */
export function gen(amount: string | bigint, maxDecimals = 4): string {
  const v = typeof amount === "bigint" ? amount : BigInt(amount || "0");
  const whole = v / ATTO;
  const frac = (v % ATTO).toString().padStart(18, "0").slice(0, maxDecimals).replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : whole.toString();
}

/** Parse a decimal GEN string into atto-GEN; returns null when not a valid amount. */
export function parseGen(input: string): bigint | null {
  const s = input.trim();
  if (!/^\d+(\.\d{0,18})?$/.test(s)) return null;
  const [w, f = ""] = s.split(".");
  return BigInt(w) * ATTO + BigInt(f.padEnd(18, "0"));
}

export const short = (a: string, head = 6, tail = 4) =>
  a && a.length > head + tail + 1 ? `${a.slice(0, head)}…${a.slice(-tail)}` : a;

export const sameAddress = (a?: string | null, b?: string | null) =>
  !!a && !!b && a.toLowerCase() === b.toLowerCase();

/** "3h 04m 09s" style countdown; seconds <= 0 renders "0s". */
export function duration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => n.toString().padStart(2, "0");
  if (d > 0) return `${d}d ${pad(h)}h ${pad(m)}m`;
  if (h > 0) return `${h}h ${pad(m)}m ${pad(sec)}s`;
  if (m > 0) return `${m}m ${pad(sec)}s`;
  return `${sec}s`;
}

export function timestamp(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
