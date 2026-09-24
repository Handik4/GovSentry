import { explorerAddress } from "../config";
import { gen, short } from "../lib/format";
import type { Dao, Incident } from "../lib/types";
import { IconExternal, IconShield } from "./Icons";

const OPEN = new Set(["PENDING_CHALLENGE", "APPEALED", "CONFIRMED"]);

function selectorCount(schema: string): number {
  try {
    return Object.keys(JSON.parse(schema) as object).length;
  } catch {
    return 0;
  }
}

export function DaoDirectory({ daos, incidents, loading }: { daos: Dao[]; incidents: Incident[]; loading: boolean }) {
  return (
    <section aria-labelledby="daos-title">
      <div className="mb-4 flex flex-wrap items-end justify-between gap-2">
        <div>
          <p className="eyebrow text-sky">Directory</p>
          <h2 id="daos-title" className="font-display text-2xl font-bold tracking-tight">
            Watched DAOs
          </h2>
        </div>
        <span className="eyebrow">{daos.length} registered</span>
      </div>
      {loading && daos.length === 0 ? (
        <p className="glass-card p-4 text-sm text-muted">Reading the registry…</p>
      ) : daos.length === 0 ? (
        <p className="glass-card border-dashed p-4 text-sm text-muted">
          No DAOs are registered yet. Registering one needs a timelock address and a description URL.
        </p>
      ) : (
        <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {daos.map((dao) => {
            const mine = incidents.filter((i) => i.dao_id === dao.dao_id);
            const open = mine.filter((i) => OPEN.has(i.status));
            const critical = open.some((i) => i.classification === "CRITICAL_MALICIOUS_PAYLOAD");
            const shield =
              open.length === 0
                ? { label: "Shield clear", tone: "text-aligned border-emerald-400/40 bg-emerald-400/10", glow: "rgba(52,211,153,0.35)" }
                : critical
                  ? { label: "Hijack attempt open", tone: "text-critical border-rose-400/50 bg-rose-500/15", glow: "rgba(251,79,106,0.45)" }
                  : { label: "Omission under review", tone: "text-suspicious border-orange-400/50 bg-orange-400/15", glow: "rgba(251,146,60,0.4)" };
            return (
              <li key={dao.dao_id} className="glass-card glow p-5">
                <div className="relative flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-start gap-3">
                    <span
                      className="grid size-10 shrink-0 place-items-center rounded-xl border border-sky-400/30 bg-gradient-to-b from-sky-400/20 to-transparent text-sky"
                      style={{ boxShadow: `0 0 18px ${shield.glow}` }}
                    >
                      <IconShield size={20} />
                    </span>
                    <div className="min-w-0">
                      <p className="font-display text-[17px] font-semibold leading-tight">{dao.name}</p>
                      <a
                        href={explorerAddress(dao.target_timelock)}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-0.5 inline-flex items-center gap-1 font-mono text-[12px] text-muted hover:text-sky"
                      >
                        timelock {short(dao.target_timelock, 8, 6)} <IconExternal size={12} />
                      </a>
                    </div>
                  </div>
                  <span className="eyebrow shrink-0">#{dao.dao_id}</span>
                </div>
                <div className="relative mt-4 flex flex-wrap gap-2">
                  <p className={`inline-flex rounded-full border px-2.5 py-0.5 text-[12px] font-semibold ${shield.tone}`}>
                    {shield.label}
                  </p>
                  {dao.verification === "VERIFIED" ? (
                    <p
                      className="inline-flex rounded-full border border-sky-400/40 bg-sky-400/10 px-2.5 py-0.5 text-[12px] font-semibold text-sky"
                      title={`Timelock admin() is the declared governor ${dao.governor}`}
                    >
                      Verified governor
                    </p>
                  ) : (
                    <p
                      className="inline-flex rounded-full border border-orange-400/50 bg-orange-400/15 px-2.5 py-0.5 text-[12px] font-semibold text-suspicious"
                      title={`Timelock admin() is ${dao.timelock_admin || "unreadable"}, not ${dao.governor}`}
                    >
                      Unverified registrar
                    </p>
                  )}
                </div>
                <dl className="relative mt-4 grid grid-cols-3 gap-2 text-center">
                  {(
                    [
                      ["Escrow", `${gen(dao.bounty_escrow, 2)}`, "GEN"],
                      ["Selectors", String(selectorCount(dao.selector_schema)), "verified"],
                      ["Flags", `${open.length}/${mine.length}`, "open/total"],
                    ] as const
                  ).map(([label, value, unit]) => (
                    <div key={label} className="rounded-xl bg-inset px-2 py-2">
                      <dt className="eyebrow !text-[10px]">{label}</dt>
                      <dd className="font-mono text-[15px]">{value}</dd>
                      <dd className="text-[10.5px] text-muted">{unit}</dd>
                    </div>
                  ))}
                </dl>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
