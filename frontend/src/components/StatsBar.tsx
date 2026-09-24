import type { ReactNode } from "react";
import { gen } from "../lib/format";
import type { Dao, Incident, Ledger } from "../lib/types";
import type { ProtocolState } from "../hooks/useProtocol";
import { IconPulse, IconShield, IconTarget, IconVault } from "./Icons";

function Stat({
  icon,
  label,
  value,
  unit,
  note,
  tone = "sky",
}: {
  icon: ReactNode;
  label: string;
  value: string;
  unit?: string;
  note: ReactNode;
  tone?: "sky" | "critical";
}) {
  const halo = tone === "critical" ? "text-critical shadow-[0_0_18px_rgba(251,79,106,0.3)] border-critical/30 from-critical/20" : "text-sky shadow-[0_0_18px_rgba(56,189,248,0.3)] border-sky-400/30 from-sky-400/20";
  return (
    <div className="gradient-edge glow relative rounded-2xl p-4 shadow-[0_8px_32px_rgba(56,189,248,0.08)] backdrop-blur-xl sm:p-5">
      <div className="relative flex items-start justify-between gap-3">
        <p className="eyebrow">{label}</p>
        <span className={`grid size-9 shrink-0 place-items-center rounded-xl border bg-gradient-to-b to-transparent ${halo}`}>{icon}</span>
      </div>
      <p className="relative mt-1 font-display text-3xl font-bold tracking-tight sm:text-[2.1rem]">
        {value}
        {unit ? <span className="ml-1.5 font-mono text-sm font-normal text-muted">{unit}</span> : null}
      </p>
      <p className="relative mt-1 text-[12.5px] text-muted">{note}</p>
    </div>
  );
}

export function StatsBar({
  daos,
  incidents,
  ledger,
  health,
  loading,
}: {
  daos: Dao[];
  incidents: Incident[];
  ledger: Ledger | null;
  health: ProtocolState["health"];
  loading: boolean;
}) {
  const hijacks = incidents.filter((i) => i.classification === "CRITICAL_MALICIOUS_PAYLOAD" && i.status !== "OVERTURNED").length;
  const omissions = incidents.filter((i) => i.classification === "SUSPICIOUS_OMISSION" && i.status !== "OVERTURNED").length;
  const escrow = daos.reduce((sum, d) => sum + BigInt(d.bounty_escrow), 0n);
  const uptime = health.attempts ? (health.successes / health.attempts) * 100 : null;
  const dash = loading ? "…" : "0";

  return (
    <section aria-label="Protocol statistics" className="space-y-3">
      <div className="grid grid-cols-1 gap-3 min-[480px]:grid-cols-2 xl:grid-cols-4">
        <Stat
          icon={<IconShield size={18} />}
          label="Protected DAOs"
          value={daos.length ? String(daos.length) : dash}
          note={<>{gen(escrow, 2)} GEN in bounty escrow</>}
        />
        <Stat
          icon={<IconTarget size={18} />}
          label="Intercepted Hijacks"
          value={incidents.length ? String(hijacks) : dash}
          tone={hijacks > 0 ? "critical" : "sky"}
          note={
            <>
              {omissions} suspicious {omissions === 1 ? "omission" : "omissions"} · {incidents.length} flagged in total
            </>
          }
        />
        <Stat
          icon={<IconVault size={18} />}
          label="Active Challenger Escrow"
          value={ledger ? gen(ledger.total_bonded, 2) : "…"}
          unit="GEN"
          note="Bonds, DAO escrow and reserved bounties"
        />
        <Stat
          icon={<IconPulse size={18} />}
          label="RPC Uptime"
          value={uptime === null ? "…" : `${uptime.toFixed(uptime === 100 ? 0 : 1)}%`}
          note={
            health.attempts
              ? `${health.successes}/${health.attempts} reads this session${health.latencyMs !== null ? ` · ${health.latencyMs} ms` : ""}`
              : "Measured live by this dashboard"
          }
        />
      </div>
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 px-1 text-[12.5px] text-muted">
        {ledger ? (
          ledger.solvent ? (
            <>
              <span aria-hidden className="font-display text-base font-bold text-aligned">=</span>
              Ledger balanced: {gen(ledger.total_deposited, 2)} GEN held equals {gen(ledger.total_bonded, 2)} bonded +{" "}
              {gen(ledger.total_claimable, 2)} owed + {gen(ledger.total_slashed, 2)} treasury.
            </>
          ) : (
            <span className="font-semibold text-critical">The contract ledger does not balance.</span>
          )
        ) : (
          "Reading the contract ledger…"
        )}
      </p>
    </section>
  );
}
