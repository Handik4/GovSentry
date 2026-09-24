import { STATUS_LABEL, VERDICT_GLYPH } from "../lib/copy";
import { duration } from "../lib/format";
import type { Dao, Incident } from "../lib/types";
import { VERDICT_GLOW, VERDICT_TEXT, isLive } from "../lib/verdictStyle";
import { VerdictBadge } from "./Verdict";

export function TriageFeed({
  incidents,
  daos,
  selected,
  onSelect,
  now,
  window: windowSeconds,
  loading,
}: {
  incidents: Incident[];
  daos: Dao[];
  selected: number | null;
  onSelect: (id: number) => void;
  now: number;
  window: number;
  loading: boolean;
}) {
  const daoName = (id: number) => daos.find((d) => d.dao_id === id)?.name ?? `DAO #${id}`;

  return (
    <section aria-labelledby="feed-title">
      <div className="mb-3 flex items-baseline justify-between">
        <h2 id="feed-title" className="font-display text-lg font-semibold">
          Proposal Triage Feed
        </h2>
        <span className="eyebrow">{incidents.length} flagged</span>
      </div>
      {loading && incidents.length === 0 ? (
        <p className="glass-card p-4 text-sm text-muted">Reading incidents from the contract…</p>
      ) : incidents.length === 0 ? (
        <p className="glass-card border-dashed p-4 text-sm text-muted">
          Nothing has been flagged yet. Use Flag Proposal to put the first one on trial.
        </p>
      ) : (
        <ul className="space-y-3">
          {incidents.map((i) => {
            const active = i.incident_id === selected;
            const windowOpen = i.status === "PENDING_CHALLENGE" && now < i.unlock_time;
            const elapsed = Math.min(1, Math.max(0, 1 - (i.unlock_time - now) / windowSeconds));
            return (
              <li key={i.incident_id}>
                <button
                  type="button"
                  onClick={() => onSelect(i.incident_id)}
                  aria-current={active ? "true" : undefined}
                  className={`glass-card group w-full p-4 text-left hover:-translate-y-0.5 ${
                    active ? "lift !border-sky-400/60 shadow-[0_0_0_1px_rgba(56,189,248,0.35),0_12px_40px_rgba(56,189,248,0.14)]" : ""
                  }`}
                >
                  <span className="flex items-start gap-3">
                    <span
                      aria-hidden
                      className={`w-7 shrink-0 font-display text-3xl font-bold leading-none ${VERDICT_TEXT[i.classification]} ${VERDICT_GLOW[i.classification]}`}
                    >
                      {VERDICT_GLYPH[i.classification]}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="flex items-baseline justify-between gap-2">
                        <span className="font-semibold">Proposal #{i.proposal_id}</span>
                        <span className="eyebrow shrink-0">incident #{i.incident_id}</span>
                      </span>
                      <span className="block truncate text-[13px] text-muted">{daoName(i.dao_id)}</span>
                      <span className="mt-2 block truncate rounded-md bg-inset px-2 py-1 font-mono text-[12px] text-sky-200">
                        {i.decoded.signature === "UNKNOWN" ? i.decoded.selector : i.decoded.signature}
                      </span>
                      <span className="mt-2.5 flex flex-wrap items-center gap-2">
                        <VerdictBadge verdict={i.classification} live={isLive(i.status)} />
                        <span className="text-[12px] text-muted">{STATUS_LABEL[i.status]}</span>
                      </span>
                      {windowOpen ? (
                        <span className="mt-3 block">
                          <span className="flex justify-between font-mono text-[11px] text-muted">
                            <span>challenge window</span>
                            <span className="text-sky">{duration(i.unlock_time - now)} left</span>
                          </span>
                          <span className="mt-1 block h-1 overflow-hidden rounded-full bg-inset">
                            <span
                              className="block h-full rounded-full bg-gradient-to-r from-sky-500 to-cyan-300"
                              style={{ width: `${elapsed * 100}%` }}
                            />
                          </span>
                        </span>
                      ) : null}
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
