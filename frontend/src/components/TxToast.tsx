import { explorerTx } from "../config";
import type { TxState } from "../hooks/useSession";
import type { ConsensusProgress, ConsensusReceipt, WritePhase } from "../lib/genlayer";
import { short, timestamp } from "../lib/format";

type StepState = "done" | "current" | "upcoming" | "failed";

// Which of the three steps each phase belongs to.
const STEP_OF: Record<WritePhase, number> = { checking: 0, signing: 0, broadcast: 1, consensus: 1, confirming: 2, done: 3 };

const LIVE_STATUS: Record<string, string> = {
  PENDING: "Queued, waiting for a leader",
  PROPOSING: "Leader executing the call in GenVM",
  COMMITTING: "Validators re-executing and committing votes",
  REVEALING: "Validators revealing votes",
  LEADER_REVEALING: "Leader revealing its result",
  APPEAL_COMMITTING: "Appeal round: committing votes",
  APPEAL_REVEALING: "Appeal round: revealing votes",
  ACCEPTED: "Accepted by validator majority",
};

function votes(p?: ConsensusProgress | ConsensusReceipt): string {
  const v = p?.votes;
  if (!v) return "";
  const parts = [`${v.agree} agree`];
  if (v.disagree) parts.push(`${v.disagree} disagree`);
  if (v.timeout) parts.push(`${v.timeout} timed out`);
  if (v.idle) parts.push(`${v.idle} idle`);
  return `${parts.join(" · ")} of ${v.total}`;
}

function steps(tx: TxState): { label: string; detail: string; state: StepState }[] {
  const phase = tx.phase === "error" ? (tx.failedAt ?? "checking") : tx.phase;
  const at = STEP_OF[phase];
  const state = (i: number): StepState =>
    tx.phase === "error" && i === at ? "failed" : i < at ? "done" : i === at && tx.phase !== "error" ? "current" : "upcoming";
  const r = tx.receipt;

  const broadcast =
    phase === "checking"
      ? "Pre-flight check against current contract state"
      : phase === "signing"
        ? "Waiting for your signature"
        : tx.simulated
          ? "Simulated submission (nothing broadcast)"
          : `Hash received ${short(tx.hash ?? "", 10, 6)}`;

  const consensus =
    at < 1
      ? "Leader + validators re-execute the call"
      : at === 1
        ? [LIVE_STATUS[tx.progress?.status ?? "PENDING"] ?? tx.progress?.status ?? "Waiting for the network", votes(tx.progress)]
            .filter(Boolean)
            .join(" · ")
        : r
          ? [r.status, r.consensus, votes(r)].filter(Boolean).join(" · ")
          : "";

  const finality =
    at < 2
      ? "Read contract state to prove the effect"
      : phase === "confirming"
        ? "Reading contract state to confirm the result"
        : tx.phase === "error"
          ? "Not reached"
          : r?.status === "FINALIZED"
            ? `Finalized${r.finalizedAt ? ` ${timestamp(r.finalizedAt)}` : ""} · ${tx.confirmation ?? ""}`
            : `${tx.confirmation ?? ""}${r?.appealDeadline ? ` Appeal window closes ${timestamp(r.appealDeadline)}.` : ""}`;

  return [
    { label: "Broadcast to network", detail: broadcast, state: state(0) },
    { label: "GenVM multi-validator consensus", detail: consensus, state: state(1) },
    { label: "On-chain finality & state confirmation", detail: finality.trim(), state: state(2) },
  ];
}

function Receipt({ receipt, simulated }: { receipt: ConsensusReceipt; simulated?: boolean }) {
  return (
    <dl className="mt-3 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 rounded-xl border border-rule bg-inset/60 p-3 text-[12px]">
      <dt className="text-muted">Transaction</dt>
      <dd className="truncate font-mono">
        {simulated ? (
          "none (guest simulation)"
        ) : (
          <a className="text-sky hover:underline" href={explorerTx(receipt.hash)} target="_blank" rel="noreferrer">
            {short(receipt.hash, 10, 8)} ↗
          </a>
        )}
      </dd>
      <dt className="text-muted">Status</dt>
      <dd className="font-mono">{[receipt.status, receipt.consensus].filter(Boolean).join(" · ")}</dd>
      <dt className="text-muted">Execution</dt>
      <dd className="font-mono">{receipt.execution ?? "unknown"}</dd>
      <dt className="text-muted">Decided</dt>
      <dd className="font-mono">{receipt.decidedAt ? new Date(receipt.decidedAt * 1000).toLocaleString() : "unknown"}</dd>
      <dt className="text-muted">Finality</dt>
      <dd className="font-mono">
        {receipt.finalizedAt
          ? `Finalized ${new Date(receipt.finalizedAt * 1000).toLocaleString()}`
          : receipt.status === "FINALIZED"
            ? "Finalized"
            : receipt.appealDeadline
              ? `Accepted; final after ${new Date(receipt.appealDeadline * 1000).toLocaleTimeString()}`
              : "Accepted"}
      </dd>
      <dt className="text-muted">Block</dt>
      <dd className="font-mono">
        {receipt.block !== null
          ? receipt.block
          : `n/a (Studio Next is blockless)${receipt.decisionId !== null ? ` · decision #${receipt.decisionId}` : ""}`}
      </dd>
    </dl>
  );
}

export function TxToast({ tx, onDismiss }: { tx: TxState | null; onDismiss: () => void }) {
  if (!tx) return null;
  const tone = tx.phase === "error" ? "border-critical" : tx.phase === "done" ? "border-aligned" : "border-sky";
  const settled = tx.phase === "done" || tx.phase === "error";

  if (tx.plain) {
    return (
      <div role={tx.phase === "error" ? "alert" : "status"} className={`fixed inset-x-4 bottom-4 z-40 mx-auto max-w-md glass-card lift !bg-slate-950/90 border-l-4 ${tone} p-4 shadow-2xl shadow-black/40 sm:inset-x-auto sm:right-6`}>
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="font-semibold">{tx.label}</p>
            {tx.error ? <p className="text-sm text-critical">{tx.error}</p> : null}
          </div>
          {settled ? (
            <button type="button" onClick={onDismiss} className="text-muted hover:text-ink" aria-label="Dismiss">✕</button>
          ) : (
            <span aria-hidden className="mt-1 size-2.5 shrink-0 rounded-full bg-sky live-dot" />
          )}
        </div>
      </div>
    );
  }

  const heading =
    tx.phase === "done"
      ? tx.incidentId !== undefined
        ? `Report successful · Incident #${tx.incidentId} confirmed`
        : tx.simulated
          ? "Simulated report confirmed"
          : "Transaction confirmed"
      : tx.phase === "error"
        ? tx.failedAt === "checking" || tx.failedAt === "signing"
          ? "Not submitted"
          : "Consensus did not confirm this transaction"
        : tx.phase === "checking" || tx.phase === "signing"
          ? "Preparing transaction…"
          : "Awaiting GenVM execution & consensus…";

  return (
    <div
      role={tx.phase === "error" ? "alert" : "status"}
      aria-live="polite"
      className={`fixed inset-x-4 bottom-4 z-40 mx-auto max-h-[calc(100dvh-2rem)] max-w-md overflow-y-auto glass-card lift !bg-slate-950/95 border-l-4 ${tone} p-4 shadow-2xl shadow-black/40 sm:inset-x-auto sm:right-6`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="eyebrow">
            {tx.label}
            {tx.simulated ? <span className="ml-2 rounded-full border border-amber/50 px-1.5 text-amber">Guest simulation</span> : null}
          </p>
          <p className={`mt-0.5 font-semibold ${tx.phase === "error" ? "text-critical" : tx.phase === "done" ? "text-aligned" : ""}`}>{heading}</p>
        </div>
        {settled ? (
          <button type="button" onClick={onDismiss} className="text-muted hover:text-ink" aria-label="Dismiss">✕</button>
        ) : (
          <span aria-hidden className="mt-1 size-2.5 shrink-0 rounded-full bg-sky live-dot" />
        )}
      </div>

      <ol className="mt-3 space-y-2">
        {steps(tx).map((st, i) => (
          <li key={st.label} aria-current={st.state === "current" ? "step" : undefined} className="flex gap-2.5">
            <span
              aria-hidden
              className={`mt-0.5 grid size-5 shrink-0 place-items-center rounded-full font-mono text-[10px] ${
                st.state === "done"
                  ? "bg-aligned text-slate-950"
                  : st.state === "current"
                    ? "bg-sky text-slate-950 live-dot"
                    : st.state === "failed"
                      ? "bg-critical text-slate-950"
                      : "border border-rule text-muted"
              }`}
            >
              {st.state === "done" ? "✓" : st.state === "failed" ? "✕" : i + 1}
            </span>
            <div className="min-w-0">
              <p className={`text-sm font-semibold ${st.state === "upcoming" ? "text-muted" : ""}`}>{st.label}</p>
              {st.detail ? <p className="text-[12px] text-muted break-words">{st.detail}</p> : null}
            </div>
          </li>
        ))}
      </ol>

      {tx.phase === "error" ? (
        <p className="mt-3 rounded-xl border border-critical/40 bg-critical/10 p-2.5 text-sm text-critical">{tx.error}</p>
      ) : null}

      {tx.phase === "done" ? (
        <p className="mt-3 inline-flex items-center gap-1.5 rounded-full border border-aligned/50 bg-aligned/10 px-2.5 py-0.5 text-xs font-semibold text-aligned">
          ✓ {tx.simulated ? "Consensus confirmed (simulated, not on-chain)" : "Consensus Confirmed (On-Chain)"}
        </p>
      ) : null}

      {tx.receipt && (tx.phase === "done" || tx.phase === "error" || tx.phase === "confirming") ? (
        <Receipt receipt={tx.receipt} simulated={tx.simulated} />
      ) : tx.hash && !tx.simulated ? (
        <a className="mt-2 inline-block font-mono text-[12px] text-sky hover:underline" href={explorerTx(tx.hash)} target="_blank" rel="noreferrer">
          Follow on the explorer ↗
        </a>
      ) : null}
    </div>
  );
}
