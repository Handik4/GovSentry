import { useState } from "react";
import { explorerAddress } from "../config";
import { APPEAL_LABEL, STATUS_LABEL } from "../lib/copy";
import { duration, gen, parseGen, sameAddress, short, timestamp } from "../lib/format";
import type { Constants, Dao, Incident } from "../lib/types";
import type { Session } from "../hooks/useSession";
import { Dissection } from "./Dissection";
import { VerdictBadge } from "./Verdict";
import { isLive } from "../lib/verdictStyle";

type StepState = "done" | "current" | "upcoming";
interface Step {
  label: string;
  detail: string;
  state: StepState;
}

function lifecycle(i: Incident, now: number): Step[] {
  const settled = i.status === "PAID" || i.status === "EXPIRED" || i.status === "OVERTURNED";
  if (i.classification === "ALIGNED") {
    return [
      { label: "Flagged", detail: timestamp(i.flagged_at), state: "done" },
      { label: "Dismissed as aligned", detail: "Description matches the calldata", state: "done" },
      { label: "Refunded", detail: settled ? "90% of bond returned" : "Waiting for refund", state: settled ? "done" : "current" },
    ];
  }
  const windowOpen = now < i.unlock_time;
  const appealed = i.appeal !== null;
  return [
    { label: "Flagged", detail: timestamp(i.flagged_at), state: "done" },
    {
      label: "Challenge window",
      detail: windowOpen ? `Closes ${timestamp(i.unlock_time)}` : `Closed ${timestamp(i.unlock_time)}`,
      state: windowOpen && !appealed ? "current" : "done",
    },
    {
      label: "Appeal",
      detail: appealed ? APPEAL_LABEL[i.appeal!.status] : windowOpen ? "Open to anyone" : "None filed",
      state: i.status === "APPEALED" ? "current" : appealed || !windowOpen ? "done" : "upcoming",
    },
    {
      label: "Settled",
      detail: settled ? STATUS_LABEL[i.status] : "Pending",
      state: settled ? "done" : !windowOpen && i.status !== "APPEALED" ? "current" : "upcoming",
    },
  ];
}

function Timeline({ steps, incident, now, windowSeconds }: { steps: Step[]; incident: Incident; now: number; windowSeconds: number }) {
  const left = incident.unlock_time - now;
  const elapsed = Math.min(1, Math.max(0, 1 - left / windowSeconds));
  const showWindow = incident.classification !== "ALIGNED";
  return (
    <section aria-label="Dispute and appeal timeline" className="glass-card glow p-4 sm:p-5">
      <div className="relative flex flex-wrap items-end justify-between gap-2">
        <p className="eyebrow">Dispute &amp; appeal timeline</p>
        {showWindow ? (
          <p className="font-mono text-[12px] text-muted">
            {left > 0 ? (
              <>
                window closes in <span className="text-base text-sky">{duration(left)}</span>
              </>
            ) : (
              <>window closed {timestamp(incident.unlock_time)}</>
            )}
          </p>
        ) : null}
      </div>
      {showWindow ? (
        <div className="relative mt-3">
          <div className="h-2 overflow-hidden rounded-full bg-inset shadow-[inset_0_1px_2px_rgba(0,0,0,0.6)]">
            <div
              className="h-full rounded-full bg-gradient-to-r from-sky-600 via-sky-400 to-cyan-300 shadow-[0_0_12px_rgba(56,189,248,0.6)]"
              style={{ width: `${elapsed * 100}%` }}
            />
          </div>
          <div className="mt-1 flex justify-between font-mono text-[10.5px] text-muted">
            <span>flagged {timestamp(incident.flagged_at)}</span>
            <span>unlock {timestamp(incident.unlock_time)}</span>
          </div>
        </div>
      ) : null}
      <ol className="relative mt-4 grid gap-2 sm:grid-flow-col sm:auto-cols-fr">
        {steps.map((st, idx) => (
          <li
            key={st.label}
            aria-current={st.state === "current" ? "step" : undefined}
            className={`rounded-xl border px-3 py-2 ${
              st.state === "done"
                ? "border-sky-400/25 bg-sky-400/[0.06]"
                : st.state === "current"
                  ? "border-sky-400/60 bg-sky-400/10 shadow-[0_0_20px_rgba(56,189,248,0.18)]"
                  : "border-rule bg-inset/40"
            }`}
          >
            <p className="flex items-center gap-2 text-sm font-semibold">
              <span
                aria-hidden
                className={`grid size-5 place-items-center rounded-full font-mono text-[10px] ${
                  st.state === "upcoming" ? "border border-rule text-muted" : "bg-sky-400 text-slate-950"
                } ${st.state === "current" ? "live-dot" : ""}`}
              >
                {idx + 1}
              </span>
              <span className={st.state === "upcoming" ? "text-muted" : ""}>{st.label}</span>
            </p>
            <p className="mt-0.5 pl-7 text-[12px] text-muted">{st.detail}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}

/** Split validator reasoning into sentences for a scannable breakdown. */
function sentences(text: string): string[] {
  // Split only where punctuation is followed by whitespace, so decimals such
  // as 0.15e18 and signatures such as f(uint256). stay intact.
  return text
    .split(/(?<=[.!?])\s+/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function ConsensusReport({ incident }: { incident: Incident }) {
  const i = incident;
  const parts = sentences(i.rationale);
  return (
    <section aria-labelledby="consensus-title" className="glass-card glow overflow-hidden">
      <div className="relative flex flex-wrap items-center justify-between gap-2 border-b border-rule px-4 py-3 sm:px-5">
        <h3 id="consensus-title" className="eyebrow !text-sky">LLM validator consensus report</h3>
        <VerdictBadge verdict={i.classification} />
      </div>
      <div className="relative grid gap-4 p-4 sm:p-5 lg:grid-cols-[1.4fr_1fr]">
        <figure className="relative self-start rounded-xl border border-sky-400/15 bg-inset p-4 pl-5">
          <span aria-hidden className="absolute -left-px top-3 bottom-3 w-[3px] rounded-full bg-gradient-to-b from-sky-300 to-cyan-500" />
          <span aria-hidden className="absolute right-3 top-0 font-display text-6xl leading-none text-sky-400/15">&rdquo;</span>
          <blockquote className="relative text-[15px] leading-relaxed">{parts[0] ?? "No reasoning recorded."}</blockquote>
          <figcaption className="mt-2 font-mono text-[11px] text-muted">Leader rationale, accepted by validator agreement</figcaption>
        </figure>
        <div>
          <p className="eyebrow mb-2">Reasoning breakdown</p>
          {parts.length > 1 ? (
            <ol className="space-y-2 text-[13.5px] leading-relaxed">
              {parts.slice(1).map((sn, n) => (
                <li key={n} className="flex gap-2.5">
                  <span aria-hidden className="mt-1 grid size-4 shrink-0 place-items-center rounded-full border border-sky-400/40 font-mono text-[9px] text-sky">
                    {n + 1}
                  </span>
                  <span>{sn}</span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-[13px] text-muted">The rationale is a single finding.</p>
          )}
          <dl className="mt-3 grid grid-cols-2 gap-2 border-t border-rule pt-3 text-[12px]">
            <div>
              <dt className="text-muted">Decoded call</dt>
              <dd className="truncate font-mono text-sky-200">{i.decoded.signature === "UNKNOWN" ? i.decoded.selector : i.decoded.signature.split("(")[0]}</dd>
            </div>
            <div>
              <dt className="text-muted">Privileged</dt>
              <dd className={`font-mono ${i.decoded.privileged ? "text-critical" : "text-aligned"}`}>{i.decoded.privileged ? "yes" : "no"}</dd>
            </div>
            <div className="col-span-2">
              <dt className="text-muted">Prose commitment</dt>
              <dd className="truncate font-mono text-slate-300" title={i.prose_hash}>{i.prose_hash}</dd>
            </div>
          </dl>
        </div>
      </div>
    </section>
  );
}

function AppealForm({ incident, constants, session }: { incident: Incident; constants: Constants | null; session: Session }) {
  const prefix = `Calldata commitment: ${incident.calldata_hash}\n\n`;
  const [text, setText] = useState(prefix);
  const minBond = BigInt(constants?.MIN_APPEAL_BOND ?? "2000000000000000000");
  const [bondText, setBondText] = useState(gen(minBond));
  const bond = parseGen(bondText);

  const argument = text.replace(incident.calldata_hash, "").replace("Calldata commitment:", "").trim();
  const problem =
    !text.toLowerCase().includes(incident.calldata_hash.toLowerCase())
      ? "Keep the calldata hash in the rebuttal. It ties your evidence to this incident."
      : argument.length === 0
        ? "Explain why the description does disclose what the calldata does."
        : text.trim().length < 32
          ? "The rebuttal needs at least 32 characters."
          : bond === null || bond < minBond
            ? `The appeal bond must be at least ${gen(minBond)} GEN.`
            : null;
  const isReporter = sameAddress(session.signer?.address, incident.reporter);

  return (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (problem || bond === null) return;
        void session.run(`Appeal incident #${incident.incident_id}`, "file_appeal", [incident.incident_id, text], bond);
      }}
    >
      <div>
        <label htmlFor="rebuttal" className="text-sm font-semibold">Rebuttal</label>
        <p id="rebuttal-help" className="text-[13px] text-muted">
          Validators rule on this text. Losing forfeits half the bond to the reporter.
        </p>
        <textarea
          id="rebuttal"
          rows={5}
          className="field mt-1.5 font-mono text-[13px]"
          value={text}
          aria-describedby="rebuttal-help"
          aria-invalid={problem !== null && argument.length > 0}
          onChange={(e) => setText(e.target.value)}
        />
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <div className="w-36">
          <label htmlFor="appeal-bond" className="text-sm font-semibold">Bond (GEN)</label>
          <input
            id="appeal-bond"
            inputMode="decimal"
            className="field mt-1.5 font-mono"
            value={bondText}
            onChange={(e) => setBondText(e.target.value)}
          />
        </div>
        <button type="submit" className="btn btn-primary" disabled={!!problem || !session.signer || isReporter}>
          File appeal
        </button>
      </div>
      <p className="text-[13px] text-muted" aria-live="polite">
        {!session.signer ? "Connect to file an appeal." : isReporter ? "You reported this incident, so you cannot appeal it." : problem}
      </p>
    </form>
  );
}

export function IncidentDossier({
  incident,
  dao,
  constants,
  session,
  now,
}: {
  incident: Incident;
  dao: Dao | undefined;
  constants: Constants | null;
  session: Session;
  now: number;
}) {
  const i = incident;
  const payout = BigInt(i.bond) + BigInt(i.reserved_bounty) + BigInt(i.appeal_award);
  const windowLeft = i.unlock_time - now;
  const payable = i.status === "PENDING_CHALLENGE" || i.status === "CONFIRMED";
  const stalledAt = i.unlock_time + (constants?.APPEAL_RESOLUTION_TIMEOUT ?? 259200);
  const busy = session.tx !== null && session.tx.phase !== "done" && session.tx.phase !== "error";

  return (
    <article aria-labelledby="dossier-title" className="space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="eyebrow">
            Incident #{i.incident_id} · {dao?.name ?? `DAO #${i.dao_id}`}
          </p>
          <h2 id="dossier-title" className="font-display text-3xl font-bold tracking-tight sm:text-4xl">
            Proposal #{i.proposal_id}
            <span className="text-muted"> · action {i.action_index}</span>
          </h2>
          <p className="mt-1 text-[12px] text-muted">
            Calldata and description read from the governor on-chain (created in block {i.created_block})
            {i.prose_truncated ? "; the description was truncated for analysis" : ""}.
          </p>
        </div>
        <VerdictBadge verdict={i.classification} size="md" live={isLive(i.status)} />
      </header>

      <Dissection
        prose={i.prose_description}
        decoded={i.decoded}
        calldata={i.raw_calldata}
        target={i.target_contract}
        verdict={i.classification}
      />

      {i.rationale ? <ConsensusReport incident={i} /> : null}

      <Timeline steps={lifecycle(i, now)} incident={i} now={now} windowSeconds={constants?.CHALLENGE_WINDOW ?? 86400} />

      <div className="grid gap-4 lg:grid-cols-[1fr_1.35fr]">
        <section className="glass-card space-y-3 p-4 sm:p-5">
          <p className="eyebrow">Stakes</p>
          <dl className="space-y-1.5 text-sm">
            <div className="flex justify-between gap-3">
              <dt className="text-muted">Reporter</dt>
              <dd>
                <a className="font-mono hover:text-sky" href={explorerAddress(i.reporter)} target="_blank" rel="noreferrer">
                  {short(i.reporter)}
                </a>
              </dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-muted">Reporter bond</dt>
              <dd className="font-mono">{gen(i.bond)} GEN</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-muted">Bounty reserved</dt>
              <dd className="font-mono">{gen(i.reserved_bounty)} GEN</dd>
            </div>
            {BigInt(i.appeal_award) > 0n ? (
              <div className="flex justify-between gap-3">
                <dt className="text-muted">Award from appeal</dt>
                <dd className="font-mono">{gen(i.appeal_award)} GEN</dd>
              </div>
            ) : null}
            <div className="flex justify-between gap-3">
              <dt className="text-muted">Calldata hash</dt>
              <dd className="font-mono" title={i.calldata_hash}>{short(i.calldata_hash, 10, 6)}</dd>
            </div>
          </dl>

          {payable ? (
            <div className="border-t border-rule pt-3">
              {windowLeft > 0 ? (
                <p className="mb-2">
                  <span className="eyebrow block">Challenge window closes in</span>
                  <span className="font-mono text-2xl text-sky drop-shadow-[0_0_10px_rgba(56,189,248,0.45)]" aria-live="off">{duration(windowLeft)}</span>
                </p>
              ) : null}
              <button
                type="button"
                className="btn btn-primary w-full"
                disabled={windowLeft > 0 || busy || !session.signer}
                onClick={() => void session.run(`Claim payout for incident #${i.incident_id}`, "claim_payout", [i.incident_id])}
              >
                Claim payout · {gen(payout)} GEN
              </button>
              <p className="mt-1.5 text-[12px] text-muted">
                {windowLeft > 0
                  ? "Unlocks when the window closes without a successful appeal. Pays the reporter."
                  : !session.signer
                    ? "Connect to claim. Anyone can trigger it; the reporter is paid."
                    : "Anyone can trigger it; the reporter is paid."}
              </p>
            </div>
          ) : null}

          {i.status === "DISMISSED" || i.status === "INCONCLUSIVE" || (i.status === "APPEALED" && now >= stalledAt) ? (
            <div className="border-t border-rule pt-3">
              <button
                type="button"
                className="btn btn-quiet w-full"
                disabled={busy || !session.signer}
                onClick={() => void session.run(`Refund incident #${i.incident_id}`, "expire_incident", [i.incident_id])}
              >
                Close and refund bonds
              </button>
              <p className="mt-1.5 text-[12px] text-muted">
                {i.status === "DISMISSED"
                  ? "Returns 90% of the reporter bond; 10% goes to the treasury."
                  : "Returns every bond in full."}{" "}
                Refunds are withdrawn from the account menu.
              </p>
            </div>
          ) : null}
        </section>

        <section className="glass-card p-4 sm:p-5">
          {i.status === "PENDING_CHALLENGE" && windowLeft > 0 ? (
            <AppealForm key={i.incident_id} incident={i} constants={constants} session={session} />
          ) : i.appeal ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p className="eyebrow">Appeal by {short(i.appeal.appellant)}</p>
                <span className="text-sm font-semibold">{APPEAL_LABEL[i.appeal.status]}</span>
              </div>
              <p className="whitespace-pre-line rounded-lg bg-inset p-3 font-mono text-[13px]">{i.appeal.rebuttal}</p>
              {i.appeal.rationale ? <p className="text-[15px] leading-relaxed">{i.appeal.rationale}</p> : null}
              {i.status === "APPEALED" ? (
                <>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={busy || !session.signer}
                    onClick={() => void session.run(`Resolve appeal on incident #${i.incident_id}`, "resolve_appeal", [i.incident_id])}
                  >
                    Ask validators to rule
                  </button>
                  <p className="text-[12px] text-muted">
                    Anyone can trigger the ruling. Unresolved appeals can be closed with full refunds after{" "}
                    {timestamp(stalledAt)}.
                  </p>
                </>
              ) : null}
            </div>
          ) : (
            <div>
              <p className="eyebrow mb-1.5">Appeal</p>
              <p className="text-sm text-muted">
                {i.classification === "ALIGNED"
                  ? "Aligned proposals cannot be appealed."
                  : "No appeal was filed before the challenge window closed."}
              </p>
            </div>
          )}
        </section>
      </div>
    </article>
  );
}
