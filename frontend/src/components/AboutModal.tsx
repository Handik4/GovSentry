import { useEffect, useRef, useState } from "react";
import type { Constants } from "../lib/types";
import { gen } from "../lib/format";
import { IconBytes, IconClose, IconLock, IconNodes, IconScale, LogoMark } from "./Icons";

interface Stage {
  title: string;
  icon: typeof IconBytes;
  summary: string;
  detail: string[];
}

function stages(c: Constants | null): Stage[] {
  const reporter = c ? gen(c.MIN_REPORTER_BOND) : "1";
  const appeal = c ? gen(c.MIN_APPEAL_BOND) : "2";
  const hours = c ? Math.round(c.CHALLENGE_WINDOW / 3600) : 24;
  return [
    {
      title: "Calldata Ingestion & Disassembly",
      icon: IconBytes,
      summary: "Every node decodes the proposal's bytes identically before any model is consulted.",
      detail: [
        "Strict validation: 0x prefix, a non-null 4-byte selector, whole 32-byte argument words.",
        "Selectors resolve against a privileged-call table and the DAO's own verified ABI.",
        "The decoded call becomes fixed ground truth in the prompt, so the model judges facts, not raw hex.",
      ],
    },
    {
      title: "Semantic Discrepancy Engine",
      icon: IconNodes,
      summary: "Validators each run an LLM that compares what the description claims with what the call executes.",
      detail: [
        "The leader proposes a classification with its reasoning; each validator re-runs the check independently.",
        "Validators must reach the same classification. Wording may differ; the verdict may not.",
        "Untrusted text is fenced and neutralized so a proposal cannot instruct the model.",
      ],
    },
    {
      title: "Consensus Verdict & Challenge Lock",
      icon: IconScale,
      summary: "The agreed verdict is written on-chain and a deceptive proposal is locked into a public challenge window.",
      detail: [
        "Aligned: the flag is dismissed and 90% of the reporter bond is refunded.",
        "Suspicious omission or critical payload: a bounty is reserved from the DAO's escrow.",
        `The incident stays locked for ${hours} hours before anyone can be paid.`,
      ],
    },
    {
      title: "Bonded Challenger Escrow",
      icon: IconLock,
      summary: "Both sides put GEN at stake, and every rebuttal is bound to the exact calldata it disputes.",
      detail: [
        `Reporters bond at least ${reporter} GEN; appellants bond at least ${appeal} GEN.`,
        "A rebuttal must quote the incident's calldata hash, so evidence cannot be replayed on another incident.",
        "The losing bond is split between the winner and the treasury; the ledger always balances.",
      ],
    },
  ];
}

export function AboutModal({ open, onClose, constants }: { open: boolean; onClose: () => void; constants: Constants | null }) {
  const ref = useRef<HTMLDialogElement>(null);
  const [focus, setFocus] = useState(0);
  const list = stages(constants);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      className="about m-auto w-[min(60rem,calc(100vw-1.5rem))] max-h-[calc(100dvh-2rem)] overflow-y-auto rounded-2xl border border-sky-500/25 bg-slate-950/95 p-0 text-ink shadow-[0_30px_80px_-20px_rgba(0,0,0,0.8),0_0_60px_rgba(56,189,248,0.12)] backdrop:bg-transparent"
      aria-labelledby="about-title"
      onClose={onClose}
      onClick={(e) => {
        if (e.target === ref.current) onClose();
      }}
    >
      <div className="relative p-5 sm:p-8">
        <div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 top-0 h-48 bg-[radial-gradient(40rem_12rem_at_20%_0%,rgba(56,189,248,0.18),transparent_70%)]"
        />
        <button
          type="button"
          onClick={onClose}
          className="btn btn-quiet absolute right-4 top-4 !px-2.5"
          aria-label="Close"
          autoFocus
        >
          <IconClose />
        </button>

        <header className="relative flex items-center gap-4 pr-12">
          <LogoMark size={52} />
          <div>
            <p className="eyebrow text-sky">About GovSentry</p>
            <h2 id="about-title" className="font-display text-2xl font-bold tracking-tight sm:text-3xl">
              A governance firewall that reads the bytecode
            </h2>
          </div>
        </header>

        <p className="relative mt-5 max-w-3xl text-[15.5px] leading-relaxed text-ink/90">
          Governance takeovers rarely look like takeovers. They pass because voters read the description, and the
          description says <em>routine parameter update</em> while the calldata calls <code className="font-mono text-sky">transferOwnership</code>,
          mints supply, or drains the treasury. GovSentry puts that gap on trial. Anyone can post a bond and flag a
          proposal; GenLayer validators decode the call, compare it with the prose, and reach a public verdict while the
          target timelock is still waiting. Honest reporters are paid from the DAO's bounty escrow, and every verdict can
          be challenged by someone willing to put GEN behind their rebuttal.
        </p>

        <section aria-labelledby="mechanism-title" className="relative mt-8">
          <h3 id="mechanism-title" className="eyebrow mb-3">
            The mechanism, in the order it runs
          </h3>
          <ol className="grid gap-3 sm:grid-cols-2">
            {list.map((s, i) => {
              const Ico = s.icon;
              const expanded = focus === i;
              return (
                <li key={s.title}>
                  <button
                    type="button"
                    aria-expanded={expanded}
                    onClick={() => setFocus(i)}
                    className={`glass-card glow flex h-full w-full flex-col justify-start p-4 text-left ${expanded ? "!border-sky-400/60 lift" : ""}`}
                  >
                    <span className="relative flex items-start gap-3">
                      <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-sky-400/30 bg-gradient-to-b from-sky-400/25 to-sky-600/10 text-sky shadow-[0_0_18px_rgba(56,189,248,0.25)]">
                        <Ico />
                      </span>
                      <span className="min-w-0">
                        <span className="font-mono text-[11px] text-sky">Stage {i + 1}</span>
                        <span className="block font-display text-[17px] font-semibold leading-snug">{s.title}</span>
                        <span className="mt-1 block text-[13.5px] text-muted">{s.summary}</span>
                      </span>
                    </span>
                    {expanded ? (
                      <ul className="relative mt-3 space-y-1.5 border-t border-rule pt-3 text-[13.5px]">
                        {s.detail.map((d) => (
                          <li key={d} className="flex gap-2">
                            <span aria-hidden className="mt-2 size-1.5 shrink-0 rounded-full bg-sky" />
                            <span>{d}</span>
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ol>
        </section>

        <section className="glass-card relative mt-6 overflow-hidden p-5">
          <div
            aria-hidden
            className="pointer-events-none absolute -right-20 -top-20 size-64 rounded-full bg-cyan-400/10 blur-3xl"
          />
          <p className="eyebrow text-cyan-300">Why this needs GenLayer</p>
          <h3 className="mt-1 font-display text-xl font-semibold">Consensus over judgment, not just arithmetic</h3>
          <div className="mt-3 grid gap-4 text-[14px] leading-relaxed text-ink/90 md:grid-cols-2">
            <p>
              A standard EVM chain can decode a selector, but it cannot decide whether a paragraph of English honestly
              describes it. Doing that on Ethereum means trusting an off-chain oracle or a committee to run the model
              and report back.
            </p>
            <p>
              GenVM runs the model inside the transaction. Each validator executes the prompt, and the equivalence
              principle accepts the verdict only when they agree on the classification. The judgment is produced
              by the chain's own consensus, with no trusted reporter in between.
            </p>
          </div>
        </section>
      </div>
    </dialog>
  );
}
