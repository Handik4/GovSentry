import { useEffect, useId, useState } from "react";
import { dryRunReport, view } from "../lib/genlayer";
import { explainError, STATUS_LABEL, VERDICT_LABEL } from "../lib/copy";
import { gen, parseGen, sameAddress } from "../lib/format";
import type { Constants, Dao, Disassembly, DryRun, Incident } from "../lib/types";
import type { Confirm, Session } from "../hooks/useSession";
import { Dissection } from "./Dissection";
import { VerdictBadge } from "./Verdict";

const wholeNumber = (v: string) => /^\d+$/.test(v.trim());

// A live Compound proposal: validators read its first action and its
// description from Ethereum mainnet.
const EXAMPLE = { proposalId: "609", actionIndex: "0", createdBlock: "26024021" };

export function FlagForm({
  daos,
  constants,
  session,
  onFlagged,
}: {
  daos: Dao[];
  constants: Constants | null;
  session: Session;
  onFlagged: (incidentId: number) => void;
}) {
  const ids = useId();
  const verified = daos.filter((d) => d.verification === "VERIFIED");
  const [daoId, setDaoId] = useState<number | null>(null);
  const [proposalId, setProposalId] = useState("");
  const [actionIndex, setActionIndex] = useState("0");
  const [createdBlock, setCreatedBlock] = useState("");
  const minBond = BigInt(constants?.MIN_REPORTER_BOND ?? "1000000000000000000");
  const [bondText, setBondText] = useState<string | null>(null);
  // Async results are stored with the input they describe, so edits make them
  // stale by construction instead of needing a reset.
  const [dryFor, setDryFor] = useState<{ key: string; state: "running" | "done" | "error"; result?: DryRun; error?: string } | null>(null);
  const [decodedFor, setDecodedFor] = useState<{ key: string; value: Disassembly | null } | null>(null);

  const dao = verified.find((d) => d.dao_id === daoId) ?? verified[0];
  const bondInput = bondText ?? gen(minBond);
  const bond = parseGen(bondInput);

  const proposalIssue = proposalId && !wholeNumber(proposalId) ? "Use a whole number." : null;
  const actionIssue = actionIndex && !wholeNumber(actionIndex) ? "Use a whole number." : null;
  const blockIssue = createdBlock && (!wholeNumber(createdBlock) || Number(createdBlock) === 0) ? "Use a block number." : null;
  const bondIssue = bond === null ? "Enter an amount in GEN." : bond < minBond ? `The minimum is ${gen(minBond)} GEN.` : null;
  const complete = !!dao && !!proposalId.trim() && !!actionIndex.trim() && !!createdBlock.trim();
  const ready = complete && !proposalIssue && !actionIssue && !blockIssue && !bondIssue;

  const dryKey = `${dao?.dao_id}:${proposalId.trim()}:${actionIndex.trim()}:${createdBlock.trim()}:${bondInput}`;
  const dry = dryFor?.key === dryKey ? dryFor : { state: "idle" as const, result: undefined, error: undefined };
  const fetched = dry.result?.action ?? null;

  // Decode the fetched calldata against the DAO's ABI (a free view call). The
  // preview decoder is strict, so unusual on-chain calldata shows undecoded.
  const decodeKey = dao && fetched ? `${dao.dao_id}:${fetched.calldata}` : null;
  const decoded = decodeKey && decodedFor?.key === decodeKey ? decodedFor.value : null;
  useEffect(() => {
    if (!decodeKey || !dao || !fetched) return;
    let cancelled = false;
    view<Disassembly>("disassemble", [dao.dao_id, fetched.calldata])
      .then((d) => !cancelled && setDecodedFor({ key: decodeKey, value: d }))
      .catch(() => !cancelled && setDecodedFor({ key: decodeKey, value: null }));
    return () => {
      cancelled = true;
    };
  }, [decodeKey, dao, fetched]);

  const args = () => [dao!.dao_id, Number(proposalId.trim()), Number(actionIndex.trim()), Number(createdBlock.trim())];

  // Per-proposal cap: every action of one proposal shares this bounty.
  const bountyCap = BigInt(constants?.MAX_PROPOSAL_BOUNTY ?? constants?.BOUNTY_CRITICAL ?? "5000000000000000000");
  const escrow = BigInt(dao?.bounty_escrow ?? "0");
  const maxBounty = escrow < bountyCap ? escrow : bountyCap;
  const feeBps = constants?.DISMISSAL_FEE_BPS ?? 1000;
  const busy = session.tx !== null && session.tx.phase !== "done" && session.tx.phase !== "error";

  return (
    <section aria-labelledby={`${ids}-title`} className="space-y-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div>
          <h2 id={`${ids}-title`} className="font-display text-2xl font-semibold tracking-tight">Flag a proposal</h2>
          <p className="text-sm text-muted">
            Point at one action of a live proposal. Validators read its calldata and description from the DAO's
            governor on-chain and judge whether the description is honest.
          </p>
        </div>
        <button
          type="button"
          className="text-sm text-sky hover:underline"
          onClick={() => {
            setProposalId(EXAMPLE.proposalId);
            setActionIndex(EXAMPLE.actionIndex);
            setCreatedBlock(EXAMPLE.createdBlock);
          }}
        >
          Fill with a live Compound proposal
        </button>
      </div>

      <form
        className="grid gap-4 lg:grid-cols-2"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!ready || bond === null) return;
          const label = `Flag proposal #${proposalId.trim()} action ${actionIndex.trim()}`;
          const [, pid, aidx] = args();
          const reporter = session.signer?.address;
          // Acceptance alone is not enough: read the incident the call returned
          // back from contract state and check it is this report.
          const confirm: Confirm = async (receipt) => {
            const raw = receipt.returnValue;
            const id = typeof raw === "bigint" || typeof raw === "number" ? Number(raw) : NaN;
            if (!Number.isInteger(id) || id <= 0) throw new Error("Validators accepted the call, but it returned no incident id.");
            const incident = await view<Incident>("get_incident", [id]);
            if (!sameAddress(incident.reporter, reporter) || incident.proposal_id !== pid || incident.action_index !== aidx) {
              throw new Error(`Incident #${id} in contract state does not match this report.`);
            }
            onFlagged(id);
            return {
              text: `Incident #${id} read back from contract state: ${VERDICT_LABEL[incident.classification]}, ${STATUS_LABEL[incident.status].toLowerCase()}.`,
              incidentId: id,
            };
          };
          const ok = await session.run(label, "report_proposal", args(), bond, confirm);
          if (ok) {
            setProposalId("");
            setActionIndex("0");
            setCreatedBlock("");
          }
        }}
      >
        <div className="grid content-start gap-4 sm:grid-cols-2">
          <div className="sm:col-span-2">
            <label htmlFor={`${ids}-dao`} className="text-sm font-semibold">DAO</label>
            <select
              id={`${ids}-dao`}
              className="field mt-1.5"
              value={dao?.dao_id ?? ""}
              onChange={(e) => setDaoId(Number(e.target.value))}
              disabled={verified.length === 0}
            >
              {verified.length === 0 ? <option value="">No verified DAOs registered</option> : null}
              {verified.map((d) => (
                <option key={d.dao_id} value={d.dao_id}>{d.name}</option>
              ))}
            </select>
            <p className="mt-1 text-[12px] text-muted">
              Only DAOs whose timelock admin is their declared governor accept reports.
            </p>
          </div>
          <div>
            <label htmlFor={`${ids}-pid`} className="text-sm font-semibold">Proposal ID</label>
            <input
              id={`${ids}-pid`}
              inputMode="numeric"
              className="field mt-1.5 font-mono"
              placeholder="609"
              value={proposalId}
              aria-invalid={!!proposalIssue}
              onChange={(e) => setProposalId(e.target.value)}
            />
            {proposalIssue ? <p className="mt-1 text-[12px] text-critical">{proposalIssue}</p> : null}
          </div>
          <div>
            <label htmlFor={`${ids}-action`} className="text-sm font-semibold">Action index</label>
            <input
              id={`${ids}-action`}
              inputMode="numeric"
              className="field mt-1.5 font-mono"
              placeholder="0"
              value={actionIndex}
              aria-invalid={!!actionIssue}
              onChange={(e) => setActionIndex(e.target.value)}
            />
            {actionIssue ? <p className="mt-1 text-[12px] text-critical">{actionIssue}</p> : null}
          </div>
          <div className="sm:col-span-2">
            <label htmlFor={`${ids}-block`} className="text-sm font-semibold">Creation block</label>
            <input
              id={`${ids}-block`}
              inputMode="numeric"
              className="field mt-1.5 font-mono"
              placeholder="26024021"
              value={createdBlock}
              aria-invalid={!!blockIssue}
              onChange={(e) => setCreatedBlock(e.target.value)}
            />
            {blockIssue ? <p className="mt-1 text-[12px] text-critical">{blockIssue}</p> : null}
            <p className="mt-1 text-[12px] text-muted">
              The block holding the proposal's ProposalCreated event, shown on the proposal's creation transaction.
            </p>
          </div>
          {fetched ? (
            <div className="glass-card p-4 sm:col-span-2">
              <p className="eyebrow mb-1">Read from the governor</p>
              <p className="font-mono text-[12px] break-all text-muted">
                action {actionIndex.trim()} of {fetched.action_count} · target {fetched.target}
                {fetched.value !== "0" ? ` · sends ${fetched.value} wei` : ""}
                {fetched.signature ? ` · ${fetched.signature}` : ""}
              </p>
            </div>
          ) : null}
        </div>

        <div className="space-y-4">
          <Dissection
            prose={fetched?.description ?? ""}
            decoded={decoded}
            verdict={dry.result?.verdict.classification ?? null}
            compact
          />

          <div className="glass-card p-4 sm:p-5">
            <div className="flex flex-wrap items-end gap-4">
              <div className="w-36">
                <label htmlFor={`${ids}-bond`} className="text-sm font-semibold">Bond (GEN)</label>
                <input
                  id={`${ids}-bond`}
                  inputMode="decimal"
                  className="field mt-1.5 font-mono"
                  value={bondInput}
                  aria-invalid={!!bondIssue}
                  onChange={(e) => setBondText(e.target.value)}
                />
              </div>
              <dl className="grid min-w-[15rem] flex-1 grid-cols-2 gap-x-4 gap-y-1 text-[13px]">
                <dt className="text-muted">If upheld, up to</dt>
                <dd className="text-right font-mono">{bond === null ? "–" : gen(bond + maxBounty)} GEN</dd>
                <dt className="text-muted">If judged aligned</dt>
                <dd className="text-right font-mono">{bond === null ? "–" : gen(bond - (bond * BigInt(feeBps)) / 10000n)} GEN back</dd>
                <dt className="text-muted">If an appeal wins</dt>
                <dd className="text-right font-mono">0 GEN</dd>
              </dl>
            </div>
            {bondIssue ? <p className="mt-2 text-[12px] text-critical">{bondIssue}</p> : null}
            <p className="mt-2 text-[12px] text-muted">
              Minimum bond {gen(minBond)} GEN. The bounty is paid from the DAO's escrow ({gen(escrow, 2)} GEN available), up to{" "}
              {gen(bountyCap)} GEN per proposal across all of its actions. Only proposals that can still execute
              (pending, active, succeeded or queued) are accepted.
            </p>

            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                className="btn btn-quiet"
                disabled={!ready || dry.state === "running"}
                onClick={async () => {
                  if (bond === null) return;
                  const key = dryKey;
                  setDryFor({ key, state: "running" });
                  try {
                    setDryFor({ key, state: "done", result: await dryRunReport(args(), bond) });
                  } catch (err) {
                    setDryFor({ key, state: "error", error: explainError(err instanceof Error ? err.message : String(err)) });
                  }
                }}
              >
                {dry.state === "running" ? "Reading the proposal…" : "Dry run verdict"}
              </button>
              <button type="submit" className="btn btn-primary" disabled={!ready || busy || !session.signer}>
                Flag and post {bond === null ? "" : `${gen(bond)} GEN`} bond
              </button>
              {!session.signer ? (
                <button
                  type="button"
                  className="btn btn-quiet"
                  disabled={busy}
                  onClick={() => {
                    const label = ready ? `Guest: flag proposal #${proposalId.trim()} action ${actionIndex.trim()}` : "Guest: flag a proposal";
                    // With a complete form the leader step runs a real one-validator dry run.
                    const work =
                      ready && bond !== null
                        ? async () => {
                            const r = await dryRunReport(args(), bond);
                            return `Leader dry run verdict: ${VERDICT_LABEL[r.verdict.classification]}. Simulated incident only; nothing was posted on-chain.`;
                          }
                        : undefined;
                    void session.simulate(label, work);
                  }}
                >
                  Walk through consensus (guest)
                </button>
              ) : null}
            </div>
            <p className="mt-2 text-[12px] text-muted" aria-live="polite">
              {!complete
                ? "Fill in every field to run a dry run or flag."
                : !session.signer
                  ? "The dry run is free and needs no wallet. Connect to flag, or walk through the consensus lifecycle as a guest."
                  : "The dry run simulates one validator without posting anything."}
            </p>
          </div>

          {dry.state === "done" && dry.result ? (
            <div className="glass-card p-4 sm:p-5" aria-live="polite">
              <div className="mb-2 flex items-center justify-between gap-2">
                <p className="eyebrow">Dry run result</p>
                <VerdictBadge verdict={dry.result.verdict.classification} />
              </div>
              <p className="text-sm leading-relaxed">{dry.result.verdict.rationale}</p>
              <p className="mt-2 text-[12px] text-muted">
                One simulated validator. The real verdict needs the validator set to agree.
              </p>
            </div>
          ) : dry.state === "error" ? (
            <p role="alert" className="rounded-xl border border-critical/40 bg-critical/10 p-3 text-sm text-critical">
              {dry.error}
            </p>
          ) : null}
        </div>
      </form>
    </section>
  );
}
