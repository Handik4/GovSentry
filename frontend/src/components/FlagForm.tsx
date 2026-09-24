import { useEffect, useId, useState } from "react";
import { dryRunFlag, view } from "../lib/genlayer";
import { explainError } from "../lib/copy";
import { gen, parseGen } from "../lib/format";
import type { Constants, Dao, Disassembly, Verdict } from "../lib/types";
import type { Session } from "../hooks/useSession";
import { Dissection } from "./Dissection";
import { VerdictBadge } from "./Verdict";

// Mirrors the contract's own checks so problems show before any call is made.
function calldataProblem(raw: string): string | null {
  const d = raw.trim().toLowerCase();
  if (!d) return null;
  if (!d.startsWith("0x")) return "Start with 0x.";
  const body = d.slice(2);
  if (!/^[0-9a-f]*$/.test(body)) return "Use hex characters only.";
  if (body.length < 8) return "Include the 4-byte function selector (8 hex characters).";
  if ((body.length - 8) % 64 !== 0) return "Arguments must be whole 32-byte words (64 hex characters each).";
  if (body.startsWith("00000000")) return "The selector cannot be 0x00000000.";
  if (body.length > 8192) return "Calldata is longer than 8192 hex characters.";
  return null;
}

function addressProblem(raw: string): string | null {
  const a = raw.trim().toLowerCase();
  if (!a) return null;
  if (!/^0x[0-9a-f]{40}$/.test(a)) return "Use a 0x address with 40 hex characters.";
  if (/^0x0{40}$/.test(a)) return "The zero address cannot be a target.";
  return null;
}

const EXAMPLE = {
  proposalId: "332",
  target: "0x6d903f6003cca6255D85CcA4D3B5E5146dC33925",
  calldata: "0xb71d1a0c0000000000000000000000004e6f746865722d61646d696e2d6b6579000000c0",
  prose: "Reserve housekeeping: sweep dust balances from deprecated cToken markets into the community treasury. No admin or parameter changes.",
};

export function FlagForm({
  daos,
  constants,
  session,
  onFlagged,
}: {
  daos: Dao[];
  constants: Constants | null;
  session: Session;
  onFlagged: () => void;
}) {
  const ids = useId();
  const [daoId, setDaoId] = useState<number | null>(null);
  const [proposalId, setProposalId] = useState("");
  const [target, setTarget] = useState("");
  const [calldata, setCalldata] = useState("");
  const [prose, setProse] = useState("");
  const minBond = BigInt(constants?.MIN_REPORTER_BOND ?? "1000000000000000000");
  const [bondText, setBondText] = useState<string | null>(null);
  // Async results are stored with the input they describe, so edits make them
  // stale by construction instead of needing a reset.
  const [decodedFor, setDecodedFor] = useState<{ key: string; value: Disassembly | null } | null>(null);
  const [dryFor, setDryFor] = useState<{ key: string; state: "running" | "done" | "error"; verdict?: Verdict; error?: string } | null>(null);

  const dao = daos.find((d) => d.dao_id === daoId) ?? daos[0];
  const bondInput = bondText ?? gen(minBond);
  const bond = parseGen(bondInput);

  const calldataIssue = calldataProblem(calldata);
  const targetIssue = addressProblem(target);
  const proposalIssue = proposalId && !/^\d+$/.test(proposalId.trim()) ? "Use a whole number." : null;
  const bondIssue = bond === null ? "Enter an amount in GEN." : bond < minBond ? `The minimum is ${gen(minBond)} GEN.` : null;
  const complete = !!dao && !!proposalId.trim() && !!target.trim() && !!calldata.trim() && !!prose.trim();
  const ready = complete && !calldataIssue && !targetIssue && !proposalIssue && !bondIssue;

  const decodeKey = dao && calldata.trim() && !calldataIssue ? `${dao.dao_id}:${calldata.trim()}` : null;
  const decoded = decodeKey && decodedFor?.key === decodeKey ? decodedFor.value : null;
  const dryKey = `${dao?.dao_id}:${proposalId.trim()}:${target.trim()}:${calldata.trim()}:${prose.trim()}:${bondInput}`;
  const dry = dryFor?.key === dryKey ? dryFor : { state: "idle" as const, verdict: undefined, error: undefined };

  // Decode the calldata against the DAO's verified ABI as it is typed (a free view call).
  useEffect(() => {
    if (!decodeKey || !dao) return;
    let cancelled = false;
    const t = window.setTimeout(() => {
      view<Disassembly>("disassemble", [dao.dao_id, calldata.trim()])
        .then((d) => !cancelled && setDecodedFor({ key: decodeKey, value: d }))
        .catch(() => !cancelled && setDecodedFor({ key: decodeKey, value: null }));
    }, 350);
    return () => {
      cancelled = true;
      window.clearTimeout(t);
    };
  }, [decodeKey, dao, calldata]);

  const args = () => [dao!.dao_id, Number(proposalId.trim()), target.trim(), calldata.trim(), prose.trim()];

  const bountyCap = BigInt(constants?.BOUNTY_CRITICAL ?? "5000000000000000000");
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
            Paste what a proposal executes and what it claims to do. Validators judge whether the description is honest.
          </p>
        </div>
        <button
          type="button"
          className="text-sm text-sky hover:underline"
          onClick={() => {
            setProposalId(EXAMPLE.proposalId);
            setTarget(EXAMPLE.target);
            setCalldata(EXAMPLE.calldata);
            setProse(EXAMPLE.prose);
          }}
        >
          Fill with an example
        </button>
      </div>

      <form
        className="grid gap-4 lg:grid-cols-2"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!ready || bond === null) return;
          const ok = await session.run(`Flag proposal #${proposalId.trim()}`, "flag_proposal", args(), bond);
          if (ok) {
            onFlagged();
            setProposalId("");
            setCalldata("");
            setProse("");
          }
        }}
      >
        <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
          <div>
            <label htmlFor={`${ids}-dao`} className="text-sm font-semibold">DAO</label>
            <select
              id={`${ids}-dao`}
              className="field mt-1.5"
              value={dao?.dao_id ?? ""}
              onChange={(e) => setDaoId(Number(e.target.value))}
              disabled={daos.length === 0}
            >
              {daos.length === 0 ? <option value="">No DAOs registered</option> : null}
              {daos.map((d) => (
                <option key={d.dao_id} value={d.dao_id}>{d.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor={`${ids}-pid`} className="text-sm font-semibold">Proposal ID</label>
            <input
              id={`${ids}-pid`}
              inputMode="numeric"
              className="field mt-1.5 font-mono"
              placeholder="331"
              value={proposalId}
              aria-invalid={!!proposalIssue}
              onChange={(e) => setProposalId(e.target.value)}
            />
            {proposalIssue ? <p className="mt-1 text-[12px] text-critical">{proposalIssue}</p> : null}
          </div>
          <div className="sm:col-span-2">
            <label htmlFor={`${ids}-target`} className="text-sm font-semibold">Target contract</label>
            <input
              id={`${ids}-target`}
              className="field mt-1.5 font-mono text-[13px]"
              placeholder="0x…"
              spellCheck={false}
              value={target}
              aria-invalid={!!targetIssue}
              onChange={(e) => setTarget(e.target.value)}
            />
            {targetIssue ? <p className="mt-1 text-[12px] text-critical">{targetIssue}</p> : null}
          </div>
          <div className="sm:col-span-2">
            <label htmlFor={`${ids}-calldata`} className="text-sm font-semibold">Raw calldata</label>
            <textarea
              id={`${ids}-calldata`}
              rows={3}
              className="field mt-1.5 font-mono text-[13px]"
              placeholder="0xf2fde38b000000000000000000000000…"
              spellCheck={false}
              value={calldata}
              aria-invalid={!!calldataIssue}
              onChange={(e) => setCalldata(e.target.value)}
            />
            {calldataIssue ? <p className="mt-1 text-[12px] text-critical">{calldataIssue}</p> : null}
          </div>
          <div className="sm:col-span-2">
            <label htmlFor={`${ids}-prose`} className="text-sm font-semibold">Proposal description</label>
            <textarea
              id={`${ids}-prose`}
              rows={4}
              className="field mt-1.5"
              placeholder="Paste the description voters were shown."
              value={prose}
              maxLength={6000}
              onChange={(e) => setProse(e.target.value)}
            />
          </div>
        </div>

        <div className="space-y-4">
          <Dissection prose={prose} decoded={decoded} verdict={dry.verdict?.classification ?? null} compact />

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
              {gen(bountyCap)} GEN for a critical payload.
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
                    setDryFor({ key, state: "done", verdict: await dryRunFlag(args(), bond) });
                  } catch (err) {
                    setDryFor({ key, state: "error", error: explainError(err instanceof Error ? err.message : String(err)) });
                  }
                }}
              >
                {dry.state === "running" ? "Asking the model…" : "Dry run verdict"}
              </button>
              <button type="submit" className="btn btn-primary" disabled={!ready || busy || !session.signer}>
                Flag and post {bond === null ? "" : `${gen(bond)} GEN`} bond
              </button>
            </div>
            <p className="mt-2 text-[12px] text-muted" aria-live="polite">
              {!complete
                ? "Fill in every field to run a dry run or flag."
                : !session.signer
                  ? "The dry run is free and needs no wallet. Connect to flag."
                  : "The dry run simulates one validator without posting anything."}
            </p>
          </div>

          {dry.state === "done" && dry.verdict ? (
            <div className="glass-card p-4 sm:p-5" aria-live="polite">
              <div className="mb-2 flex items-center justify-between gap-2">
                <p className="eyebrow">Dry run result</p>
                <VerdictBadge verdict={dry.verdict.classification} />
              </div>
              <p className="text-sm leading-relaxed">{dry.verdict.rationale}</p>
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
