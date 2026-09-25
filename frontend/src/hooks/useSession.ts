import { useCallback, useRef, useState } from "react";
import {
  awaitFinality,
  balanceOf,
  ConsensusError,
  connectWallet,
  forgetStudioAccount,
  fundFromFaucet,
  studioAccount,
  view,
  write,
  type ConsensusProgress,
  type ConsensusReceipt,
  type Signer,
  type WritePhase,
} from "../lib/genlayer";
import { explainError } from "../lib/copy";

export interface TxState {
  label: string;
  phase: WritePhase | "error";
  /** The phase that was running when an error ended the flow. */
  failedAt?: WritePhase;
  hash?: string;
  progress?: ConsensusProgress;
  receipt?: ConsensusReceipt;
  /** What the post-consensus contract read proved, e.g. "Incident #7 recorded on-chain". */
  confirmation?: string;
  incidentId?: number;
  error?: string;
  /** A guest walkthrough: nothing was signed or posted. */
  simulated?: boolean;
  /** A single-step request (the faucet) with no consensus lifecycle. */
  plain?: boolean;
}

/** Proves the transaction's effect by reading contract state after acceptance. */
export type Confirm = (receipt: ConsensusReceipt) => Promise<{ text: string; incidentId?: number }>;

const RECEIPTS_KEY = "govsentry.incident-receipts";

function loadReceipts(): Record<number, ConsensusReceipt> {
  try {
    return JSON.parse(localStorage.getItem(RECEIPTS_KEY) ?? "{}") as Record<number, ConsensusReceipt>;
  } catch {
    return {};
  }
}

function saveReceipts(r: Record<number, ConsensusReceipt>) {
  try {
    localStorage.setItem(RECEIPTS_KEY, JSON.stringify(r, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
  } catch {
    /* receipts stay in memory for this tab */
  }
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function useSession(onSettled: () => Promise<void>) {
  const [signer, setSigner] = useState<Signer | null>(null);
  const [balance, setBalance] = useState<bigint | null>(null);
  const [claimable, setClaimable] = useState<bigint>(0n);
  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [tx, setTx] = useState<TxState | null>(null);
  const [receipts, setReceipts] = useState<Record<number, ConsensusReceipt>>(loadReceipts);
  // Guards late updates (finality, simulation ticks) from landing on a newer flow.
  const flow = useRef(0);

  const refreshAccount = useCallback(async (s: Signer | null = signer) => {
    if (!s) return;
    const [bal, owed] = await Promise.all([
      balanceOf(s.address).catch(() => null),
      view<string>("get_claimable", [s.address]).catch(() => "0"),
    ]);
    setBalance(bal);
    setClaimable(BigInt(owed || "0"));
  }, [signer]);

  const connect = useCallback(async (kind: "wallet" | "studio") => {
    setConnecting(true);
    setConnectError(null);
    try {
      const s = kind === "wallet" ? await connectWallet() : studioAccount();
      setSigner(s);
      await refreshAccount(s);
    } catch (err) {
      setConnectError(explainError(err instanceof Error ? err.message : String(err)));
    } finally {
      setConnecting(false);
    }
  }, [refreshAccount]);

  const disconnect = useCallback((forget = false) => {
    if (forget) forgetStudioAccount();
    setSigner(null);
    setBalance(null);
    setClaimable(0n);
  }, []);

  const fund = useCallback(async () => {
    if (!signer) return;
    flow.current++;
    setTx({ label: "Requesting test GEN from the Studio faucet", phase: "consensus", plain: true });
    try {
      await fundFromFaucet(signer.address);
      setTx({ label: "Added 20 test GEN", phase: "done", plain: true });
      await refreshAccount();
    } catch (err) {
      setTx({ label: "Faucet request", phase: "error", plain: true, error: explainError(String(err)) });
    }
  }, [signer, refreshAccount]);

  const rememberReceipt = useCallback((incidentId: number, receipt: ConsensusReceipt) => {
    setReceipts((prev) => {
      const next = { ...prev, [incidentId]: receipt };
      saveReceipts(next);
      return next;
    });
  }, []);

  /**
   * Run a contract write through its full lifecycle: pre-flight, signature,
   * broadcast, validator consensus, then a contract read that proves the
   * effect. Resolves with the receipt only when all of that succeeded.
   */
  const run = useCallback(
    async (
      label: string,
      method: string,
      args: Parameters<typeof write>[2],
      value = 0n,
      confirm?: Confirm,
    ): Promise<ConsensusReceipt | null> => {
      const id = ++flow.current;
      if (!signer) {
        setTx({ label, phase: "error", failedAt: "checking", error: "Connect a wallet or a Studio test account first." });
        return null;
      }
      let current: TxState = { label, phase: "checking" };
      const update = (patch: Partial<TxState>) => {
        current = { ...current, ...patch };
        if (flow.current === id) setTx(current);
      };
      update({});
      try {
        const receipt = await write(signer, method, args, value, (phase, hash, progress) =>
          update({ phase, hash: hash ?? current.hash, progress: progress ?? current.progress }),
        );
        update({ phase: "confirming", receipt });
        const confirmed = confirm ? await confirm(receipt) : (await onSettled(), { text: "Contract state re-read after acceptance." });
        if (confirmed.incidentId !== undefined) rememberReceipt(confirmed.incidentId, receipt);
        update({ phase: "done", confirmation: confirmed.text, incidentId: confirmed.incidentId });

        // Accepted is decided; follow it through the appeal window to finality.
        if (receipt.status === "ACCEPTED") {
          void awaitFinality(receipt.hash).then((final) => {
            if (!final) return;
            if (confirmed.incidentId !== undefined) rememberReceipt(confirmed.incidentId, final);
            update({ receipt: final });
          });
        }
        return receipt;
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        update({
          phase: "error",
          failedAt: current.phase === "error" ? current.failedAt : current.phase,
          receipt: err instanceof ConsensusError ? err.receipt : current.receipt,
          error: err instanceof ConsensusError ? message : explainError(message),
        });
        return null;
      } finally {
        void onSettled();
        void refreshAccount();
      }
    },
    [signer, onSettled, refreshAccount, rememberReceipt],
  );

  /**
   * Guest walkthrough of the same lifecycle with nothing signed or posted.
   * `work` runs during the leader step, e.g. a real single-validator dry run,
   * and returns a line to show in the result.
   */
  const simulate = useCallback(async (label: string, work?: () => Promise<string>) => {
    const id = ++flow.current;
    let current: TxState = { label, phase: "checking", simulated: true };
    const update = (patch: Partial<TxState>) => {
      current = { ...current, ...patch };
      if (flow.current === id) setTx(current);
    };
    const live = () => flow.current === id;
    const votes = (agree: number, idle: number) => ({ agree, disagree: 0, timeout: 0, idle, total: 5 });
    try {
      update({});
      await wait(900);
      if (!live()) return;
      update({ phase: "broadcast" });
      await wait(1200);
      update({ phase: "consensus", progress: { status: "PROPOSING", votes: null } });
      const [outcome] = await Promise.all([work ? work() : Promise.resolve(null), wait(1800)]);
      if (!live()) return;
      update({ progress: { status: "COMMITTING", votes: votes(0, 5) } });
      await wait(1400);
      update({ progress: { status: "REVEALING", votes: votes(2, 3) } });
      await wait(1200);
      update({ progress: { status: "REVEALING", votes: votes(4, 1) } });
      await wait(900);
      const now = Math.floor(Date.now() / 1000);
      const receipt: ConsensusReceipt = {
        hash: "0x",
        status: "ACCEPTED",
        consensus: "MAJORITY_AGREE",
        execution: "FINISHED_WITH_RETURN",
        votes: votes(4, 1),
        decidedAt: now,
        finalizedAt: null,
        appealDeadline: now + 30,
        decisionId: null,
        block: null,
        returnValue: null,
        failure: null,
      };
      update({ phase: "confirming", receipt, progress: { status: "ACCEPTED", votes: receipt.votes } });
      await wait(1200);
      update({ phase: "done", confirmation: outcome ?? "Simulated incident recorded. Nothing was posted on-chain." });
    } catch (err) {
      update({
        phase: "error",
        failedAt: current.phase === "error" ? current.failedAt : current.phase,
        error: explainError(err instanceof Error ? err.message : String(err)),
      });
    }
  }, []);

  return {
    signer,
    balance,
    claimable,
    connecting,
    connectError,
    tx,
    receipts,
    dismissTx: () => {
      flow.current++;
      setTx(null);
    },
    connect,
    disconnect,
    fund,
    run,
    simulate,
  };
}

export type Session = ReturnType<typeof useSession>;
