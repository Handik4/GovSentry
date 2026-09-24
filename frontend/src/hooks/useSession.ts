import { useCallback, useState } from "react";
import {
  balanceOf,
  connectWallet,
  forgetStudioAccount,
  fundFromFaucet,
  studioAccount,
  view,
  write,
  type Signer,
  type WritePhase,
} from "../lib/genlayer";
import { explainError } from "../lib/copy";

export interface TxState {
  label: string;
  phase: WritePhase | "error";
  hash?: string;
  error?: string;
}

export function useSession(onSettled: () => void) {
  const [signer, setSigner] = useState<Signer | null>(null);
  const [balance, setBalance] = useState<bigint | null>(null);
  const [claimable, setClaimable] = useState<bigint>(0n);
  const [connecting, setConnecting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [tx, setTx] = useState<TxState | null>(null);

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
    setTx({ label: "Requesting test GEN from the Studio faucet", phase: "consensus" });
    try {
      await fundFromFaucet(signer.address);
      setTx({ label: "Added 20 test GEN", phase: "done" });
      await refreshAccount();
    } catch (err) {
      setTx({ label: "Faucet request", phase: "error", error: explainError(String(err)) });
    }
  }, [signer, refreshAccount]);

  /** Run a contract write; resolves true when validators decided it successfully. */
  const run = useCallback(
    async (label: string, method: string, args: Parameters<typeof write>[2], value = 0n): Promise<boolean> => {
      if (!signer) {
        setTx({ label, phase: "error", error: "Connect a wallet or a Studio test account first." });
        return false;
      }
      setTx({ label, phase: "checking" });
      try {
        const res = await write(signer, method, args, value, (phase, hash) => setTx({ label, phase, hash }));
        if (res.execution && res.execution !== "FINISHED_WITH_RETURN") {
          setTx({ label, phase: "error", hash: res.hash, error: "Validators decided the transaction, but it reverted." });
          return false;
        }
        setTx({ label, phase: "done", hash: res.hash });
        return true;
      } catch (err) {
        setTx((t) => ({ label, phase: "error", hash: t?.hash, error: explainError(err instanceof Error ? err.message : String(err)) }));
        return false;
      } finally {
        onSettled();
        void refreshAccount();
      }
    },
    [signer, onSettled, refreshAccount],
  );

  return {
    signer,
    balance,
    claimable,
    connecting,
    connectError,
    tx,
    dismissTx: () => setTx(null),
    connect,
    disconnect,
    fund,
    run,
  };
}

export type Session = ReturnType<typeof useSession>;
