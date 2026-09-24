import { explorerTx } from "../config";
import type { TxState } from "../hooks/useSession";

const PHASE_TEXT = {
  checking: "Checking the call against current contract state…",
  signing: "Waiting for your signature…",
  consensus: "Validators are reaching consensus…",
  done: "Done.",
  error: "",
} as const;

export function TxToast({ tx, onDismiss }: { tx: TxState | null; onDismiss: () => void }) {
  if (!tx) return null;
  const tone =
    tx.phase === "error" ? "border-critical" : tx.phase === "done" ? "border-aligned" : "border-sky";
  return (
    <div
      role={tx.phase === "error" ? "alert" : "status"}
      className={`fixed inset-x-4 bottom-4 z-40 mx-auto max-w-md glass-card lift !bg-slate-950/90 border-l-4 ${tone} p-4 shadow-2xl shadow-black/40 sm:inset-x-auto sm:right-6`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-semibold">{tx.label}</p>
          <p className={`text-sm ${tx.phase === "error" ? "text-critical" : "text-muted"}`}>
            {tx.phase === "error" ? tx.error : PHASE_TEXT[tx.phase]}
          </p>
          {tx.hash ? (
            <a className="mt-1 inline-block font-mono text-[12px] text-sky hover:underline" href={explorerTx(tx.hash)} target="_blank" rel="noreferrer">
              View transaction ↗
            </a>
          ) : null}
        </div>
        {tx.phase === "done" || tx.phase === "error" ? (
          <button type="button" onClick={onDismiss} className="text-muted hover:text-ink" aria-label="Dismiss">
            ✕
          </button>
        ) : (
          <span aria-hidden className="mt-1 size-2.5 shrink-0 rounded-full bg-sky live-dot" />
        )}
      </div>
    </div>
  );
}
