import { useEffect, useRef, useState } from "react";
import { CONFIG, explorerAddress } from "../config";
import { gen, short } from "../lib/format";
import type { Session } from "../hooks/useSession";
import { IconCheck, IconClose, IconCopy, IconExternal, IconMenu, LogoMark } from "./Icons";

export type SectionId = "dashboard" | "daos" | "flag";

const NAV: { id: SectionId; label: string }[] = [
  { id: "dashboard", label: "Dashboard" },
  { id: "daos", label: "Watched DAOs" },
  { id: "flag", label: "Flag Proposal" },
];

function useDismiss(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) close();
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);
  return ref;
}

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex items-center gap-1 text-muted hover:text-sky"
      aria-label={copied ? "Copied" : label}
      title={label}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1400);
        });
      }}
    >
      {copied ? <IconCheck size={15} className="text-aligned" /> : <IconCopy size={15} />}
    </button>
  );
}

function WalletMenu({ session }: { session: Session }) {
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  const { signer } = session;

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        className={signer ? "btn btn-quiet" : "btn btn-primary"}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        disabled={session.connecting}
      >
        {session.connecting ? (
          "Connecting…"
        ) : signer ? (
          <>
            <span className="size-2 rounded-full bg-aligned shadow-[0_0_8px_var(--aligned)]" aria-hidden />
            <span className="font-mono text-[13px]">{short(signer.address)}</span>
          </>
        ) : (
          <>
            <span className="sm:hidden">Connect</span>
            <span className="hidden sm:inline">Connect Wallet</span>
          </>
        )}
      </button>

      {open ? (
        <div role="menu" className="glass-card lift absolute right-0 z-40 mt-3 w-[min(21rem,calc(100vw-2rem))] !bg-slate-950/90 p-3">
          {signer ? (
            <div className="space-y-3">
              <div>
                <p className="eyebrow">{signer.kind === "wallet" ? "Browser wallet" : "Studio test account"}</p>
                <p className="mt-1 break-all font-mono text-[13px]">{signer.address}</p>
              </div>
              <dl className="grid grid-cols-2 gap-2 text-sm">
                <div className="rounded-xl bg-inset p-2.5">
                  <dt className="eyebrow">Balance</dt>
                  <dd className="font-mono">{session.balance === null ? "…" : `${gen(session.balance, 3)} GEN`}</dd>
                </div>
                <div className="rounded-xl bg-inset p-2.5">
                  <dt className="eyebrow">Refunds owed</dt>
                  <dd className="font-mono">{gen(session.claimable, 3)} GEN</dd>
                </div>
              </dl>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={session.claimable === 0n}
                  onClick={() => {
                    setOpen(false);
                    void session.run(`Withdraw ${gen(session.claimable)} GEN`, "withdraw", []);
                  }}
                >
                  Withdraw refunds
                </button>
                <button type="button" className="btn btn-quiet" onClick={() => void session.fund()}>
                  Get test GEN
                </button>
              </div>
              <div className="flex justify-between border-t border-rule pt-2 text-sm">
                <button
                  type="button"
                  className="text-muted hover:text-ink"
                  onClick={() => {
                    session.disconnect();
                    setOpen(false);
                  }}
                >
                  Disconnect
                </button>
                {signer.kind === "studio" ? (
                  <button
                    type="button"
                    className="text-muted hover:text-critical"
                    onClick={() => {
                      session.disconnect(true);
                      setOpen(false);
                    }}
                  >
                    Forget test account
                  </button>
                ) : null}
              </div>
            </div>
          ) : (
            <div className="space-y-1">
              {(
                [
                  ["wallet", "Browser wallet", `MetaMask or any injected wallet. ${CONFIG.networkName} is added if needed.`],
                  ["studio", "Studio test account", "A key kept in this browser, funded from the Studio faucet. Test network only."],
                ] as const
              ).map(([kind, title, body]) => (
                <button
                  key={kind}
                  type="button"
                  role="menuitem"
                  className="w-full rounded-xl p-3 text-left transition-colors hover:bg-sky-500/10"
                  onClick={() => {
                    setOpen(false);
                    void session.connect(kind);
                  }}
                >
                  <span className="block font-semibold">{title}</span>
                  <span className="block text-[13px] text-muted">{body}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}

export function Header({
  session,
  online,
  active,
  onAbout,
}: {
  session: Session;
  online: boolean | null;
  active: SectionId;
  onAbout: () => void;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useDismiss(menuOpen, () => setMenuOpen(false));

  const navLink = (id: SectionId, label: string, stacked = false) => (
    <a
      key={id}
      href={`#${id}`}
      aria-current={active === id ? "location" : undefined}
      onClick={() => setMenuOpen(false)}
      className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${stacked ? "block" : ""} ${
        active === id ? "bg-sky-500/15 text-sky shadow-[inset_0_0_0_1px_rgba(56,189,248,0.3)]" : "text-muted hover:text-ink"
      }`}
    >
      {label}
    </a>
  );
  const aboutLink = (stacked = false) => (
    <button
      type="button"
      onClick={() => {
        setMenuOpen(false);
        onAbout();
      }}
      className={`rounded-lg px-3 py-1.5 text-left text-sm font-medium text-muted transition-colors hover:text-ink ${stacked ? "block w-full" : ""}`}
    >
      How it Works
    </button>
  );

  return (
    <header className="sticky top-0 z-30 border-b border-rule bg-slate-950/70 backdrop-blur-xl">
      <div className="mx-auto flex max-w-[1320px] items-center gap-4 px-4 py-3 sm:px-6">
        <a href="#dashboard" className="flex items-center gap-3">
          <LogoMark />
          <span className="flex flex-col leading-none sm:flex-row sm:items-center sm:gap-2.5">
            <span className="brand-gradient font-display text-[22px] font-bold tracking-tight">GovSentry</span>
            <span className="mt-1 w-fit whitespace-nowrap rounded-full border border-sky-400/30 bg-sky-400/10 px-2 py-0.5 font-mono text-[9px] uppercase tracking-[0.08em] text-sky sm:mt-0 sm:text-[10px] sm:tracking-[0.12em]">
              Autonomous Interceptor
            </span>
          </span>
        </a>

        <nav aria-label="Primary" className="ml-4 hidden items-center gap-1 lg:flex">
          {NAV.map((n) => navLink(n.id, n.label))}
          {aboutLink()}
        </nav>

        <div className="ml-auto hidden items-center gap-2 xl:flex">
          <span className="pill">
            <span
              aria-hidden
              className={`size-2 rounded-full ${
                online === null ? "bg-muted" : online ? "bg-aligned live-dot shadow-[0_0_10px_var(--aligned)]" : "bg-critical"
              }`}
            />
            <span className="font-medium">{CONFIG.networkName}</span>
            <span className="sr-only">{online === false ? "RPC unreachable" : "RPC reachable"}</span>
          </span>
          <span className="pill">
            <a
              className="inline-flex items-center gap-1.5 font-mono text-[12.5px] hover:text-sky"
              href={explorerAddress(CONFIG.address)}
              target="_blank"
              rel="noreferrer"
              title="Open the contract in the explorer"
            >
              {short(CONFIG.address)}
              <IconExternal size={13} />
            </a>
            <CopyButton value={CONFIG.address} label="Copy contract address" />
          </span>
        </div>

        <div className="ml-auto flex items-center gap-2 xl:ml-0">
          <WalletMenu session={session} />
          <div ref={menuRef} className="relative lg:hidden">
            <button
              type="button"
              className="btn btn-quiet !px-2.5"
              aria-label={menuOpen ? "Close menu" : "Open menu"}
              aria-expanded={menuOpen}
              onClick={() => setMenuOpen((o) => !o)}
            >
              {menuOpen ? <IconClose /> : <IconMenu />}
            </button>
            {menuOpen ? (
              <div className="glass-card lift absolute right-0 z-40 mt-3 w-64 !bg-slate-950/90 p-2">
                <nav aria-label="Primary" className="space-y-0.5">
                  {NAV.map((n) => navLink(n.id, n.label, true))}
                  {aboutLink(true)}
                </nav>
                <div className="mt-2 space-y-2 border-t border-rule p-2 text-[13px]">
                  <p className="flex items-center gap-2">
                    <span aria-hidden className={`size-2 rounded-full ${online ? "bg-aligned" : "bg-muted"}`} />
                    {CONFIG.networkName} · chain {CONFIG.chainId}
                  </p>
                  <p className="flex items-center gap-2">
                    <a className="font-mono text-sky" href={explorerAddress(CONFIG.address)} target="_blank" rel="noreferrer">
                      {short(CONFIG.address)} ↗
                    </a>
                    <CopyButton value={CONFIG.address} label="Copy contract address" />
                  </p>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
      {session.connectError ? (
        <p role="alert" className="mx-auto max-w-[1320px] px-4 pb-3 text-sm text-critical sm:px-6">
          {session.connectError}
        </p>
      ) : null}
    </header>
  );
}
