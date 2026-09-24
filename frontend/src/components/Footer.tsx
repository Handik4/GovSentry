import { CONFIG, explorerAddress } from "../config";
import { short } from "../lib/format";
import type { Dao } from "../lib/types";
import { CopyButton } from "./Header";
import { IconExternal, IconGithub, LogoMark } from "./Icons";

const REPO = "https://github.com/Handik4/GovSentry";
const LINK = "inline-flex items-center gap-1.5 text-muted transition-colors hover:text-sky";

export function Footer({ daos, onAbout }: { daos: Dao[]; onAbout: () => void }) {
  const firstDao = daos[0];
  return (
    <footer className="mt-16 border-t border-rule bg-slate-950/60 backdrop-blur-xl">
      <div className="mx-auto grid max-w-[1320px] gap-10 px-4 py-10 sm:px-6 md:grid-cols-[1.3fr_1fr_1fr]">
        <div>
          <div className="flex items-center gap-3">
            <LogoMark size={34} />
            <span className="brand-gradient font-display text-xl font-bold tracking-tight">GovSentry</span>
          </div>
          <p className="mt-3 max-w-sm text-[14px] leading-relaxed text-muted">
            Autonomous Governance Firewall natively powered by GenLayer GenVM. Deceptive proposals are decoded, judged
            by validator consensus, and put on the public record before the timelock runs.
          </p>
          <button type="button" onClick={onAbout} className="mt-3 text-[13px] text-sky hover:underline">
            How GovSentry works
          </button>
        </div>

        <nav aria-label="Explorer and contract">
          <p className="eyebrow mb-3">On-chain</p>
          <ul className="space-y-2 text-[13.5px]">
            <li>
              <a className={LINK} href={CONFIG.explorerUrl} target="_blank" rel="noreferrer">
                {CONFIG.networkName} Explorer <IconExternal size={13} />
              </a>
            </li>
            <li className="flex items-center gap-2">
              <a className={LINK} href={explorerAddress(CONFIG.address)} target="_blank" rel="noreferrer">
                Contract <span className="font-mono text-ink/80">{short(CONFIG.address)}</span> <IconExternal size={13} />
              </a>
              <CopyButton value={CONFIG.address} label="Copy contract address" />
            </li>
            {firstDao ? (
              <li>
                <a
                  className={LINK}
                  href={`https://etherscan.io/address/${firstDao.target_timelock}`}
                  target="_blank"
                  rel="noreferrer"
                  title={`${firstDao.name} on Etherscan`}
                >
                  Timelock specs <span className="font-mono text-ink/80">{short(firstDao.target_timelock)}</span>{" "}
                  <IconExternal size={13} />
                </a>
              </li>
            ) : null}
            <li className="font-mono text-[12px] text-muted">
              chain {CONFIG.chainId} · {CONFIG.rpcUrl.replace(/^https?:\/\//, "")}
            </li>
          </ul>
        </nav>

        <nav aria-label="Project">
          <p className="eyebrow mb-3">Project</p>
          <ul className="space-y-2 text-[13.5px]">
            <li>
              <a className={LINK} href={REPO} target="_blank" rel="noreferrer">
                <IconGithub size={16} /> Handik4/GovSentry
              </a>
            </li>
            <li>
              <a className={LINK} href="https://docs.genlayer.com" target="_blank" rel="noreferrer">
                GenLayer Studio Docs <IconExternal size={13} />
              </a>
            </li>
            <li>
              <a
                href={`${REPO}/blob/main/LICENSE`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex overflow-hidden rounded-md border border-sky-400/30 font-mono text-[11px] transition-colors hover:border-sky-400/60"
              >
                <span className="bg-slate-800 px-2 py-0.5 text-muted">license</span>
                <span className="bg-sky-500/20 px-2 py-0.5 text-sky">MIT · 2026 Handik4</span>
              </a>
            </li>
          </ul>
        </nav>
      </div>
      <div className="border-t border-rule">
        <p className="mx-auto max-w-[1320px] px-4 py-4 text-center text-[12px] tracking-wide text-muted sm:px-6">
          Built for GenLayer Ecosystem <span aria-hidden className="mx-1.5 text-sky">•</span> Zero Discretion Governance
          Security <span className="mx-1.5 text-slate-600">·</span> {CONFIG.networkName} is a test network
        </p>
      </div>
    </footer>
  );
}
