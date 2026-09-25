import { useCallback, useEffect, useState } from "react";
import { AboutModal } from "./components/AboutModal";
import { DaoDirectory } from "./components/DaoDirectory";
import { FlagForm } from "./components/FlagForm";
import { Footer } from "./components/Footer";
import { Header, type SectionId } from "./components/Header";
import { IncidentDossier } from "./components/IncidentDossier";
import { StatsBar } from "./components/StatsBar";
import { TriageFeed } from "./components/TriageFeed";
import { TxToast } from "./components/TxToast";
import { CONFIG } from "./config";
import { useNow } from "./hooks/useNow";
import { useProtocol } from "./hooks/useProtocol";
import { useSession } from "./hooks/useSession";

const SECTIONS: SectionId[] = ["dashboard", "daos", "flag"];

/** Highlight the nav link for whichever section sits under the header. */
function useActiveSection(): SectionId {
  const [active, setActive] = useState<SectionId>("dashboard");
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id as SectionId);
      },
      { rootMargin: "-96px 0px -55% 0px" },
    );
    SECTIONS.forEach((id) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, []);
  return active;
}

export default function App() {
  const protocol = useProtocol();
  const { refresh } = protocol;
  const now = useNow();
  const onSettled = useCallback(() => refresh(), [refresh]);
  const session = useSession(onSettled);
  const [selected, setSelected] = useState<number | null>(null);
  // `#about` deep-links straight to the About dialog.
  const [aboutOpen, setAboutOpen] = useState(() => window.location.hash === "#about");
  const active = useActiveSection();

  // Follow the newest incident until the reader picks one.
  const current = protocol.incidents.find((i) => i.incident_id === selected) ?? protocol.incidents[0] ?? null;

  const { dismissTx, tx } = session;
  useEffect(() => {
    // Only the faucet toast clears itself; consensus receipts stay until dismissed.
    if (tx?.phase !== "done" || !tx.plain) return;
    const t = window.setTimeout(dismissTx, 6000);
    return () => window.clearTimeout(t);
  }, [tx, dismissTx]);

  // One failed poll over good data is a blip, not an outage: raise the alarm
  // only when nothing has loaded yet or reads keep failing.
  const degraded = !!protocol.error && (!protocol.updatedAt || protocol.health.failStreak >= 2);
  const online = degraded ? false : protocol.updatedAt ? true : null;
  const openAbout = () => setAboutOpen(true);

  return (
    <>
      <div className="ambient" aria-hidden />
      <a href="#dashboard" className="btn btn-primary sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50">
        Skip to content
      </a>
      <Header session={session} online={online} active={active} onAbout={openAbout} />

      <main className="mx-auto max-w-[1320px] px-4 sm:px-6">
        <section id="dashboard" aria-labelledby="dashboard-title" className="space-y-8 pt-8 sm:pt-10">
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="max-w-2xl">
              <p className="eyebrow flex items-center gap-2 !text-sky">
                <span aria-hidden className="size-1.5 rounded-full bg-sky live-dot" />
                Live on {CONFIG.networkName}
              </p>
              <h1 id="dashboard-title" className="mt-2 font-display text-3xl font-bold tracking-tight sm:text-[2.6rem] sm:leading-[1.1]">
                Every proposal, checked against <span className="brand-gradient">what it actually executes</span>
              </h1>
            </div>
            <button type="button" onClick={openAbout} className="btn btn-quiet">
              How it works
            </button>
          </div>

          {degraded ? (
            <p role="alert" className="rounded-xl border border-critical/40 bg-critical/10 p-3 text-sm text-critical">
              Could not read the contract: {protocol.error}. Retrying every 15 seconds.
            </p>
          ) : null}

          <StatsBar
            daos={protocol.daos}
            incidents={protocol.incidents}
            ledger={protocol.ledger}
            health={protocol.health}
            loading={protocol.loading}
          />

          <div className="grid gap-6 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
            <aside className="min-w-0 lg:sticky lg:top-24 lg:max-h-[calc(100dvh-7rem)] lg:self-start lg:overflow-y-auto lg:pb-2 lg:pr-1">
              <TriageFeed
                incidents={protocol.incidents}
                daos={protocol.daos}
                selected={current?.incident_id ?? null}
                onSelect={setSelected}
                now={now}
                window={protocol.constants?.CHALLENGE_WINDOW ?? 86400}
                loading={protocol.loading}
              />
            </aside>

            <div className="min-w-0">
              {current ? (
                <IncidentDossier
                  incident={current}
                  dao={protocol.daos.find((d) => d.dao_id === current.dao_id)}
                  constants={protocol.constants}
                  session={session}
                  now={now}
                />
              ) : (
                <div className="glass-card border-dashed p-10 text-center text-muted">
                  {protocol.loading ? "Reading incidents from the contract…" : "No incidents yet. Flag a proposal to open the first one."}
                </div>
              )}
            </div>
          </div>
        </section>

        <section id="daos" className="pt-16">
          <DaoDirectory daos={protocol.daos} incidents={protocol.incidents} loading={protocol.loading} />
        </section>

        <section id="flag" className="pt-16">
          <div className="glass-card glow p-5 sm:p-7">
            <div className="relative">
              <FlagForm daos={protocol.daos} constants={protocol.constants} session={session} onFlagged={setSelected} />
            </div>
          </div>
        </section>
      </main>

      <Footer daos={protocol.daos} onAbout={openAbout} />
      <AboutModal
        open={aboutOpen}
        onClose={() => {
          setAboutOpen(false);
          if (window.location.hash === "#about") history.replaceState(null, "", window.location.pathname + window.location.search);
        }}
        constants={protocol.constants}
      />
      <TxToast tx={session.tx} onDismiss={session.dismissTx} />
    </>
  );
}
