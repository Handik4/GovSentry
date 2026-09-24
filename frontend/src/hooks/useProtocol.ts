import { useCallback, useEffect, useRef, useState } from "react";
import { CONFIG } from "../config";
import { view } from "../lib/genlayer";
import type { Constants, Dao, Incident, Ledger } from "../lib/types";

export interface ProtocolState {
  constants: Constants | null;
  ledger: Ledger | null;
  daos: Dao[];
  incidents: Incident[];
  loading: boolean;
  error: string | null;
  updatedAt: number | null;
  /** RPC health measured by this dashboard during the session. */
  health: { attempts: number; successes: number; latencyMs: number | null; failStreak: number };
}

const PAGE = 50;

async function pages<T>(method: string, count: number): Promise<T[]> {
  const out: T[] = [];
  for (let start = 1; start <= count; start += PAGE) {
    out.push(...(await view<T[]>(method, [start, PAGE])));
  }
  return out;
}

export function useProtocol() {
  const [state, setState] = useState<ProtocolState>({
    constants: null,
    ledger: null,
    daos: [],
    incidents: [],
    loading: true,
    error: null,
    updatedAt: null,
    health: { attempts: 0, successes: 0, latencyMs: null, failStreak: 0 },
  });
  const inflight = useRef(false);

  const refresh = useCallback(async () => {
    if (inflight.current) return;
    inflight.current = true;
    const started = performance.now();
    try {
      const [constants, ledger, counts] = await Promise.all([
        view<Constants>("get_constants"),
        view<Ledger>("get_ledger"),
        view<{ dao_count: number; incident_count: number }>("get_counts"),
      ]);
      const [daos, incidents] = await Promise.all([
        pages<Dao>("list_daos", counts.dao_count),
        pages<Incident>("list_incidents", counts.incident_count),
      ]);
      const latencyMs = Math.round(performance.now() - started);
      setState((s) => ({
        constants,
        ledger,
        daos,
        incidents: incidents.sort((a, b) => b.incident_id - a.incident_id),
        loading: false,
        error: null,
        updatedAt: Date.now(),
        health: { attempts: s.health.attempts + 1, successes: s.health.successes + 1, latencyMs, failStreak: 0 },
      }));
    } catch (err) {
      setState((s) => ({
        ...s,
        health: { ...s.health, attempts: s.health.attempts + 1, failStreak: s.health.failStreak + 1 },
        loading: false,
        error: err instanceof Error ? err.message.split("\n")[0] : String(err),
      }));
    } finally {
      inflight.current = false;
    }
  }, []);

  // Poll the contract: once immediately, then on an interval while visible.
  useEffect(() => {
    const first = window.setTimeout(() => void refresh(), 0);
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh();
    }, CONFIG.pollMs);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(id);
    };
  }, [refresh]);

  return { ...state, refresh };
}
