import { abi, chains, createAccount, createClient, generatePrivateKey } from "genlayer-js";
import { CONFIG } from "../config";
import type { DryRun, FetchedAction, Verdict } from "./types";

type Client = ReturnType<typeof createClient>;
type Hex = `0x${string}`;
type CallArg = Parameters<Client["readContract"]>[0]["args"] extends (infer A)[] | undefined ? A : never;

export interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on?(event: string, handler: (...args: unknown[]) => void): void;
  removeListener?(event: string, handler: (...args: unknown[]) => void): void;
}

declare global {
  interface Window {
    ethereum?: Eip1193;
  }
}

/** Studio Next is chain 61997; genlayer-js ships it as `studioDevnet`. */
export const chain = {
  ...chains.studioDevnet,
  name: `GenLayer ${CONFIG.networkName}`,
  rpcUrls: { default: { http: [CONFIG.rpcUrl] } },
  blockExplorers: { default: { name: "GenLayer Explorer", url: CONFIG.explorerUrl } },
};

// ---------------------------------------------------------------- reads

let reader: Client | null = null;
function readClient(): Client {
  // Views go through `gen_call` and need no signer; a throwaway account keeps
  // simulations (dry runs) working before any wallet is connected.
  reader ??= createClient({ chain, account: createAccount() });
  return reader;
}

export async function view<T>(functionName: string, args: CallArg[] = []): Promise<T> {
  const out = await readClient().readContract({
    address: CONFIG.address,
    functionName,
    args,
    jsonSafeReturn: true,
  });
  return out as T;
}

// -------------------------------------------------------------- errors

const decoder = new TextDecoder();

function base64Bytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Pull the contract's own revert message out of a failed simulation. GenLayer
 * returns the leader receipt under `cause.data.receipt.result`: one status byte
 * (0x01 = user error) followed by the UTF-8 message.
 */
export function revertReason(err: unknown): string {
  let e: unknown = err;
  for (let depth = 0; e && depth < 6; depth++) {
    const receipt = (e as { data?: { receipt?: { result?: string } } }).data?.receipt;
    if (receipt?.result) {
      const bytes = base64Bytes(receipt.result);
      if (bytes[0] === 1 || bytes[0] === 2) return decoder.decode(bytes.slice(1));
    }
    e = (e as { cause?: unknown }).cause;
  }
  if (err instanceof Error) return err.message.split("\n")[0];
  return String(err);
}

// ------------------------------------------------------------- signers

export type SignerKind = "wallet" | "studio";

export interface Signer {
  kind: SignerKind;
  address: Hex;
  client: Client;
}

const STUDIO_KEY_STORAGE = "govsentry.studio-account";
const CHAIN_HEX = `0x${CONFIG.chainId.toString(16)}`;

export async function connectWallet(): Promise<Signer> {
  const eth = window.ethereum;
  if (!eth) throw new Error("No browser wallet found. Install MetaMask, or use a Studio test account.");
  const accounts = (await eth.request({ method: "eth_requestAccounts" })) as string[];
  if (!accounts?.length) throw new Error("The wallet did not share an account.");
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_HEX }] });
  } catch (err) {
    if ((err as { code?: number }).code !== 4902) throw err;
    await eth.request({
      method: "wallet_addEthereumChain",
      params: [
        {
          chainId: CHAIN_HEX,
          chainName: chain.name,
          nativeCurrency: chain.nativeCurrency,
          rpcUrls: [CONFIG.rpcUrl],
          blockExplorerUrls: [CONFIG.explorerUrl],
        },
      ],
    });
  }
  const address = accounts[0] as Hex;
  const client = createClient({
    chain,
    account: address,
    provider: eth as unknown as NonNullable<Parameters<typeof createClient>[0]>["provider"],
  });
  return { kind: "wallet", address, client };
}

/**
 * A key held in this browser for Studio Next only. Studio is a test network
 * with a faucet, so this lets anyone exercise the full lifecycle without a
 * browser wallet. Never use it on a network with real value.
 */
export function studioAccount(): Signer {
  let key: string | null = null;
  try {
    key = localStorage.getItem(STUDIO_KEY_STORAGE);
  } catch {
    /* storage blocked: fall through to an ephemeral key */
  }
  if (!key) {
    key = generatePrivateKey();
    try {
      localStorage.setItem(STUDIO_KEY_STORAGE, key);
    } catch {
      /* ephemeral for this tab */
    }
  }
  const account = createAccount(key as Hex);
  return { kind: "studio", address: account.address, client: createClient({ chain, account }) };
}

export function forgetStudioAccount(): void {
  try {
    localStorage.removeItem(STUDIO_KEY_STORAGE);
  } catch {
    /* nothing stored */
  }
}

export async function fundFromFaucet(address: Hex, genAmount = 20): Promise<void> {
  await readClient().request({
    method: "sim_fundAccount",
    params: [address, genAmount * 1e18],
  });
}

export async function balanceOf(address: Hex): Promise<bigint> {
  const res = await fetch(CONFIG.rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getBalance", params: [address, "latest"] }),
  });
  const json = (await res.json()) as { result?: string };
  return json.result ? BigInt(json.result) : 0n;
}

// -------------------------------------------------------------- writes

export type WritePhase = "checking" | "signing" | "broadcast" | "consensus" | "confirming" | "done";

export interface VoteTally {
  agree: number;
  disagree: number;
  timeout: number;
  idle: number;
  total: number;
}

/** Live view of a transaction while validators work on it. */
export interface ConsensusProgress {
  status: string;
  votes: VoteTally | null;
}

/** The canonical record of a decided transaction, as the network stores it. */
export interface ConsensusReceipt {
  hash: Hex;
  /** Stored lifecycle status: ACCEPTED, FINALIZED, UNDETERMINED, … */
  status: string;
  /** Round result, e.g. MAJORITY_AGREE. */
  consensus: string | null;
  /** GenVM execution result, e.g. FINISHED_WITH_RETURN. */
  execution: string | null;
  votes: VoteTally | null;
  /** Unix seconds when validators materialized the decision. */
  decidedAt: number | null;
  /** Unix seconds when the appeal window closed and the decision became final. */
  finalizedAt: number | null;
  appealDeadline: number | null;
  decisionId: number | null;
  /** Null on Studio networks, which order transactions without blocks. */
  block: number | null;
  returnValue: unknown;
  /** The validators' own reason when the transaction did not succeed. */
  failure: string | null;
}

export class ConsensusError extends Error {
  readonly receipt: ConsensusReceipt;
  constructor(message: string, receipt: ConsensusReceipt) {
    super(message);
    this.receipt = receipt;
  }
}

// Numeric status codes, in protocol order.
const STATUS_NAMES = [
  "UNINITIALIZED", "PENDING", "PROPOSING", "COMMITTING", "REVEALING", "ACCEPTED", "UNDETERMINED",
  "FINALIZED", "CANCELED", "APPEAL_REVEALING", "APPEAL_COMMITTING", "VALIDATORS_TIMEOUT", "LEADER_TIMEOUT",
  "LEADER_REVEALING",
];
const DECIDED = new Set(["ACCEPTED", "FINALIZED", "UNDETERMINED", "CANCELED", "VALIDATORS_TIMEOUT", "LEADER_TIMEOUT"]);
const AGREED = new Set(["ACCEPTED", "FINALIZED"]);

const STATUS_FAILURE: Record<string, string> = {
  UNDETERMINED: "Validators could not reach a majority on the leader's result, so nothing was committed.",
  LEADER_TIMEOUT: "The leader validator timed out before proposing a result.",
  VALIDATORS_TIMEOUT: "Too many validators timed out before voting.",
  CANCELED: "The transaction was canceled before consensus.",
};
const RESULT_FAILURE: Record<string, string> = {
  MAJORITY_DISAGREE: "A majority of validators disagreed with the leader's result.",
  NO_MAJORITY: "Validators split with no majority.",
  MAJORITY_TIMEOUT: "A majority of validators timed out.",
  DETERMINISTIC_VIOLATION: "Validators detected a deterministic violation in the leader's execution.",
};

type RawTx = Record<string, unknown> & {
  status?: string | number;
  result_name?: string;
  txExecutionResultName?: string;
  last_vote_timestamp?: string | number;
  last_round?: { validator_votes_name?: string[] };
  consensus_data?: {
    votes?: Record<string, string>;
    leader_receipt?: { result?: string; genvm_result?: { error_description?: string | null; stderr?: string } }[];
  };
  consensus_history?: {
    latestDecision?: { decisionId?: number; appealDeadline?: number; materializedAt?: number } | null;
    consensus_results?: { monitoring?: Record<string, number> }[];
  };
};

async function rpc<T>(method: string, params: unknown[]): Promise<T> {
  const res = await fetch(CONFIG.rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const json = (await res.json()) as { result?: T; error?: { message?: string } };
  if (json.error) throw new Error(json.error.message ?? `${method} failed`);
  return json.result as T;
}

function statusName(raw: RawTx): string {
  const s = raw.status;
  if (typeof s === "number") return STATUS_NAMES[s] ?? String(s);
  if (s === "ACTIVATED") return "PENDING";
  return s ?? "PENDING";
}

function tally(raw: RawTx): VoteTally | null {
  const names = raw.last_round?.validator_votes_name ?? Object.values(raw.consensus_data?.votes ?? {});
  if (!names.length) return null;
  const t: VoteTally = { agree: 0, disagree: 0, timeout: 0, idle: 0, total: names.length };
  for (const n of names.map((x) => x.toLowerCase())) {
    if (n === "agree" || n === "finished_with_return") t.agree++;
    else if (n === "timeout") t.timeout++;
    else if (n === "idle" || n === "not_voted") t.idle++;
    else t.disagree++;
  }
  return t;
}

const seconds = (v: unknown) => (v === undefined || v === null || v === "" ? null : Math.floor(Number(v)));

/** Decode the leader's result: a status byte (0 = return, 1/2 = error) then the payload. */
function leaderResult(raw: RawTx): { value?: unknown; error?: string } {
  const receipt = raw.consensus_data?.leader_receipt?.[0];
  if (!receipt?.result) return {};
  const bytes = base64Bytes(receipt.result);
  if (bytes[0] === 0) {
    try {
      return { value: toPlain(abi.calldata.decode(bytes.slice(1))) };
    } catch {
      return {};
    }
  }
  const msg = decoder.decode(bytes.slice(1)) || receipt.genvm_result?.error_description || receipt.genvm_result?.stderr;
  return { error: msg || undefined };
}

async function blockNumber(hash: Hex): Promise<number | null> {
  try {
    const r = await rpc<{ blockNumber?: string } | null>("eth_getTransactionReceipt", [hash]);
    const n = r?.blockNumber ? Number(BigInt(r.blockNumber)) : 0;
    return n > 0 ? n : null;
  } catch {
    return null;
  }
}

async function readReceipt(hash: Hex, raw: RawTx): Promise<ConsensusReceipt> {
  const status = statusName(raw);
  const decision = raw.consensus_history?.latestDecision ?? null;
  const results = raw.consensus_history?.consensus_results ?? [];
  const monitoring = results[results.length - 1]?.monitoring ?? {};
  const consensus = raw.result_name ?? null;
  const execution = raw.txExecutionResultName ?? null;
  const leader = leaderResult(raw);

  let failure: string | null = null;
  if (!AGREED.has(status)) failure = STATUS_FAILURE[status] ?? `Consensus ended in ${status}.`;
  else if (consensus && RESULT_FAILURE[consensus]) failure = RESULT_FAILURE[consensus];
  else if (execution && execution !== "FINISHED_WITH_RETURN") failure = leader.error ?? `GenVM execution ended with ${execution}.`;
  if (failure && leader.error && !failure.includes(leader.error)) failure = `${failure} Leader reported: ${leader.error}`;

  return {
    hash,
    status,
    consensus,
    execution,
    votes: tally(raw),
    decidedAt: seconds(decision?.materializedAt ?? monitoring.ACCEPTED ?? raw.last_vote_timestamp),
    finalizedAt: status === "FINALIZED" ? seconds(monitoring.FINALIZED ?? decision?.appealDeadline) : null,
    appealDeadline: seconds(decision?.appealDeadline),
    decisionId: decision?.decisionId ?? null,
    block: await blockNumber(hash),
    returnValue: leader.value,
    failure,
  };
}

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Poll the stored transaction until validators decide it, reporting every
 * status change on the way. Resolves with the canonical receipt; it never
 * treats submission alone as success.
 */
export async function awaitConsensus(
  hash: Hex,
  onProgress: (p: ConsensusProgress) => void,
  { interval = 2500, timeoutMs = 10 * 60_000 } = {},
): Promise<ConsensusReceipt> {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    const raw = await rpc<RawTx | null>("eth_getTransactionByHash", [hash]).catch(() => null);
    if (raw) {
      const status = statusName(raw);
      const votes = tally(raw);
      const key = `${status}:${votes ? `${votes.agree}/${votes.disagree}/${votes.timeout}` : ""}`;
      if (key !== last) {
        last = key;
        onProgress({ status, votes });
      }
      if (DECIDED.has(status)) return readReceipt(hash, raw);
    }
    await pause(interval);
  }
  throw new Error("Validators have not decided this transaction after 10 minutes. It may still settle; check the explorer.");
}

/** After acceptance, follow the transaction until its appeal window closes and it is final. */
export async function awaitFinality(hash: Hex, { interval = 5000, timeoutMs = 5 * 60_000 } = {}): Promise<ConsensusReceipt | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const raw = await rpc<RawTx | null>("eth_getTransactionByHash", [hash]).catch(() => null);
    if (raw && statusName(raw) !== "ACCEPTED") return readReceipt(hash, raw);
    await pause(interval);
  }
  return null;
}

/**
 * Pre-flight the call as a simulation so reverts surface with the contract's
 * own reason before anything is signed, then submit with a fee distribution
 * estimated from the network's live fee policy and follow it through
 * consensus. Throws ConsensusError unless validators accepted a successful
 * execution.
 */
export async function write(
  signer: Signer,
  functionName: string,
  args: CallArg[],
  value: bigint,
  onPhase: (p: WritePhase, hash?: Hex, progress?: ConsensusProgress) => void,
): Promise<ConsensusReceipt> {
  onPhase("checking");
  try {
    await signer.client.simulateWriteContract({ address: CONFIG.address, functionName, args, value });
  } catch (err) {
    throw new Error(revertReason(err));
  }

  onPhase("signing");
  const fees = await signer.client.estimateTransactionFees();
  const hash = (await signer.client.writeContract({
    address: CONFIG.address,
    functionName,
    args,
    value,
    fees,
  })) as Hex;

  onPhase("broadcast", hash);
  const receipt = await awaitConsensus(hash, (p) => onPhase("consensus", hash, p));
  if (receipt.failure) throw new ConsensusError(receipt.failure, receipt);
  return receipt;
}

// ------------------------------------------------------------- dry run

function toPlain(v: unknown): unknown {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, toPlain(x)]));
  return v;
}

/**
 * Run report_proposal as a leader-only simulation. Its non-deterministic
 * blocks run in order: first the on-chain proposal read, then the LLM
 * verdict. Both outputs are decoded so the form can show what validators
 * fetched from the governor. Nothing is signed or stored.
 */
export async function dryRunReport(args: CallArg[], value: bigint): Promise<DryRun> {
  let result: { receipt?: Record<string, unknown> };
  try {
    result = (await readClient().simulateWriteContract({
      address: CONFIG.address,
      functionName: "report_proposal",
      args,
      value,
      includeReceipt: true,
    })) as { receipt?: Record<string, unknown> };
  } catch (err) {
    throw new Error(revertReason(err));
  }
  const outputs = (result.receipt?.eq_outputs ?? {}) as Record<string, string>;
  let verdict: Verdict | null = null;
  let action: FetchedAction | null = null;
  for (const key of Object.keys(outputs).sort((a, b) => Number(a) - Number(b))) {
    const bytes = base64Bytes(outputs[key]);
    if (bytes[0] !== 0) throw new Error(decoder.decode(bytes.slice(1)));
    const decoded = toPlain(abi.calldata.decode(bytes.slice(1))) as Record<string, unknown>;
    if (typeof decoded.classification === "string") {
      verdict = { classification: decoded.classification as Verdict["classification"], rationale: String(decoded.rationale ?? "") };
    } else if (typeof decoded.calldata === "string") {
      action = {
        target: String(decoded.target),
        value: String(decoded.value),
        signature: String(decoded.signature ?? ""),
        calldata: decoded.calldata,
        description: String(decoded.description ?? ""),
        action_count: Number(decoded.action_count ?? 0),
      };
    }
  }
  if (!verdict) throw new Error("The simulation returned no verdict.");
  return { verdict, action };
}
