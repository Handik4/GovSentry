import { abi, chains, createAccount, createClient, generatePrivateKey } from "genlayer-js";
import { CONFIG } from "../config";
import type { Verdict } from "./types";

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

export type WritePhase = "checking" | "signing" | "consensus" | "done";

export interface WriteResult {
  hash: Hex;
  execution: string | undefined;
}

/**
 * Pre-flight the call as a simulation so reverts surface with the contract's
 * own reason before anything is signed, then submit with a fee distribution
 * estimated from the network's live fee policy and wait for a decision.
 */
export async function write(
  signer: Signer,
  functionName: string,
  args: CallArg[],
  value: bigint,
  onPhase: (p: WritePhase, hash?: Hex) => void,
): Promise<WriteResult> {
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

  onPhase("consensus", hash);
  const receipt = (await signer.client.waitForTransactionReceipt({
    hash: hash as Parameters<Client["waitForTransactionReceipt"]>[0]["hash"],
    waitUntil: "decided",
    interval: 3000,
    retries: 200,
  })) as { txExecutionResultName?: string };
  onPhase("done", hash);
  return { hash, execution: receipt.txExecutionResultName };
}

// ------------------------------------------------------------- dry run

function toPlain(v: unknown): unknown {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, toPlain(x)]));
  return v;
}

/**
 * Run flag_proposal as a leader-only simulation and read the LLM verdict from
 * the non-deterministic block's output. Nothing is signed or stored.
 */
export async function dryRunFlag(args: CallArg[], value: bigint): Promise<Verdict> {
  let result: { receipt?: Record<string, unknown> };
  try {
    result = (await readClient().simulateWriteContract({
      address: CONFIG.address,
      functionName: "flag_proposal",
      args,
      value,
      includeReceipt: true,
    })) as { receipt?: Record<string, unknown> };
  } catch (err) {
    throw new Error(revertReason(err));
  }
  const outputs = result.receipt?.eq_outputs as Record<string, string> | undefined;
  const first = outputs?.["0"];
  if (!first) throw new Error("The simulation returned no verdict.");
  const bytes = base64Bytes(first);
  if (bytes[0] !== 0) throw new Error(decoder.decode(bytes.slice(1)));
  const decoded = toPlain(abi.calldata.decode(bytes.slice(1))) as Partial<Verdict>;
  if (!decoded.classification) throw new Error("The simulation returned an unreadable verdict.");
  return { classification: decoded.classification, rationale: String(decoded.rationale ?? "") };
}
