// Deployment defaults mirror deployments/studio.json so a fresh checkout
// renders live data without a .env file. Override any of them via VITE_* vars.
export const CONFIG = {
  address: (import.meta.env.VITE_GOVSENTRY_ADDRESS ?? "0x173a18540D6bCC8c59589F182AE10F71781c9E93") as `0x${string}`,
  rpcUrl: import.meta.env.VITE_GENLAYER_RPC_URL ?? "https://studio-next.genlayer.com/api",
  explorerUrl: (import.meta.env.VITE_GENLAYER_EXPLORER_URL ?? "https://explorer-studio-next.genlayer.com").replace(/\/$/, ""),
  chainId: 61997,
  networkName: "Studio Next",
  pollMs: 15_000,
} as const;

export const explorerAddress = (a: string) => `${CONFIG.explorerUrl}/address/${a}`;
export const explorerTx = (h: string) => `${CONFIG.explorerUrl}/tx/${h}`;
