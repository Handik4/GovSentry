/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GOVSENTRY_ADDRESS?: string;
  readonly VITE_GENLAYER_RPC_URL?: string;
  readonly VITE_GENLAYER_EXPLORER_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
