# GovSentry

GovSentry is an autonomous interceptor for malicious DAO governance proposals,
built as a GenLayer intelligent contract on GenVM.

It takes a cross-chain governance proposal, disassembles the proposal's
execution calldata, and uses validator-consensus LLM reasoning to check whether
the proposal's description truthfully represents what the bytecode will do. It
is designed to catch hidden minting, unauthorized ownership transfers, stealth
upgrades, and treasury drains before they execute.

## Live deployment

GovSentry is deployed to **GenLayer Studio Next** (chain `61997`):

| | |
| --- | --- |
| Contract | [`0x23e4Ccd46b851E00eb28e2f9974A34Cfa78257B5`](https://explorer-studio-next.genlayer.com/address/0x23e4Ccd46b851E00eb28e2f9974A34Cfa78257B5) |
| Deploy tx | [`0x292725cd…04096`](https://explorer-studio-next.genlayer.com/tx/0x292725cd0bc6fbb63f56dabeb952d7ab6349389da861b5991e7a92534db04096) |
| RPC | `https://studio-next.genlayer.com/api` |
| Bootstrap DAO | #1 Compound Governance Timelock (`0x6d903f60…dC33925`), 7 verified selectors, 10 GEN test bounty escrow |

Every deployment and bootstrap transaction reached `finalized` with
`MAJORITY_AGREE`. Hashes and explorer links are recorded in
[`deployments/studio.json`](deployments/studio.json).

## How it works

1. A DAO sponsor calls `register_dao(target_timelock, name, description_url)`
   and can attach GEN to seed a bounty escrow. `register_selectors` adds the
   DAO's verified ABI.
2. A reporter calls `flag_proposal(dao_id, proposal_id, target_contract,
   raw_calldata, prose_description)` with at least **1 GEN** bond. The contract
   validates the calldata strictly, decodes the selector and its arguments, and
   runs an LLM alignment check under validator consensus. The result is one of:
   - `ALIGNED`: the flag is dismissed and 90% of the bond is refunded via
     `expire_incident`.
   - `SUSPICIOUS_OMISSION` or `CRITICAL_MALICIOUS_PAYLOAD`: the bounty is
     reserved and the incident is locked for a **24h** challenge window.
3. Anyone can call `file_appeal(incident_id, direct_rebuttal_proof)` with at
   least **2 GEN**. The rebuttal must quote the incident's `calldata_hash`,
   which binds the evidence to that incident.
4. `resolve_appeal(incident_id)` asks the validators to rule on the rebuttal:
   `UPHELD`, `REJECTED`, or `INCONCLUSIVE`.
5. `claim_payout(incident_id)` pays the reporter their bond plus the bounty,
   plus any award from a rejected appeal. It works only after the window
   closes, and reverts with `ERR_CHALLENGE_WINDOW_ACTIVE` if called early.
6. `expire_incident(incident_id)` settles dismissed, inconclusive, and stalled
   incidents fairly. Refunds are collected with `withdraw()`.

The contract stays solvent at all times:

```
total_deposited == total_bonded + total_claimable + total_slashed
```

See [`specs/architecture.md`](specs/architecture.md) for the full design,
settlement matrix, and threat model.

## Layout

```
contracts/gov_sentry.py                 intelligent contract
tests/direct/                           direct-mode test suites (lifecycle, adversarial)
scripts/deploy.py                       deploy and record in deployments/studio.json
scripts/bootstrap.py                    register the bootstrap DAO, selectors and escrow
deployments/studio.json                 live deployment record
frontend/                               Vite + React + Tailwind dashboard
specs/architecture.md                   architecture specification
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

genvm-lint check contracts/gov_sentry.py   # lint and SDK validation
pytest tests/direct/                        # direct-mode tests (no network)
```

## Deployment

Put the deployer key in a local `.env`, which is gitignored:

```bash
echo "GENLAYER_PRIVATE_KEY=0x..." > .env
python scripts/deploy.py --network studio_next --fund   # --fund tops up from the Studio faucet
python scripts/bootstrap.py                             # register DAO #1, selectors, escrow
python scripts/bootstrap.py --demo-incident             # optional: file one demo flag
```

Studio Next requires an explicit fee distribution on each transaction. Both
scripts estimate it from the network's live fee policy. The deployer becomes the
contract owner. The owner's only privilege is sweeping the slashed treasury.

## Frontend

```bash
cd frontend
cp .env.example .env    # optional: the defaults already point at the live contract
npm install
npm run dev             # http://localhost:5173
npm run build           # type-check and production bundle in dist/
```

The dashboard reads the contract directly over GenLayer RPC, with no backend.
It has:

- **Triage feed:** every flagged proposal with its verdict, decoded function and
  live challenge-window countdown.
- **Dissection:** the proposal description set against the decoded calldata,
  with the validators' reasoning.
- **Lifecycle panel:** a calldata-bound appeal form, a request for a validator
  ruling, a payout claim (enabled once the window closes) and a
  close-and-refund action.
- **Flag form:** live selector decoding against the DAO's verified ABI, bond and
  payout math, and a free **dry run** that returns a real LLM verdict from a
  leader-only simulation without posting anything.
- **Wallets:** any injected wallet (Studio Next is added automatically), or a
  **Studio test account**, a browser-held key funded from the Studio faucet,
  for trying the full flow without MetaMask.

Every write is first simulated, so a revert shows the contract's own reason
(for example `ERR_CHALLENGE_WINDOW_ACTIVE`) before anything is signed.

## License

MIT © 2026 Handik4
# GovSentry
