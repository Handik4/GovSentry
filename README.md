# GovSentry

GovSentry is an autonomous interceptor for malicious DAO governance proposals,
built as a GenLayer intelligent contract on GenVM (v0.3.0).

It reads a live governance proposal straight from the DAO's governor on its own
chain, disassembles the calldata the timelock will execute, and uses
validator-consensus LLM reasoning to check whether the proposal's on-chain
description truthfully represents what that calldata does. It is designed to
catch hidden minting, unauthorized ownership transfers, stealth upgrades, and
treasury drains before they execute.

**What "interceptor" means.** GovSentry is an on-chain automated
firewall/oracle. It does not execute, queue, or cancel anything on the DAO's
chain itself. It emits consensus threat verdicts (`SUSPICIOUS_OMISSION`,
`CRITICAL_MALICIOUS_PAYLOAD`) with a bonded challenge window. A DAO Guardian,
an emergency pause module, or a veto-capable multisig consumes those verdicts
and blocks the proposal before its timelock ETA.

## Live deployment

GovSentry is deployed to **GenLayer Studio Next** (chain `61997`):

| | |
| --- | --- |
| Contract | [`0x173a18540D6bCC8c59589F182AE10F71781c9E93`](https://explorer-studio-next.genlayer.com/address/0x173a18540D6bCC8c59589F182AE10F71781c9E93) (v0.3.0) |
| Deploy tx | [`0x533b74ee…d11dc6`](https://explorer-studio-next.genlayer.com/tx/0x533b74ee3eed038f34345b06a336c344ec11cb29571d334add1f68492ad11dc6) |
| RPC | `https://studio-next.genlayer.com/api` |
| Chain 1 RPC (curated) | `https://rpc.mevblocker.io` |
| Bootstrap DAO | #1 Compound Governance Timelock (`0x6d903f60…dC33925`), governor `0x309a862b…04c8c0`, **VERIFIED** (timelock `admin()` read through web consensus), 8 preimage-checked selectors, 10 GEN test bounty escrow |
| Demo incident | Compound proposal 609 (Active), action 0, read from mainnet: [`SUSPICIOUS_OMISSION`](https://explorer-studio-next.genlayer.com/tx/0x4f25c2de3019058527fbb0b81b0ae5e4c490d703f46f3e14bc900fbb584846ff) |

Every deployment and bootstrap transaction reached `finalized` with
`MAJORITY_AGREE`. Hashes and explorer links are recorded in
[`deployments/studio.json`](deployments/studio.json). Earlier deployments
(`0x23e4Ccd4…8257B5`, which accepted reporter-supplied calldata, and
`0xc5129C89…867bd8`, which lacked the lifecycle check and per-funder escrow)
should no longer be used.

## How it works

1. The owner curates one JSON-RPC endpoint per chain with
   `set_chain_rpc(chain_id, rpc_url)`. DAOs choose a chain, never an endpoint.
2. A DAO sponsor calls `register_dao(target_timelock, governor, chain_id, name,
   description_url)` and can attach GEN to seed a bounty escrow. Validators
   read the timelock's `admin()` through web consensus: the DAO is `VERIFIED`
   only if it is the declared governor, otherwise `UNVERIFIED_REGISTRAR`.
   `register_selectors` adds the DAO's ABI; every entry must be a true
   keccak256 preimage of its selector, and well-known privileged selectors can
   never be remapped.
3. A reporter calls `report_proposal(dao_id, proposal_id, action_index,
   created_block)` with at least **1 GEN** bond, against a `VERIFIED` DAO.
   Validators fetch that action and the proposal description from chain (see
   below), decode the selector and its arguments, and run an LLM alignment
   check under validator consensus. The result is one of:
   - `ALIGNED`: the flag is dismissed and 90% of the bond is refunded via
     `expire_incident`.
   - `SUSPICIOUS_OMISSION` or `CRITICAL_MALICIOUS_PAYLOAD`: the bounty is
     reserved and the incident is locked for a **24h** challenge window.
4. Anyone can call `file_appeal(incident_id, direct_rebuttal_proof)` with at
   least **2 GEN**. The rebuttal must quote the incident's `calldata_hash`,
   which binds the evidence to that incident.
5. `resolve_appeal(incident_id)` asks the validators to rule on the rebuttal:
   `UPHELD`, `REJECTED`, or `INCONCLUSIVE`.
6. `claim_payout(incident_id)` pays the reporter their bond plus the bounty,
   plus any award from a rejected appeal. It works only after the window
   closes, and reverts with `ERR_CHALLENGE_WINDOW_ACTIVE` if called early.
7. `expire_incident(incident_id)` settles dismissed, inconclusive, and stalled
   incidents fairly. Refunds are collected with `withdraw()`.
8. Anyone can fund a DAO's escrow with `fund_bounty_escrow(dao_id)` and owns
   only their own position (pool shares, so paid bounties are borne pro rata).
   A funder withdraws their whole position with
   `withdraw_bounty_escrow(dao_id)` only after their own
   `request_escrow_closure(dao_id)` has run for **14 days** and none of the
   DAO's incidents is unresolved. The registrant has no claim on other funders'
   money.
9. The bounty reserved across all actions of one proposal is capped at
   `MAX_PROPOSAL_BOUNTY` (**5 GEN**), so splitting a hijack over several actions
   does not multiply the payout.

### Web consensus verification pipeline

Nothing the verdict depends on comes from the reporter:

```
report_proposal(dao_id, proposal_id, action_index, created_block)
  -> one JSON-RPC batch to the curated endpoint for the DAO's chain:
       eth_call   governor.getActions(id)        GovernorBravo
       eth_call   governor.proposalDetails(id)   OpenZeppelin GovernorStorage
       eth_getLogs ProposalCreated in created_block, from the governor only
       eth_call   governor.state(id)             must be Pending, Active,
                                                 Succeeded or Queued
  -> stored actions are authoritative; the event must match them exactly,
     and (OpenZeppelin) keccak256(description) must equal descriptionHash
  -> Bravo actions are reassembled as keccak(signature)[:4] + args,
     exactly as the timelock will call them
  -> validators re-fetch and must return an identical normalized result
```

Errors are classified so consensus stays sound: chain answers such as
`ERR_PROPOSAL_NOT_FOUND` or `ERR_PROPOSAL_MISMATCH` (`[EXTERNAL]`) must match
exactly between leader and validators, two transient RPC failures
(`[TRANSIENT] ERR_RPC_UNAVAILABLE`) agree and revert, anything else disagrees.

### Security review (v0.3.0)

| Finding | Fix | Regression test |
| --- | --- | --- |
| Critical: fabricated proposal drain | Action and description fetched from the governor via web consensus; `flag_proposal` removed | `test_fake_proposal_id_fails_verification` and siblings |
| Critical: selector spoofing | `keccak256(signature)[:4] == selector` (`ERR_INVALID_SELECTOR_PREIMAGE`); well-known selectors immutable (`ERR_IMMUTABLE_SELECTOR`) | `test_spoofed_selector_registration_reverts` |
| High: single-action DoS | Deduplication on `dao_id:proposal_id:action_index` | `test_multi_action_reports_are_independent` |
| High: third-party registration | Timelock `admin()` resolved on-chain; `VERIFIED` vs `UNVERIFIED_REGISTRAR`; unverified DAOs cannot be reported against or squat a timelock | `test_timelock_admin_resolution_flags_unverified_dao` |
| High: escrow rug | 14-day `request_escrow_closure` notice; withdrawal blocked while incidents are unresolved | `test_instant_escrow_withdrawal_reverts_without_closure_notice` |
| Historical / executed proposal exploitation | Governor `state()` read in the same batch; only Pending (0), Active (1), Succeeded (4) and Queued (5) are reportable, anything else or a reverting `state()` fails closed with `ERR_PROPOSAL_NOT_ACTIONABLE` | `test_executed_proposal_rejected_by_state_check` |
| Escrow hijacking | Per-funder escrow positions (`escrow_ledger`, pool shares per `dao_id:epoch:funder`) and per-funder closure notices | `test_funder_escrow_isolation` |
| Bounty multiplication on multi-action proposals | `awarded_bounty_per_proposal` caps reserved plus paid bounty per proposal at 5 GEN; overturned reservations free the cap | `test_multi_action_bounty_cap` |

All of them live in [`tests/direct/test_review_poc.py`](tests/direct/test_review_poc.py).

### Residual risks

- **Curated RPC trust.** Every validator reads the same owner-chosen endpoint,
  so a compromised or lying endpoint could feed all of them the same false
  proposal. Mitigations: owner-only curation, cross-checks between the event
  and stored actions (and `descriptionHash` on OpenZeppelin governors). Using
  several independent endpoints per chain is future work.
- **Public RPC availability.** Free endpoints rate-limit or block validator
  egress (Blast's public endpoint returned 503 for `eth_getLogs` during the
  bootstrap). Failures revert as `[TRANSIENT]`, and the owner can repoint the
  chain with `set_chain_rpc`, but a keyed provider is advisable in production.
- **Governor coverage.** GovernorBravo and OpenZeppelin `GovernorStorage` are
  supported. Governors that expose neither `getActions` nor `proposalDetails`
  cannot be reported against yet.
- **Unknown selectors.** Calls the DAO has not registered are marked
  privileged, which pushes models toward harsher verdicts; on the live
  Compound demo validators refused to agree until the DAO's `setVersion`
  selector was registered. Sponsors should register their full ABI.
- **Verification means "admin is the governor", not "the registrant is the
  DAO".** A third party can still sponsor a correctly paired DAO; it only
  risks its own escrow, and cannot pair a real timelock with a fake governor.
- **Escrow pinning.** Any open incident blocks every funder's withdrawal. A
  reporter could delay closures by filing flags, at the cost of a 10%
  dismissal fee per dismissed flag. Funders who join while incidents are open
  share in their outcome, because shares are priced on reserved plus
  unreserved escrow.
- **Lifecycle is checked at report time.** A proposal canceled after it was
  reported still pays out if its verdict survives the challenge window; that is
  intended, since the alarm may be why it was canceled.
- **Verdicts are advisory.** Protection depends on a Guardian or pause module
  actually consuming the verdict before the timelock ETA.

The contract stays solvent at all times:

```
total_deposited == total_bonded + total_claimable + total_slashed
```

See [`specs/architecture.md`](specs/architecture.md) for the full design,
settlement matrix, and threat model.

## Layout

```
contracts/gov_sentry.py                 intelligent contract
tests/direct/                           direct-mode test suites (lifecycle, adversarial, review PoCs)
scripts/deploy.py                       deploy and record in deployments/studio.json
scripts/bootstrap.py                    curate the chain RPC, register DAO, selectors, escrow
deployments/studio.json                 live deployment record
frontend/                               Vite + React + Tailwind dashboard
specs/architecture.md                   architecture specification
```

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

genvm-lint check contracts/gov_sentry.py   # lint and SDK validation
pytest tests/direct/                        # direct-mode tests (RPC and LLM mocked, no network)
```

## Deployment

Put the deployer key in a local `.env`, which is gitignored:

```bash
echo "GENLAYER_PRIVATE_KEY=0x..." > .env
python scripts/deploy.py --network studio_next --fund   # --fund tops up from the Studio faucet
python scripts/bootstrap.py                             # chain RPC, DAO #1, selectors, escrow
python scripts/bootstrap.py --demo-incident             # optional: report a real Compound proposal
```

Studio Next requires an explicit fee distribution on each transaction. Both
scripts estimate it from the network's live fee policy. `deploy.py` exits
non-zero unless the deployment finishes with a return. The deployer becomes the
contract owner. The owner's privileges are curating chain RPC endpoints and
sweeping the slashed treasury.

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
- **Flag form:** a proposal reference (DAO, proposal id, action index, creation
  block), bond and payout math, and a free **dry run** that reads the proposal
  from chain and returns a real LLM verdict from a leader-only simulation,
  showing exactly what validators fetched, without posting anything.
- **DAO directory:** each DAO's verification status (`VERIFIED` governor or
  `UNVERIFIED_REGISTRAR`).
- **Wallets:** any injected wallet (Studio Next is added automatically), or a
  **Studio test account**, a browser-held key funded from the Studio faucet,
  for trying the full flow without MetaMask.

Every write is first simulated, so a revert shows the contract's own reason
(for example `ERR_CHALLENGE_WINDOW_ACTIVE`) before anything is signed.

## License

MIT © 2026 Handik4
# GovSentry
