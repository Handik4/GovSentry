"""Shared helpers for GovSentry direct-mode tests.

Uses the genlayer-test pytest plugin fixtures: direct_vm, direct_deploy,
direct_alice, direct_bob, direct_charlie.
"""

import hashlib
import json
import time
from datetime import datetime, timezone

CONTRACT = "contracts/gov_sentry.py"

ATTO = 10**18
REPORTER_BOND = 1 * ATTO
APPEAL_BOND = 2 * ATTO
ESCROW = 10 * ATTO
CHALLENGE_WINDOW = 86400

TIMELOCK = "0x1111111111111111111111111111111111111111"
TARGET = "0x2222222222222222222222222222222222222222"
ATTACKER = "3333333333333333333333333333333333333333"

# transferOwnership(0x3333...3333)
CALLDATA_OWNERSHIP = "0xf2fde38b" + "0" * 24 + ATTACKER
# mint(0x3333...3333, 1_000_000e18)
CALLDATA_MINT = "0x40c10f19" + "0" * 24 + ATTACKER + format(10**24, "064x")
# setFee(uint256 30)
CALLDATA_SET_FEE = "0x69fe0e2d" + format(30, "064x")

PROSE_DECEPTIVE = "Routine parameter adjustment: refresh keeper heartbeat interval."
PROSE_HONEST = "Set the protocol swap fee to 30 basis points via setFee(30)."

SEMANTIC_PROMPT = r".*GovSentry, a DAO governance security auditor.*"
APPEAL_PROMPT = r".*GovSentry appeal tribunal.*"


def sha256_hex(text: str) -> str:
    return "0x" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _llm_payload(obj: dict) -> bytes:
    """LLM mock body. Passed as bytes because the direct harness auto-parses
    str mocks into dicts, while the runner's JSON prompt decoder expects the
    raw JSON text it would receive from a real model."""
    return json.dumps(obj).encode("utf-8")


def mock_verdict(direct_vm, classification: str, rationale: str = "mocked rationale"):
    direct_vm.mock_llm(
        SEMANTIC_PROMPT,
        _llm_payload({"classification": classification, "rationale": rationale}),
    )


def mock_appeal(direct_vm, outcome: str, rationale: str = "mocked appeal rationale"):
    direct_vm.mock_llm(
        APPEAL_PROMPT,
        _llm_payload({"appeal_outcome": outcome, "rationale": rationale}),
    )


def hex_of(account) -> str:
    v = getattr(account, "as_hex", None)
    if isinstance(v, str):
        return v
    return "0x" + bytes(account).hex()


def warp_to(direct_vm, unix_seconds: int) -> None:
    ts = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
    direct_vm.warp(ts.strftime("%Y-%m-%dT%H:%M:%SZ"))


def start_clock(direct_vm) -> int:
    """Pin the VM clock to a known instant and return it."""
    t0 = int(time.time()) // 60 * 60
    warp_to(direct_vm, t0)
    return t0


def register(contract, direct_vm, sponsor, escrow: int = ESCROW, timelock: str = TIMELOCK) -> int:
    direct_vm.sender = sponsor
    direct_vm.value = escrow
    dao_id = contract.register_dao(timelock, "Example DAO", "https://example.org/dao")
    direct_vm.value = 0
    return dao_id


def flag(contract, direct_vm, reporter, dao_id: int, proposal_id: int = 1,
         calldata: str = CALLDATA_OWNERSHIP, prose: str = PROSE_DECEPTIVE,
         bond: int = REPORTER_BOND) -> int:
    direct_vm.sender = reporter
    direct_vm.value = bond
    incident_id = contract.flag_proposal(dao_id, proposal_id, TARGET, calldata, prose)
    direct_vm.value = 0
    return incident_id


def appeal(contract, direct_vm, appellant, incident_id: int, rebuttal: str,
           bond: int = APPEAL_BOND) -> None:
    direct_vm.sender = appellant
    direct_vm.value = bond
    contract.file_appeal(incident_id, rebuttal)
    direct_vm.value = 0


def bound_rebuttal(contract, incident_id: int) -> str:
    h = contract.get_incident(incident_id)["calldata_hash"]
    return (
        f"Rebuttal for calldata {h}: the forum post linked in the proposal "
        "discloses the ownership migration to the new multisig in full."
    )


def assert_solvent(contract) -> dict:
    ledger = contract.get_ledger()
    dep = int(ledger["total_deposited"])
    parts = int(ledger["total_bonded"]) + int(ledger["total_claimable"]) + int(ledger["total_slashed"])
    assert dep == parts, ledger
    assert ledger["solvent"] is True
    return ledger
