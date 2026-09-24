"""Shared helpers for GovSentry direct-mode tests.

Uses the genlayer-test pytest plugin fixtures: direct_vm, direct_deploy,
direct_alice, direct_bob, direct_charlie.
"""

import hashlib
import json
import time
from datetime import datetime, timezone

from eth_abi import encode as abi_encode
from eth_utils import keccak

CONTRACT = "contracts/gov_sentry.py"

ATTO = 10**18
REPORTER_BOND = 1 * ATTO
APPEAL_BOND = 2 * ATTO
ESCROW = 10 * ATTO
CHALLENGE_WINDOW = 86400
ESCROW_CLOSURE_NOTICE = 14 * 86400

TIMELOCK = "0x1111111111111111111111111111111111111111"
TARGET = "0x2222222222222222222222222222222222222222"
ATTACKER = "3333333333333333333333333333333333333333"
GOVERNOR = "0x4444444444444444444444444444444444444444"
CHAIN_ID = 1
RPC_URL = "https://rpc.example.org/mainnet"
RPC_PATTERN = r"^https://rpc\.example\.org/mainnet$"
CREATED_BLOCK = 21_000_000
PROPOSAL_CREATED_TOPIC = "0x" + keccak(
    text="ProposalCreated(uint256,address,address[],uint256[],string[],bytes[],uint256,uint256,string)"
).hex()

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


def deploy(direct_deploy):
    """Deploy as the default sender (the owner) and curate the test chain RPC."""
    contract = direct_deploy(CONTRACT)
    contract.set_chain_rpc(CHAIN_ID, RPC_URL)
    return contract


# ------------------------------------------------------ JSON-RPC mocking
#
# Direct-mode web mocks match on URL only and the first match wins, so each
# helper replaces the previous RPC mock. The contract sends one JSON-RPC
# batch per web-consensus read and matches replies by id.


def mock_rpc(direct_vm, replies: list) -> None:
    direct_vm._web_mocks[:] = [m for m in direct_vm._web_mocks if m[0].pattern != RPC_PATTERN]
    direct_vm.mock_web(RPC_PATTERN, {"method": "POST", "status": 200, "body": json.dumps(replies)})


def mock_timelock_admin(direct_vm, admin: str | None) -> None:
    """admin() returns `admin`; None simulates a timelock without admin()."""
    if admin is None:
        reply = {"jsonrpc": "2.0", "id": 0, "error": {"code": 3, "message": "execution reverted"}}
    else:
        reply = {"jsonrpc": "2.0", "id": 0, "result": "0x" + "0" * 24 + admin[2:].lower()}
    mock_rpc(direct_vm, [reply])


def action(calldata: str = CALLDATA_OWNERSHIP, target: str = TARGET, value: int = 0,
           signature: str = "") -> tuple:
    """One GovernorBravo action. With a signature, `calldata` holds only the
    ABI-encoded arguments, as Bravo stores it."""
    return (target, value, signature, bytes.fromhex(calldata[2:] if calldata.startswith("0x") else calldata))


def get_actions_result(actions: list) -> str:
    targets, values, signatures, calldatas = (list(x) for x in zip(*actions)) if actions else ([], [], [], [])
    return "0x" + abi_encode(
        ["address[]", "uint256[]", "string[]", "bytes[]"], [targets, values, signatures, calldatas]
    ).hex()


def proposal_created_log(proposal_id: int, actions: list, description: str,
                         governor: str = GOVERNOR) -> dict:
    targets, values, signatures, calldatas = (list(x) for x in zip(*actions)) if actions else ([], [], [], [])
    data = abi_encode(
        ["uint256", "address", "address[]", "uint256[]", "string[]", "bytes[]", "uint256", "uint256", "string"],
        [proposal_id, "0x" + "55" * 20, targets, values, signatures, calldatas,
         CREATED_BLOCK + 13140, CREATED_BLOCK + 32850, description],
    )
    return {"address": governor, "topics": [PROPOSAL_CREATED_TOPIC], "data": "0x" + data.hex(),
            "blockNumber": hex(CREATED_BLOCK)}


def proposal_details_result(actions: list, description_hash: bytes) -> str:
    targets, values, _, calldatas = (list(x) for x in zip(*actions))
    return "0x" + abi_encode(
        ["address[]", "uint256[]", "bytes[]", "bytes32"], [targets, values, calldatas, description_hash]
    ).hex()


REVERTED = {"code": 3, "message": "execution reverted"}


def mock_proposal(direct_vm, proposal_id: int, actions: list, description: str,
                  logs: list | None = None, oz: bool = False,
                  description_hash: bytes | None = None) -> None:
    """Governor state for one proposal: stored actions + its ProposalCreated
    log. Bravo serves getActions (empty arrays for unknown ids) and has no
    proposalDetails; OpenZeppelin GovernorStorage is the reverse."""
    if logs is None:
        logs = [proposal_created_log(proposal_id, actions, description)]
    if oz:
        digest = description_hash if description_hash is not None else keccak(text=description)
        replies = [
            {"jsonrpc": "2.0", "id": 0, "error": REVERTED},
            {"jsonrpc": "2.0", "id": 1, "result": proposal_details_result(actions, digest)},
        ]
    else:
        replies = [
            {"jsonrpc": "2.0", "id": 0, "result": get_actions_result(actions)},
            {"jsonrpc": "2.0", "id": 1, "error": REVERTED},
        ]
    # Replies may arrive out of order; the contract matches them by id.
    mock_rpc(direct_vm, [{"jsonrpc": "2.0", "id": 2, "result": logs}, *replies])


def register(contract, direct_vm, sponsor, escrow: int = ESCROW, timelock: str = TIMELOCK,
             governor: str = GOVERNOR, admin: str | None = GOVERNOR) -> int:
    mock_timelock_admin(direct_vm, admin)
    direct_vm.sender = sponsor
    direct_vm.value = escrow
    dao_id = contract.register_dao(timelock, governor, CHAIN_ID, "Example DAO", "https://example.org/dao")
    direct_vm.value = 0
    return dao_id


def report(contract, direct_vm, reporter, dao_id: int, proposal_id: int = 1,
           action_index: int = 0, bond: int = REPORTER_BOND,
           created_block: int = CREATED_BLOCK) -> int:
    """Report an action of whatever proposal the RPC mock currently serves."""
    direct_vm.sender = reporter
    direct_vm.value = bond
    incident_id = contract.report_proposal(dao_id, proposal_id, action_index, created_block)
    direct_vm.value = 0
    return incident_id


def flag(contract, direct_vm, reporter, dao_id: int, proposal_id: int = 1,
         calldata: str = CALLDATA_OWNERSHIP, prose: str = PROSE_DECEPTIVE,
         bond: int = REPORTER_BOND) -> int:
    """Publish a single-action proposal on the mocked governor, then report it."""
    mock_proposal(direct_vm, proposal_id, [action(calldata)], prose)
    return report(contract, direct_vm, reporter, dao_id, proposal_id, bond=bond)


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
