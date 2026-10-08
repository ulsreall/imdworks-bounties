"""Escrow and token bindings: selectors, state readers, log decoding.

Selectors and topic hashes are computed locally with the Keccak-256
implementation in this repository, which is a useful self-check: if the derived
selector does not match the one the live contract answers to, the encoder is
wrong.
"""

from __future__ import annotations

from . import abi
from .keccak256 import keccak256

FUNCTIONS = {
    "createBounty": "createBounty(uint256,uint64,bytes32,string)",
    "addReward": "addReward(uint256,uint256)",
    "setOperator": "setOperator(address,bool)",
    "submitWork": "submitWork(uint256,bytes32,string)",
    "submitWorkFor": "submitWorkFor(uint256,address,bytes32,string)",
    "award": "award(uint256,address)",
    "cancel": "cancel(uint256)",
    "expire": "expire(uint256)",
    "withdraw": "withdraw(address)",
    "claimable": "claimable(address)",
    "totalLocked": "totalLocked()",
    "totalClaimable": "totalClaimable()",
    "liabilities": "liabilities()",
    "nextBountyId": "nextBountyId()",
    "bounties": "bounties(uint256)",
    "token": "paymentToken()",
    "balanceOf": "balanceOf(address)",
    "paused": "paused()",
    "mint": "mint(address,uint256)",
    "approve": "approve(address,uint256)",
    "transfer": "transfer(address,uint256)",
    "setPaused": "setPaused(bool)",
}

EVENTS = {
    "BountyCreated": "BountyCreated(uint256,address,uint256,uint64,bytes32,string)",
    "RewardAdded": "RewardAdded(uint256,uint256,uint256)",
    "WorkSubmitted": "WorkSubmitted(uint256,address,address,bytes32,string)",
    "BountyAwarded": "BountyAwarded(uint256,address,uint256)",
    "BountyRefunded": "BountyRefunded(uint256,address,uint256,uint8)",
    "Withdrawn": "Withdrawn(address,address,uint256)",
    "Transfer": "Transfer(address,address,uint256)",
    "Approval": "Approval(address,address,uint256)",
    "PausedSet": "PausedSet(bool)",
}

STATUS = {0: "None", 1: "Open", 2: "Awarded", 3: "Cancelled", 4: "Expired"}


def selector(name: str) -> str:
    return "0x" + keccak256(FUNCTIONS[name].encode()).hex()[:8]


def topic(name: str) -> str:
    return "0x" + keccak256(EVENTS[name].encode()).hex()


TOPIC_INDEX = {topic(name): name for name in EVENTS}


# --------------------------------------------------------------- calldata

def calldata(name: str, args: list[tuple[str, object]]) -> str:
    return selector(name) + abi.encode_args(args).hex()


def cd_create_bounty(reward: int, deadline: int, brief_hash: str, brief_uri: str) -> str:
    return calldata("createBounty", [("uint256", reward), ("uint64", deadline),
                                     ("bytes32", brief_hash), ("string", brief_uri)])


def cd_add_reward(bounty_id: int, amount: int) -> str:
    return calldata("addReward", [("uint256", bounty_id), ("uint256", amount)])


def cd_set_operator(operator: str, approved: bool) -> str:
    return calldata("setOperator", [("address", operator), ("bool", approved)])


def cd_submit_work(bounty_id: int, proof_hash: str, proof_uri: str) -> str:
    return calldata("submitWork", [("uint256", bounty_id), ("bytes32", proof_hash),
                                   ("string", proof_uri)])


def cd_submit_work_for(bounty_id: int, author: str, proof_hash: str, proof_uri: str) -> str:
    return calldata("submitWorkFor", [("uint256", bounty_id), ("address", author),
                                      ("bytes32", proof_hash), ("string", proof_uri)])


def cd_award(bounty_id: int, winner: str) -> str:
    return calldata("award", [("uint256", bounty_id), ("address", winner)])


def cd_cancel(bounty_id: int) -> str:
    return calldata("cancel", [("uint256", bounty_id)])


def cd_expire(bounty_id: int) -> str:
    return calldata("expire", [("uint256", bounty_id)])


def cd_withdraw(recipient: str) -> str:
    return calldata("withdraw", [("address", recipient)])


def cd_claimable(account: str) -> str:
    return calldata("claimable", [("address", account)])


def cd_bounties(bounty_id: int) -> str:
    return calldata("bounties", [("uint256", bounty_id)])


def cd_balance_of(account: str) -> str:
    return calldata("balanceOf", [("address", account)])


def cd_mint(to: str, amount: int) -> str:
    return calldata("mint", [("address", to), ("uint256", amount)])


def cd_approve(spender: str, amount: int) -> str:
    return calldata("approve", [("address", spender), ("uint256", amount)])


def cd_transfer(to: str, amount: int) -> str:
    return calldata("transfer", [("address", to), ("uint256", amount)])


def cd_set_paused(value: bool) -> str:
    return calldata("setPaused", [("bool", value)])


# ----------------------------------------------------------------- decoding

def decode_log(log: dict) -> dict | None:
    """Normalise a raw eth_getLogs entry into a typed event dict."""
    topics = [t.lower() for t in log["topics"]]
    name = TOPIC_INDEX.get(topics[0])
    if name is None:
        return None
    base = {
        "name": name,
        "block": int(log["blockNumber"], 16),
        "log_index": int(log["logIndex"], 16),
        "tx": log["transactionHash"],
        "address": log["address"].lower(),
        "block_hash": (log.get("blockHash") or "").lower(),
    }
    words = abi.split_words(log["data"]) if log["data"] not in ("0x", "") else []

    if name == "BountyCreated":
        base.update({
            "bounty_id": abi.dec_uint(bytes.fromhex(topics[1][2:])),
            "creator": abi.dec_address(bytes.fromhex(topics[2][2:])),
            "reward": abi.dec_uint(words[0]),
            "deadline": abi.dec_uint(words[1]),
            "brief_hash": abi.dec_bytes32(words[2]),
            "brief_uri": abi.dec_string(log["data"], index=3) if words else "",
        })
    elif name == "RewardAdded":
        base.update({
            "bounty_id": abi.dec_uint(bytes.fromhex(topics[1][2:])),
            "amount": abi.dec_uint(words[0]),
            "reward_total": abi.dec_uint(words[1]),
        })
    elif name == "WorkSubmitted":
        base.update({
            "bounty_id": abi.dec_uint(bytes.fromhex(topics[1][2:])),
            "author": abi.dec_address(bytes.fromhex(topics[2][2:])),
            "operator": abi.dec_address(bytes.fromhex(topics[3][2:])),
            "proof_hash": abi.dec_bytes32(words[0]),
            "proof_uri": abi.dec_string(log["data"], index=1) if len(words) > 1 else "",
        })
    elif name == "BountyAwarded":
        base.update({
            "bounty_id": abi.dec_uint(bytes.fromhex(topics[1][2:])),
            "winner": abi.dec_address(bytes.fromhex(topics[2][2:])),
            "amount": abi.dec_uint(words[0]),
        })
    elif name == "BountyRefunded":
        base.update({
            "bounty_id": abi.dec_uint(bytes.fromhex(topics[1][2:])),
            "creator": abi.dec_address(bytes.fromhex(topics[2][2:])),
            "amount": abi.dec_uint(words[0]),
            "status": abi.dec_uint(words[1]),
        })
    elif name == "Withdrawn":
        base.update({
            "account": abi.dec_address(bytes.fromhex(topics[1][2:])),
            "recipient": abi.dec_address(bytes.fromhex(topics[2][2:])),
            "amount": abi.dec_uint(words[0]),
        })
    elif name == "Transfer":
        base.update({
            "from": abi.dec_address(bytes.fromhex(topics[1][2:])),
            "to": abi.dec_address(bytes.fromhex(topics[2][2:])),
            "value": abi.dec_uint(words[0]),
        })
    elif name == "PausedSet":
        base.update({"paused": abi.dec_bool(words[0])})
    return base
