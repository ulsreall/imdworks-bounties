"""Minimal JSON-RPC client for a local anvil/hardhat node (no dependencies).

Only localhost is used: the reconciliation fixture never talks to a public
network, so no API keys and no paid RPC are involved.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8599"


class RpcError(RuntimeError):
    pass


class Rpc:
    def __init__(self, url: str = DEFAULT_URL, timeout: float = 30.0) -> None:
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method: str, params: list | None = None, retries: int = 4):
        last: Exception | None = None
        for attempt in range(retries):
            self._id += 1
            payload = json.dumps({"jsonrpc": "2.0", "id": self._id,
                                  "method": method, "params": params or []}).encode()
            req = urllib.request.Request(self.url, data=payload,
                                         headers={"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = json.loads(resp.read().decode())
                if "error" in body:
                    raise RpcError(f"{method}: {body['error'].get('message')}")
                return body.get("result")
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                last = exc
                time.sleep(0.2 * (attempt + 1))
        raise RpcError(f"{method} failed after {retries} attempts: {last}")

    # ---- convenience -----------------------------------------------------
    def block_number(self) -> int:
        return int(self.call("eth_blockNumber"), 16)

    def get_code(self, address: str, block: str = "latest") -> str:
        return self.call("eth_getCode", [address, block])

    def get_balance(self, address: str, block: str = "latest") -> int:
        return int(self.call("eth_getBalance", [address, block]), 16)

    def chain_id(self) -> int:
        return int(self.call("eth_chainId"), 16)

    def send(self, frm: str, to: str | None, data: str, gas: str | None = None) -> str:
        tx: dict = {"from": frm, "data": data, "value": "0x0"}
        if to:
            tx["to"] = to
        if gas:
            tx["gas"] = gas
        return self.call("eth_sendTransaction", [tx])

    def send_and_wait(self, frm: str, to: str | None, data: str,
                      gas: str | None = None, expect_ok: bool = True) -> dict:
        tx_hash = self.send(frm, to, data, gas)
        receipt = self.wait_receipt(tx_hash)
        status = int(receipt.get("status", "0x0"), 16)
        if expect_ok and status != 1:
            raise RpcError(f"transaction reverted: {tx_hash}")
        receipt["_hash"] = tx_hash
        return receipt

    def wait_receipt(self, tx_hash: str, timeout: float = 30.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            receipt = self.call("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                return receipt
            time.sleep(0.05)
        raise RpcError(f"no receipt for {tx_hash}")

    def increase_time(self, seconds: int) -> int:
        raw = self.call("evm_increaseTime", [seconds])
        try:
            return int(str(raw), 16)
        except ValueError:
            return int(str(raw))

    def mine(self) -> None:
        self.call("evm_mine", [])

    def get_logs(self, address: str, from_block: int, to_block: int) -> list[dict]:
        return self.call("eth_getLogs", [{
            "address": address,
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
        }])

    def get_block(self, block: int) -> dict:
        return self.call("eth_getBlockByNumber", [hex(block), False])
