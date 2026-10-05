"""Contract tests: the Python SDK must send exactly the keys the server reads.

The server ignores unknown JSON keys, so a misnamed field (the SDK used to send
`execution_time` instead of `execution_time_ms`) fails silently. These tests
pin the wire format to src/snapshot.rs (AuthorizeRequest), src/binding.rs
(BindExecutionRequest) and src/routes/agents.rs (register response).
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from irl_client import IRLClient  # noqa: E402

# Required fields of AuthorizeRequest (src/snapshot.rs, no serde default).
AUTHORIZE_REQUIRED = {
    "agent_id", "model_hash_hex", "model_id", "prompt_version", "feature_schema_id",
    "hyperparameter_checksum", "action", "asset", "order_type", "venue_id", "quantity",
    "notional", "client_order_id", "agent_valid_time",
}
# Every field BindExecutionRequest (src/binding.rs) deserializes.
BIND_FIELDS = {
    "trace_id", "exchange_tx_id", "execution_status", "asset", "executed_quantity",
    "executed_side", "execution_price", "execution_time_ms",
}


class FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status_code = status
        self.ok = 200 <= status < 300
        self._payload = payload
        self.text = "x"

    def json(self) -> dict:
        return self._payload


class FakeSession:
    def __init__(self, payload: dict, status: int = 200):
        self.headers: dict = {}
        self.sent: list[tuple[str, dict]] = []
        self._response = FakeResponse(status, payload)

    def post(self, url: str, json: dict, timeout: int):
        self.sent.append((url, json))
        return self._response


def _client(payload: dict, status: int = 200) -> tuple[IRLClient, FakeSession]:
    client = IRLClient(
        base_url="http://irl:4000",
        token="tok",
        agent_id="00000000-0000-0000-0000-000000000001",
        model_hash_hex="a" * 64,
    )
    session = FakeSession(payload, status)
    client._session = session
    return client, session


def test_authorize_sends_every_required_field():
    client, session = _client({"trace_id": "t", "reasoning_hash": "r", "authorized": True})

    client.authorize(action="Long", quantity=0.5, asset="BTC/USDT", notional=30_000.0, venue_id="BINANCE")

    url, body = session.sent[0]
    assert url.endswith("/irl/authorize")
    assert AUTHORIZE_REQUIRED <= body.keys()
    assert body["action"] == {"Long": 0.5}


def test_authorize_generates_client_order_id_when_omitted():
    client, session = _client({"trace_id": "t", "reasoning_hash": "r"})

    client.authorize(action="Long", quantity=1.0, asset="X", notional=1.0, venue_id="V")
    client.authorize(action="Long", quantity=1.0, asset="X", notional=1.0, venue_id="V")

    ids = [body["client_order_id"] for _, body in session.sent]
    assert all(i.startswith("irl-") for i in ids)
    assert ids[0] != ids[1]


def test_authorize_keeps_caller_client_order_id():
    client, session = _client({"trace_id": "t", "reasoning_hash": "r"})

    client.authorize(action="Long", quantity=1.0, asset="X", notional=1.0, venue_id="V", client_order_id="mine-1")

    assert session.sent[0][1]["client_order_id"] == "mine-1"


def test_authorize_requires_venue_id_before_calling_server():
    client, session = _client({})

    with pytest.raises(ValueError, match="venue_id"):
        client.authorize(action="Long", quantity=1.0, asset="X", notional=1.0)

    assert session.sent == []


def test_bind_sends_only_server_field_names():
    client, session = _client({"trace_id": "t", "verification_status": "Matched", "final_proof": "p"})

    client.bind(
        "t",
        exchange_order_id="EX-1",
        execution_status="Filled",
        execution_price=1.0,
        executed_quantity=2.0,
        execution_time_ms=1_790_000_000_000,
        executed_side="Long",
        asset="BTC/USDT",
    )

    body = session.sent[0][1]
    assert body.keys() <= BIND_FIELDS
    assert body["execution_time_ms"] == 1_790_000_000_000
    assert "execution_time" not in body


def test_register_agent_reads_agent_id_from_real_response_shape():
    # Exact body returned by POST /irl/agents (src/routes/agents.rs).
    client, _ = _client({"agent_id": "agent-uuid", "model_hash_hex": "a" * 64, "status": "Active"}, status=201)

    profile = client.register_agent(name="bot", model_hash_hex="a" * 64, max_notional=200.0)

    assert profile.id == "agent-uuid"
    assert profile.name == "bot"
    assert profile.max_notional == 200.0
    assert profile.created_at is None


def test_parse_agent_accepts_server_profile_without_created_at():
    profile = IRLClient._parse_agent(
        {
            "agent_id": "u",
            "name": "n",
            "model_hash_hex": "h",
            "status": "Active",
            "max_notional": 1.0,
            "allowed_regimes": None,
        }
    )

    assert profile.id == "u"
    assert profile.created_at is None


def test_register_agent_sends_venue_and_asset_allowlists_only_when_given():
    client, session = _client({"agent_id": "a1", "model_hash_hex": "a" * 64, "status": "Active"}, status=201)

    profile = client.register_agent(
        name="bot",
        model_hash_hex="a" * 64,
        max_notional=200.0,
        allowed_venues=["binance"],
        allowed_assets=["BTCUSDT"],
    )
    client.register_agent(name="open", model_hash_hex="a" * 64, max_notional=1.0)

    scoped, unscoped = session.sent[0][1], session.sent[1][1]
    assert scoped["allowed_venues"] == ["binance"]
    assert scoped["allowed_assets"] == ["BTCUSDT"]
    assert "allowed_venues" not in unscoped and "allowed_assets" not in unscoped
    assert profile.allowed_assets == ["BTCUSDT"]
