"""
IRL Engine Python SDK
=====================
Zero-dependency client for the MacroPulse IRL Engine REST API.
Requires: requests (pip install requests)

Quickstart
----------
    from irl_client import IRLClient

    irl = IRLClient(
        base_url="http://localhost:4000",
        token="mp_xxxxxxxxxxxx",
        agent_id="00000000-0000-0000-0000-000000000001",
        model_hash_hex=IRLClient.compute_model_hash({"model": "hmm-v3.1", "version": "1.0"}),
    )

    auth = irl.authorize(
        action="Long",      # SDK converts "Long" → {"Long": quantity} automatically
        quantity=2.0,       # or "Short", "Neutral", "Buy" (Custom), "Open Long" (Custom)
        asset="BTC-PERP",
        notional=120_000.0,
    )

    if auth.shadow_blocked:
        print(f"[SHADOW] trade would have been blocked — trace_id={auth.trace_id}")

    bind = irl.bind(auth.trace_id, exchange_order_id="EX-12345")
    print(f"bind status: {bind.verification_status}")
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError as exc:
    raise ImportError(
        "irl_client requires the 'requests' package. "
        "Install it with: pip install requests"
    ) from exc


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class IRLError(Exception):
    """Raised when the IRL Engine returns a non-2xx response."""

    def __init__(self, error_code: str, message: str, status: int) -> None:
        super().__init__(f"[{error_code}] {message} (HTTP {status})")
        self.error_code = error_code
        self.message = message
        self.status = status


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AuthorizeResult:
    trace_id: str
    reasoning_hash: str
    authorized: bool
    shadow_blocked: bool = False


@dataclass
class BindResult:
    trace_id: str
    final_proof: Optional[str]
    verification_status: str          # PENDING / MATCHED / DIVERGENT / ORPHAN / EXPIRED
    execution_status: Optional[str]   # Filled / Rejected / Partial
    divergence_reason: Optional[str] = None


@dataclass
class AgentProfile:
    # The server's key is "agent_id"; exposed as `id` for backward compatibility.
    id: str
    name: str
    model_hash_hex: str
    status: str
    max_notional: float
    allowed_regimes: Optional[List[int]] = None
    created_at: Optional[str] = None  # not returned by IRL v1.3.0
    # None = unrestricted; enforced at authorize (case-insensitive).
    allowed_venues: Optional[List[str]] = None
    allowed_assets: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class IRLClient:
    """
    Thin HTTP client for the IRL Engine REST API.

    Parameters
    ----------
    base_url : str
        Base URL of the IRL Engine sidecar, e.g. ``"http://localhost:4000"``.
    token : str
        Bearer token (IRL_API_TOKENS entry).
    agent_id : str
        UUID of the registered agent (from ``POST /irl/agents``).
    model_hash_hex : str
        SHA-256 hex digest of the agent's model configuration. Must match the
        hash registered in the Multi-Agent Registry. Use
        ``IRLClient.compute_model_hash(config_dict)`` to generate.
    model_id : str
        Human-readable model identifier, e.g. ``"hmm-v3.1"``.
    prompt_version : str
        Version tag for the agent's prompt template, e.g. ``"v2.0"``.
    feature_schema_id : str
        Identifier for the input feature schema.
    hyperparameter_checksum : str
        Hex checksum of the agent's hyperparameter set.
    timeout : int
        HTTP request timeout in seconds (default: 10).
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        agent_id: str,
        model_hash_hex: str,
        *,
        model_id: str = "default",
        prompt_version: str = "v1.0",
        feature_schema_id: str = "default",
        hyperparameter_checksum: str = "0" * 64,
        timeout: int = 10,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        self.agent_id = agent_id
        self.model_hash_hex = model_hash_hex
        self.model_id = model_id
        self.prompt_version = prompt_version
        self.feature_schema_id = feature_schema_id
        self.hyperparameter_checksum = hyperparameter_checksum
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Core methods
    # ------------------------------------------------------------------

    @staticmethod
    def _encode_action(action: Any, quantity: float) -> Any:
        """
        Encode a trade action into the server's serde enum format.

        Accepts both shorthand strings and pre-encoded dicts:
          "Long"           → {"Long": quantity}
          "Short"          → {"Short": quantity}
          "Neutral"        → "Neutral"
          "Buy"            → {"Custom": "Buy"}     (equities)
          "Open Long"      → {"Custom": "Open Long"}
          {"Long": 2.0}    → passthrough (already encoded)
          {"Custom": "Buy"} → passthrough
        """
        if isinstance(action, dict):
            return action  # already in serde format
        if action in ("Long", "Short"):
            return {action: quantity}
        if action == "Neutral":
            return "Neutral"
        # Anything else is a Custom action
        return {"Custom": action}

    def authorize(
        self,
        action: Any,
        quantity: float,
        asset: str,
        notional: float,
        *,
        order_type: str = "MARKET",
        venue_id: Optional[str] = None,
        notional_currency: str = "USD",
        multiplier: float = 1.0,
        limit_price: Optional[float] = None,
        stop_price: Optional[float] = None,
        client_order_id: Optional[str] = None,
        heartbeat: Optional[Dict[str, Any]] = None,
        valid_time_ms: Optional[int] = None,
        reduce_only: bool = False,
        regulatory: Optional[Dict[str, Any]] = None,
    ) -> AuthorizeResult:
        """
        Seal and authorize a trade intent.

        Parameters
        ----------
        action : str or dict
            Trade direction. Accepted formats:
            - ``"Long"`` or ``"Short"`` — converted to ``{"Long": quantity}`` automatically
            - ``"Neutral"`` — no directional exposure
            - ``"Buy"``, ``"Sell"``, ``"Open Long"``, etc. — wrapped as ``{"Custom": "..."}``
            - Pre-encoded dict: ``{"Long": 2.0}`` or ``{"Custom": "Buy"}`` (passed through)
        quantity : float
            Quantity in base asset units.
        asset : str
            Asset identifier, e.g. ``"BTC-PERP"``, ``"AAPL"``, ``"ES"`` (CME).
        notional : float
            Notional value in ``notional_currency``.
        order_type : str
            ``"MARKET"``, ``"LIMIT"``, ``"STOP"``, ``"STOP_LIMIT"``, ``"TWAP"``,
            ``"VWAP"``, ``"IOC"``, ``"FOK"``, ``"POST_ONLY"``, ``"PEGGED"``,
            ``"TRAILING_STOP"``, ``"ICEBERG"``, or ``"Custom:<str>"``.
        venue_id : str, optional
            Execution venue MIC code or internal route (e.g. ``"XNAS"``, ``"CME"``).
        notional_currency : str
            ISO 4217 currency of the notional. Default ``"USD"``.
        multiplier : float
            Contract multiplier for futures/options. Default ``1.0``.
            Examples: CME ES = 50, equity options = 100.
        limit_price : float, optional
            Required for LIMIT and STOP_LIMIT orders.
        stop_price : float, optional
            Stop trigger price for STOP_LIMIT orders.
        client_order_id : str, optional
            Client-assigned order ID for EMS correlation.
        heartbeat : dict, optional
            Layer 2 signed heartbeat (required when LAYER2_ENABLED=true).
        valid_time_ms : int, optional
            Unix epoch milliseconds of the agent's reasoning moment.
            Defaults to current time.
        reduce_only : bool
            When True, bypasses allowed_sides check (position-closing order).
        regulatory : dict, optional
            Optional regulatory metadata. Keys: mifid_algo_id, mifid_decision_maker,
            cftc_cti_code, cftc_account_type, cat_order_id, jurisdiction.

        Returns
        -------
        AuthorizeResult
            Contains ``trace_id``, ``reasoning_hash``, ``authorized``, and
            ``shadow_blocked`` (True if SHADOW_MODE intercepted a policy block).

        Raises
        ------
        IRLError
            On policy violations (403), validation errors (400), or server errors.
        """
        payload: Dict[str, Any] = {
            "agent_id": self.agent_id,
            "model_hash_hex": self.model_hash_hex,
            "model_id": self.model_id,
            "prompt_version": self.prompt_version,
            "feature_schema_id": self.feature_schema_id,
            "hyperparameter_checksum": self.hyperparameter_checksum,
            "action": self._encode_action(action, quantity),
            "quantity": quantity,
            "asset": asset,
            "notional": notional,
            "notional_currency": notional_currency,
            "multiplier": multiplier,
            "order_type": order_type,
            "reduce_only": reduce_only,
            "agent_valid_time": valid_time_ms if valid_time_ms is not None else int(time.time() * 1000),
            # Both required by the server (422 if missing).
            "venue_id": venue_id,
            "client_order_id": client_order_id or f"irl-{uuid.uuid4().hex}",
        }
        if limit_price is not None:
            payload["limit_price"] = limit_price
        if stop_price is not None:
            payload["stop_price"] = stop_price
        if heartbeat is not None:
            payload["heartbeat"] = heartbeat
        if regulatory is not None:
            payload["regulatory"] = regulatory

        if not venue_id:
            raise ValueError("venue_id is required by IRL (e.g. 'BINANCE', 'XNAS')")
        data = self._post("/irl/authorize", payload)
        return AuthorizeResult(
            trace_id=data["trace_id"],
            reasoning_hash=data["reasoning_hash"],
            authorized=data.get("authorized", True),
            shadow_blocked=data.get("shadow_blocked", False),
        )

    def bind(
        self,
        trace_id: str,
        exchange_order_id: str,
        *,
        execution_status: str = "Filled",
        execution_price: Optional[float] = None,
        executed_quantity: Optional[float] = None,
        execution_time_ms: Optional[int] = None,
        executed_side: Optional[str] = None,
        asset: Optional[str] = None,
    ) -> BindResult:
        """
        Bind an exchange execution report to the authorized intent.

        Call this after receiving confirmation from the exchange, regardless of
        whether the order was filled, rejected, or partially filled. A rejected
        order with verification_status=MATCHED is the correct outcome for a
        ``{"execution_status": "Rejected"}`` bind — the seal closes the chain.

        Parameters
        ----------
        trace_id : str
            The trace_id from the corresponding authorize call.
        exchange_order_id : str
            The exchange-assigned order ID.
        execution_status : str
            ``"Filled"``, ``"Rejected"``, or ``"Partial"``.
        execution_price : float, optional
            Fill price.
        executed_quantity : float, optional
            Quantity executed. Required for divergence detection on partial fills.
        execution_time_ms : int, optional
            Unix epoch milliseconds of the exchange confirmation.

        Returns
        -------
        BindResult
            Contains ``trace_id``, ``final_proof``, ``verification_status``,
            ``execution_status``, and ``divergence_reason`` (if DIVERGENT).
        """
        payload: Dict[str, Any] = {
            "trace_id": trace_id,
            "exchange_tx_id": exchange_order_id,
            "execution_status": execution_status,
        }
        if execution_price is not None:
            payload["execution_price"] = execution_price
        if executed_quantity is not None:
            payload["executed_quantity"] = executed_quantity
        if execution_time_ms is not None:
            # Server field is execution_time_ms; unknown keys are silently ignored,
            # so the old "execution_time" key dropped the fill time without error.
            payload["execution_time_ms"] = execution_time_ms
        if executed_side is not None:
            payload["executed_side"] = executed_side
        if asset is not None:
            payload["asset"] = asset

        data = self._post("/irl/bind-execution", payload)
        return BindResult(
            trace_id=data["trace_id"],
            final_proof=data.get("final_proof"),
            verification_status=data["verification_status"],
            execution_status=data.get("execution_status"),
            divergence_reason=data.get("divergence_reason"),
        )

    def get_trace(self, trace_id: str) -> Dict[str, Any]:
        """Return the full Reasoning_Trace_v1 JSON for forensic audit replay."""
        return self._get(f"/irl/trace/{trace_id}")

    def get_pending(self, age_seconds: int = 0) -> Dict[str, Any]:
        """Return PENDING traces older than ``age_seconds``."""
        return self._get("/irl/pending", params={"age_seconds": age_seconds})

    def get_orphans(self) -> Dict[str, Any]:
        """Return EXPIRED and DIVERGENT traces."""
        return self._get("/irl/orphans")

    def get_shadow_violations(self) -> Dict[str, Any]:
        """Return traces where shadow mode intercepted a policy violation."""
        return self._get("/irl/shadow-violations")

    def health(self) -> str:
        """Return ``"ok"`` if the engine is reachable."""
        resp = self._session.get(f"{self._base}/irl/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.text.strip()

    # ------------------------------------------------------------------
    # Agent management helpers
    # ------------------------------------------------------------------

    def register_agent(
        self,
        name: str,
        model_hash_hex: str,
        max_notional: float,
        allowed_regimes: Optional[List[int]] = None,
        allowed_venues: Optional[List[str]] = None,
        allowed_assets: Optional[List[str]] = None,
    ) -> AgentProfile:
        """Register a new agent in the Multi-Agent Registry.

        ``allowed_venues`` / ``allowed_assets`` restrict which ``venue_id`` and
        ``asset`` the agent may authorize (None = any).
        """
        payload: Dict[str, Any] = {
            "name": name,
            "model_hash_hex": model_hash_hex,
            "max_notional": max_notional,
        }
        optional = {
            "allowed_regimes": allowed_regimes,
            "allowed_venues": allowed_venues,
            "allowed_assets": allowed_assets,
        }
        payload.update({k: v for k, v in optional.items() if v is not None})
        data = self._post("/irl/agents", payload)
        # The register response is {agent_id, model_hash_hex, status}; fill the
        # rest from the request rather than failing on missing keys.
        return AgentProfile(
            id=data["agent_id"],
            name=name,
            model_hash_hex=data.get("model_hash_hex", model_hash_hex),
            status=data.get("status", "Active"),
            max_notional=max_notional,
            allowed_regimes=allowed_regimes,
            allowed_venues=allowed_venues,
            allowed_assets=allowed_assets,
        )

    def list_agents(self) -> List[AgentProfile]:
        """List all registered agents."""
        data = self._get("/irl/agents")
        return [self._parse_agent(a) for a in data.get("agents", [])]

    def get_agent(self, agent_id: str) -> AgentProfile:
        """Return a single agent profile by UUID. GET /irl/agents/:id"""
        data = self._get(f"/irl/agents/{agent_id}")
        return self._parse_agent(data)

    def suspend_agent(self, agent_id: str) -> None:
        """Suspend an agent (kill-switch)."""
        self._patch(f"/irl/agents/{agent_id}/status", {"status": "Suspended"})

    def activate_agent(self, agent_id: str) -> None:
        """Re-activate a suspended agent."""
        self._patch(f"/irl/agents/{agent_id}/status", {"status": "Active"})

    def list_traces(
        self,
        *,
        agent_id: Optional[str] = None,
        from_ms: Optional[int] = None,
        to_ms: Optional[int] = None,
        status: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Return a filtered, paginated list of reasoning traces.
        GET /irl/traces

        Parameters
        ----------
        agent_id : str, optional
            Filter by agent UUID.
        from_ms : int, optional
            Start of time range (Unix epoch milliseconds).
        to_ms : int, optional
            End of time range (Unix epoch milliseconds).
        status : str, optional
            Filter by verification_status: PENDING, MATCHED, DIVERGENT,
            ORPHAN, EXPIRED, or SHADOW_HALTED.
        limit : int, optional
            Max rows to return. Server default: 500, max: 5000.

        Returns
        -------
        dict with keys: ``count`` (int), ``traces`` (list).
        """
        params: Dict[str, Any] = {}
        if agent_id is not None:
            params["agent_id"] = agent_id
        if from_ms is not None:
            params["from"] = from_ms
        if to_ms is not None:
            params["to"] = to_ms
        if status is not None:
            params["status"] = status
        if limit is not None:
            params["limit"] = limit
        return self._get("/irl/traces", params=params or None)

    # ------------------------------------------------------------------
    # Admin endpoints — owner-level token required
    # ------------------------------------------------------------------

    def get_shadow_mode(self) -> Dict[str, Any]:
        """Return current shadow mode state. GET /irl/admin/shadow-mode
        Returns: {shadow_mode: bool, updated_at: str|None, updated_by: str|None}
        """
        return self._get("/irl/admin/shadow-mode")

    def set_shadow_mode(self, enabled: bool, reason: Optional[str] = None) -> Dict[str, Any]:
        """Enable or disable shadow mode. POST /irl/admin/shadow-mode
        Returns: {shadow_mode: bool, changed_by: str}
        """
        payload: Dict[str, Any] = {"enabled": enabled}
        if reason:
            payload["reason"] = reason
        return self._post("/irl/admin/shadow-mode", payload)

    def get_audit_log(
        self,
        *,
        action: Optional[str] = None,
        target_id: Optional[str] = None,
        from_dt: Optional[str] = None,
        to_dt: Optional[str] = None,
        before_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Return paginated admin audit log. GET /irl/admin/audit-log
        Returns: {count: int, entries: list, next_cursor: str|None}

        Cursor-based pagination: pass result["next_cursor"] as before_id on next call.
        """
        params: Dict[str, Any] = {}
        if action:
            params["action"] = action
        if target_id:
            params["target_id"] = target_id
        if from_dt:
            params["from"] = from_dt
        if to_dt:
            params["to"] = to_dt
        if before_id:
            params["before_id"] = before_id
        if limit:
            params["limit"] = limit
        return self._get("/irl/admin/audit-log", params=params or None)

    def gdpr_erase(self, agent_id: str) -> Dict[str, Any]:
        """GDPR Art. 17 erasure — nullifies PII in all traces for the given agent.
        POST /irl/admin/gdpr-erase/:agent_id
        Requires KMS_PROVIDER configured server-side.
        Returns: {agent_id, gdpr_request_id, traces_erased, status}
        """
        return self._post(f"/irl/admin/gdpr-erase/{agent_id}", {})

    def issue_token(self, client_name: str) -> Dict[str, Any]:
        """Issue a new client-role API token (returned exactly once).
        POST /irl/admin/tokens
        Returns: {token_id, client_name, token}
        Save the token immediately — it is never stored server-side.
        """
        return self._post("/irl/admin/tokens", {"client_name": client_name})

    def revoke_token(self, token_id: str) -> Dict[str, Any]:
        """Revoke a token by its 12-character token_id prefix.
        DELETE /irl/admin/tokens/:token_id
        Returns: {token_id, status}
        """
        resp = self._session.delete(
            f"{self._base}/irl/admin/tokens/{token_id}",
            timeout=self.timeout,
        )
        return self._handle(resp)

    # ------------------------------------------------------------------
    # Static utilities
    # ------------------------------------------------------------------

    @staticmethod
    def compute_model_hash(config_dict: Dict[str, Any]) -> str:
        """
        Compute the SHA-256 hex digest of a model configuration dict.

        The dict is serialized with sorted keys and no whitespace (RFC 8785
        canonical-ish) before hashing. Register this hash in the MAR and pass
        it as ``model_hash_hex`` to the client constructor.

        Example
        -------
            hash_hex = IRLClient.compute_model_hash({
                "model": "hmm-v3.1",
                "features": ["vix", "yield_curve", "credit_spread"],
                "version": "1.0",
            })
        """
        canonical = json.dumps(config_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        resp = self._session.post(
            f"{self._base}{path}",
            json=body,
            timeout=self.timeout,
        )
        return self._handle(resp)

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resp = self._session.get(
            f"{self._base}{path}",
            params=params,
            timeout=self.timeout,
        )
        return self._handle(resp)

    def _patch(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        resp = self._session.patch(
            f"{self._base}{path}",
            json=body,
            timeout=self.timeout,
        )
        return self._handle(resp)

    @staticmethod
    def _handle(resp: "requests.Response") -> Dict[str, Any]:
        if resp.ok:
            if resp.text.strip():
                return resp.json()
            return {}
        try:
            err = resp.json()
            raise IRLError(
                error_code=err.get("error", "UNKNOWN"),
                message=err.get("message", resp.text),
                status=resp.status_code,
            )
        except (ValueError, KeyError):
            raise IRLError(
                error_code="UNKNOWN",
                message=resp.text or "No response body",
                status=resp.status_code,
            )

    @staticmethod
    def _parse_agent(data: Dict[str, Any]) -> AgentProfile:
        return AgentProfile(
            id=data.get("agent_id") or data["id"],
            name=data["name"],
            model_hash_hex=data["model_hash_hex"],
            status=data["status"],
            max_notional=data["max_notional"],
            allowed_regimes=data.get("allowed_regimes"),
            created_at=data.get("created_at"),
            allowed_venues=data.get("allowed_venues"),
            allowed_assets=data.get("allowed_assets"),
        )
