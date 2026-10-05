/**
 * IRL Engine TypeScript SDK
 * =========================
 * Zero-dependency client for the MacroPulse IRL Engine REST API.
 * Works in Node.js (≥18) and any modern browser / Deno / Bun environment.
 *
 * @example
 * ```ts
 * import { IRLClient } from "./irl-client";
 *
 * const irl = new IRLClient({
 *   baseUrl: "http://localhost:4000",
 *   token: "mp_xxxxxxxxxxxx",
 *   agentId: "00000000-0000-0000-0000-000000000001",
 *   modelHashHex: await IRLClient.computeModelHash({ model: "hmm-v3.1", version: "1.0" }),
 * });
 *
 * const auth = await irl.authorize({
 *   action: longAction(2.0),   // or shortAction(1.5), "Neutral", customAction("Buy")
 *   quantity: 2.0,
 *   asset: "BTC-PERP",
 *   notional: 120_000,
 * });
 *
 * if (auth.shadowBlocked) {
 *   console.warn(`[SHADOW] trade would have been blocked — ${auth.traceId}`);
 * }
 *
 * const bind = await irl.bind({ traceId: auth.traceId, exchangeOrderId: "EX-12345" });
 * console.log("bind status:", bind.verificationStatus);
 * ```
 */

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export class IRLError extends Error {
  readonly errorCode: string;
  readonly status: number;

  constructor(errorCode: string, message: string, status: number) {
    super(`[${errorCode}] ${message} (HTTP ${status})`);
    this.name = "IRLError";
    this.errorCode = errorCode;
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Trade action in the serde enum format required by the IRL Engine server.
 *
 * Use the helper functions for clarity:
 *   longAction(2.0)         → {Long: 2.0}
 *   shortAction(1.5)        → {Short: 1.5}
 *   "Neutral"               → "Neutral"
 *   customAction("Buy")     → {Custom: "Buy"}
 *   customAction("Open Long") → {Custom: "Open Long"}
 */
export type TradeAction =
  | { Long: number }
  | { Short: number }
  | "Neutral"
  | { Custom: string };

/** Build a Long (buy) action. */
export const longAction = (quantity: number): TradeAction => ({ Long: quantity });
/** Build a Short (sell) action. */
export const shortAction = (quantity: number): TradeAction => ({ Short: quantity });
/** Build a Neutral (flat) action. */
export const neutralAction = (): TradeAction => "Neutral";
/** Build a Custom action for exchange-specific semantics (e.g. "Buy", "Open Long"). */
export const customAction = (s: string): TradeAction => ({ Custom: s });

export type OrderType =
  | "MARKET" | "LIMIT" | "STOP" | "STOP_LIMIT" | "TWAP" | "VWAP"
  | "IOC" | "FOK" | "POST_ONLY" | "PEGGED" | "TRAILING_STOP" | "ICEBERG";
export type ExecutionStatus = "Filled" | "Rejected" | "Partial";
export type VerificationStatus =
  | "PENDING"
  | "MATCHED"
  | "DIVERGENT"
  | "ORPHAN"
  | "EXPIRED";
export type AgentStatus = "Active" | "Suspended" | "Deregistered";

export interface AuthorizeRequest {
  action: TradeAction;
  quantity: number;
  asset: string;
  notional: number;
  /** ISO 4217 currency of the notional. Defaults to "USD". */
  notionalCurrency?: string;
  /** Contract multiplier for futures/options. Default 1.0 (spot/equities/crypto perps). */
  multiplier?: number;
  orderType?: OrderType;
  venueId?: string;
  limitPrice?: number;
  /** Stop trigger price for STOP_LIMIT orders. */
  stopPrice?: number;
  clientOrderId?: string;
  /** When true, bypasses allowed_sides check (position-reducing order). */
  reduceOnly?: boolean;
  /** Optional regulatory metadata (MiFID II, CFTC, SEC CAT). */
  regulatory?: {
    mifidAlgoId?: string;
    mifidDecisionMaker?: string;
    cftcCtiCode?: string;
    cftcAccountType?: string;
    catOrderId?: string;
    jurisdiction?: string;
  };
  /** Layer 2 signed heartbeat. Required when LAYER2_ENABLED=true. */
  heartbeat?: SignedHeartbeat;
  /**
   * Unix epoch milliseconds of the agent's reasoning moment.
   * Set to the model inference timestamp — not Date.now() at call time.
   * Defaults to Date.now().
   */
  validTimeMs?: number;
}

export interface SignedHeartbeat {
  sequence_id: number;
  timestamp_ms: number;
  regime_id: number;
  mta_ref: string;
  signature: number[];
}

export interface AuthorizeResult {
  traceId: string;
  reasoningHash: string;
  authorized: boolean;
  /** True when SHADOW_MODE intercepted a policy block. Trade was allowed through
   *  but persisted as SHADOW_HALTED for compliance review. */
  shadowBlocked: boolean;
}

export interface BindRequest {
  traceId: string;
  exchangeOrderId: string;
  executionStatus?: ExecutionStatus;
  executionPrice?: number;
  /** Quantity actually executed. Required for accurate divergence detection on partial fills. */
  executedQuantity?: number;
  executionTimeMs?: number;
  /** Exchange-reported direction ("Long" | "Short"); verified against the intent. */
  executedSide?: string;
  /** Asset actually traded; triggers the asset-mismatch check. */
  asset?: string;
}

export interface BindResult {
  traceId: string;
  finalProof: string | null;
  verificationStatus: VerificationStatus;
  executionStatus: ExecutionStatus | null;
  divergenceReason: string | null;
}

export interface AgentProfile {
  id: string;
  name: string;
  modelHashHex: string;
  status: AgentStatus;
  maxNotional: number;
  allowedRegimes: number[] | null;
  /** Not returned by IRL v1.3.0. */
  createdAt?: string;
}

export interface RegisterAgentRequest {
  name: string;
  modelHashHex: string;
  maxNotional: number;
  allowedRegimes?: number[];
}

export interface TraceListParams {
  agentId?: string;
  from?: number;    // Unix ms
  to?: number;      // Unix ms
  status?: string;  // PENDING|MATCHED|DIVERGENT|ORPHAN|EXPIRED|SHADOW_HALTED
  limit?: number;   // default 500, max 5000
}

export interface TraceListResult {
  count: number;
  traces: unknown[];
}

export interface AuditLogParams {
  action?: string;
  targetId?: string;
  from?: string;    // ISO 8601
  to?: string;      // ISO 8601
  beforeId?: string; // pagination cursor (UUID)
  limit?: number;
}

export interface AuditLogResult {
  count: number;
  entries: unknown[];
  nextCursor: string | null;
}

export interface ShadowModeResult {
  shadowMode: boolean;
  updatedAt: string | null;
  updatedBy: string | null;
}

export interface TokenIssueResult {
  tokenId: string;
  clientName: string;
  token: string; // returned once — never stored server-side
}

export interface IRLClientOptions {
  /** Base URL of the IRL Engine sidecar, e.g. `"http://localhost:4000"`. */
  baseUrl: string;
  /** Bearer token (IRL_API_TOKENS entry). */
  token: string;
  /** UUID of the registered agent. */
  agentId: string;
  /** SHA-256 hex digest of the agent model config. Use `IRLClient.computeModelHash`. */
  modelHashHex: string;
  /** Human-readable model identifier, e.g. `"hmm-v3.1"`. Default: `"default"`. */
  modelId?: string;
  /** Version tag for the prompt template. Default: `"v1.0"`. */
  promptVersion?: string;
  /** Feature schema identifier. Default: `"default"`. */
  featureSchemaId?: string;
  /** Hyperparameter checksum hex. Default: 64 zero characters. */
  hyperparameterChecksum?: string;
  /** Fetch timeout in milliseconds. Default: 10 000. */
  timeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class IRLClient {
  private readonly base: string;
  private readonly headers: Record<string, string>;
  private readonly agentId: string;
  private readonly modelHashHex: string;
  private readonly modelId: string;
  private readonly promptVersion: string;
  private readonly featureSchemaId: string;
  private readonly hyperparameterChecksum: string;
  private readonly timeoutMs: number;

  constructor(opts: IRLClientOptions) {
    this.base = opts.baseUrl.replace(/\/$/, "");
    this.headers = {
      Authorization: `Bearer ${opts.token}`,
      "Content-Type": "application/json",
    };
    this.agentId = opts.agentId;
    this.modelHashHex = opts.modelHashHex;
    this.modelId = opts.modelId ?? "default";
    this.promptVersion = opts.promptVersion ?? "v1.0";
    this.featureSchemaId = opts.featureSchemaId ?? "default";
    this.hyperparameterChecksum = opts.hyperparameterChecksum ?? "0".repeat(64);
    this.timeoutMs = opts.timeoutMs ?? 10_000;
  }

  // ------------------------------------------------------------------
  // Core methods
  // ------------------------------------------------------------------

  /**
   * Seal and authorize a trade intent.
   *
   * @throws {IRLError} On policy violations (403), validation errors (400), or server errors.
   */
  async authorize(req: AuthorizeRequest): Promise<AuthorizeResult> {
    const body: Record<string, unknown> = {
      agent_id: this.agentId,
      model_hash_hex: this.modelHashHex,
      model_id: this.modelId,
      prompt_version: this.promptVersion,
      feature_schema_id: this.featureSchemaId,
      hyperparameter_checksum: this.hyperparameterChecksum,
      action: req.action,
      quantity: req.quantity,
      asset: req.asset,
      notional: req.notional,
      notional_currency: req.notionalCurrency ?? "USD",
      multiplier: req.multiplier ?? 1.0,
      order_type: req.orderType ?? "MARKET",
      reduce_only: req.reduceOnly ?? false,
      agent_valid_time: req.validTimeMs ?? Date.now(),
    };
    // venue_id and client_order_id are required by the server (422 if missing).
    if (!req.venueId) throw new Error("venueId is required by IRL (e.g. 'BINANCE')");
    body.venue_id = req.venueId;
    if (req.limitPrice !== undefined)    body.limit_price = req.limitPrice;
    if (req.stopPrice !== undefined)     body.stop_price = req.stopPrice;
    body.client_order_id = req.clientOrderId ?? `irl-${crypto.randomUUID().replace(/-/g, "")}`;
    if (req.heartbeat !== undefined)     body.heartbeat = req.heartbeat;
    if (req.regulatory !== undefined)    body.regulatory = {
      mifid_algo_id:        req.regulatory.mifidAlgoId,
      mifid_decision_maker: req.regulatory.mifidDecisionMaker,
      cftc_cti_code:        req.regulatory.cftcCtiCode,
      cftc_account_type:    req.regulatory.cftcAccountType,
      cat_order_id:         req.regulatory.catOrderId,
      jurisdiction:         req.regulatory.jurisdiction,
    };

    const data = await this.post("/irl/authorize", body);
    return {
      traceId:       data.trace_id,
      reasoningHash: data.reasoning_hash,
      authorized:    data.authorized ?? true,
      shadowBlocked: data.shadow_blocked ?? false,
    };
  }

  /**
   * Bind an exchange execution report to the authorized intent.
   *
   * Call this after receiving confirmation from the exchange — even for
   * rejections. `verificationStatus = MATCHED` on a rejected order means the
   * chain is correctly closed; it does not mean the trade succeeded.
   *
   * @throws {IRLError} If the trace_id is not found (404) or on server error.
   */
  async bind(req: BindRequest): Promise<BindResult> {
    const body: Record<string, unknown> = {
      trace_id: req.traceId,
      exchange_tx_id: req.exchangeOrderId,
      execution_status: req.executionStatus ?? "Filled",
    };
    if (req.executionPrice !== undefined)    body.execution_price = req.executionPrice;
    if (req.executedQuantity !== undefined)  body.executed_quantity = req.executedQuantity;
    // Server field is execution_time_ms; unknown keys are silently ignored.
    if (req.executionTimeMs !== undefined)   body.execution_time_ms = req.executionTimeMs;
    if (req.executedSide !== undefined)      body.executed_side = req.executedSide;
    if (req.asset !== undefined)             body.asset = req.asset;

    const data = await this.post("/irl/bind-execution", body);
    return {
      traceId:             data.trace_id,
      finalProof:          data.final_proof ?? null,
      verificationStatus:  data.verification_status,
      executionStatus:     data.execution_status ?? null,
      divergenceReason:    data.divergence_reason ?? null,
    };
  }

  /** Return the full Reasoning_Trace_v1 JSON for forensic audit replay. */
  async getTrace(traceId: string): Promise<Record<string, unknown>> {
    return this.get(`/irl/trace/${traceId}`);
  }

  /** Return PENDING traces older than `ageSeconds` (default: all PENDING). */
  async getPending(ageSeconds = 0): Promise<{ count: number; traces: unknown[] }> {
    return this.get("/irl/pending", { age_seconds: String(ageSeconds) });
  }

  /** Return EXPIRED and DIVERGENT traces. */
  async getOrphans(): Promise<{ count: number; traces: unknown[] }> {
    return this.get("/irl/orphans");
  }

  /** Return traces where shadow mode intercepted a policy violation. */
  async getShadowViolations(): Promise<{ count: number; traces: unknown[] }> {
    return this.get("/irl/shadow-violations");
  }

  /** Returns `"ok"` if the engine is reachable. */
  async health(): Promise<string> {
    const resp = await this.fetch(`${this.base}/irl/health`, {
      method: "GET",
      headers: this.headers,
    });
    return resp.text();
  }

  // ------------------------------------------------------------------
  // Agent management helpers
  // ------------------------------------------------------------------

  async registerAgent(req: RegisterAgentRequest): Promise<AgentProfile> {
    const body: Record<string, unknown> = {
      name: req.name,
      model_hash_hex: req.modelHashHex,
      max_notional: req.maxNotional,
    };
    if (req.allowedRegimes !== undefined) body.allowed_regimes = req.allowedRegimes;
    // The register response is {agent_id, model_hash_hex, status}; fill the rest
    // from the request.
    const data = await this.post("/irl/agents", body);
    const d = data as Record<string, unknown>;
    return {
      id:             (d.agent_id ?? d.id) as string,
      name:           req.name,
      modelHashHex:   (d.model_hash_hex as string | undefined) ?? req.modelHashHex,
      status:         ((d.status as AgentStatus | undefined) ?? "Active") as AgentStatus,
      maxNotional:    req.maxNotional,
      allowedRegimes: req.allowedRegimes ?? null,
    };
  }

  async listAgents(): Promise<AgentProfile[]> {
    const data = await this.get("/irl/agents");
    return ((data as Record<string, unknown>).agents as unknown[] ?? []).map(
      (a) => IRLClient.parseAgent(a as Record<string, unknown>)
    );
  }

  async suspendAgent(agentId: string): Promise<void> {
    await this.patch(`/irl/agents/${agentId}/status`, { status: "Suspended" });
  }

  async activateAgent(agentId: string): Promise<void> {
    await this.patch(`/irl/agents/${agentId}/status`, { status: "Active" });
  }

  /** Return a single agent profile by UUID. GET /irl/agents/:id */
  async getAgent(agentId: string): Promise<AgentProfile> {
    const data = await this.get(`/irl/agents/${agentId}`);
    return IRLClient.parseAgent(data);
  }

  /**
   * Return a filtered, paginated list of reasoning traces.
   * GET /irl/traces — all params optional.
   */
  async listTraces(params: TraceListParams = {}): Promise<TraceListResult> {
    const q: Record<string, string> = {};
    if (params.agentId !== undefined) q.agent_id = params.agentId;
    if (params.from !== undefined)    q.from = String(params.from);
    if (params.to !== undefined)      q.to = String(params.to);
    if (params.status !== undefined)  q.status = params.status;
    if (params.limit !== undefined)   q.limit = String(params.limit);
    const data = await this.get("/irl/traces", q);
    return { count: data.count as number, traces: data.traces as unknown[] };
  }

  // ------------------------------------------------------------------
  // Admin endpoints — owner-level token required
  // ------------------------------------------------------------------

  /** Current shadow mode state. GET /irl/admin/shadow-mode */
  async getShadowMode(): Promise<ShadowModeResult> {
    const d = await this.get("/irl/admin/shadow-mode");
    return {
      shadowMode: d.shadow_mode as boolean,
      updatedAt:  (d.updated_at as string | null) ?? null,
      updatedBy:  (d.updated_by as string | null) ?? null,
    };
  }

  /**
   * Enable or disable shadow mode. POST /irl/admin/shadow-mode
   * @param enabled - true to enable, false to disable
   * @param reason  - optional human-readable reason (recorded in audit log)
   */
  async setShadowMode(enabled: boolean, reason?: string): Promise<{ shadowMode: boolean; changedBy: string }> {
    const body: Record<string, unknown> = { enabled };
    if (reason !== undefined) body.reason = reason;
    const d = await this.post("/irl/admin/shadow-mode", body);
    return { shadowMode: d.shadow_mode as boolean, changedBy: d.changed_by as string };
  }

  /**
   * Return paginated admin audit log. GET /irl/admin/audit-log
   * Cursor-based: pass result.nextCursor as params.beforeId on next call.
   */
  async getAuditLog(params: AuditLogParams = {}): Promise<AuditLogResult> {
    const q: Record<string, string> = {};
    if (params.action !== undefined)   q.action = params.action;
    if (params.targetId !== undefined) q.target_id = params.targetId;
    if (params.from !== undefined)     q.from = params.from;
    if (params.to !== undefined)       q.to = params.to;
    if (params.beforeId !== undefined) q.before_id = params.beforeId;
    if (params.limit !== undefined)    q.limit = String(params.limit);
    const d = await this.get("/irl/admin/audit-log", q);
    return {
      count:      d.count as number,
      entries:    d.entries as unknown[],
      nextCursor: (d.next_cursor as string | null) ?? null,
    };
  }

  /**
   * GDPR Art. 17 erasure — nullifies PII in all traces for the given agent.
   * POST /irl/admin/gdpr-erase/:agentId
   * Requires KMS_PROVIDER configured server-side.
   */
  async gdprErase(agentId: string): Promise<{ agentId: string; gdprRequestId: string; tracesErased: number; status: string }> {
    const d = await this.post(`/irl/admin/gdpr-erase/${agentId}`, {});
    return {
      agentId:       d.agent_id as string,
      gdprRequestId: d.gdpr_request_id as string,
      tracesErased:  d.traces_erased as number,
      status:        d.status as string,
    };
  }

  /**
   * Issue a new client-role API token. POST /irl/admin/tokens
   * The raw token is returned exactly once — save it immediately.
   */
  async issueToken(clientName: string): Promise<TokenIssueResult> {
    const d = await this.post("/irl/admin/tokens", { client_name: clientName });
    return {
      tokenId:    d.token_id as string,
      clientName: d.client_name as string,
      token:      d.token as string,
    };
  }

  /**
   * Revoke a token by its 12-character token_id prefix.
   * DELETE /irl/admin/tokens/:tokenId
   * Takes effect immediately — server cache is invalidated.
   */
  async revokeToken(tokenId: string): Promise<{ tokenId: string; status: string }> {
    const d = await this.delete(`/irl/admin/tokens/${tokenId}`);
    return { tokenId: d.token_id as string, status: d.status as string };
  }

  // ------------------------------------------------------------------
  // Static utilities
  // ------------------------------------------------------------------

  /**
   * Compute the SHA-256 hex digest of a model configuration object.
   *
   * Keys are sorted and the object is serialized with no extra whitespace
   * (canonical form) before hashing. Register this hash in the MAR.
   *
   * Requires the Web Crypto API (available in Node ≥ 18, all modern browsers).
   *
   * @example
   * ```ts
   * const hash = await IRLClient.computeModelHash({
   *   model: "hmm-v3.1",
   *   features: ["vix", "yield_curve"],
   *   version: "1.0",
   * });
   * ```
   */
  static async computeModelHash(config: Record<string, unknown>): Promise<string> {
    const canonical = JSON.stringify(
      Object.fromEntries(Object.entries(config).sort(([a], [b]) => a.localeCompare(b))),
    );
    const encoded = new TextEncoder().encode(canonical);
    const hashBuf = await crypto.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // ------------------------------------------------------------------
  // Internal HTTP helpers
  // ------------------------------------------------------------------

  private async post(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const resp = await this.fetch(`${this.base}${path}`, {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify(body),
    });
    return IRLClient.handleResponse(resp);
  }

  private async get(
    path: string,
    params?: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    const url = new URL(`${this.base}${path}`);
    if (params) {
      for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    }
    const resp = await this.fetch(url.toString(), {
      method: "GET",
      headers: this.headers,
    });
    return IRLClient.handleResponse(resp);
  }

  private async patch(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const resp = await this.fetch(`${this.base}${path}`, {
      method: "PATCH",
      headers: this.headers,
      body: JSON.stringify(body),
    });
    return IRLClient.handleResponse(resp);
  }

  private async delete(path: string): Promise<Record<string, unknown>> {
    const resp = await this.fetch(`${this.base}${path}`, {
      method: "DELETE",
      headers: this.headers,
    });
    return IRLClient.handleResponse(resp);
  }

  /** Wraps `fetch` with an AbortController timeout. */
  private async fetch(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await globalThis.fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  private static async handleResponse(resp: Response): Promise<Record<string, unknown>> {
    if (resp.ok) {
      const text = await resp.text();
      return text.trim() ? (JSON.parse(text) as Record<string, unknown>) : {};
    }
    let errorCode = "UNKNOWN";
    let message = resp.statusText;
    try {
      const err = (await resp.json()) as { error?: string; message?: string };
      errorCode = err.error ?? "UNKNOWN";
      message = err.message ?? resp.statusText;
    } catch {
      // body wasn't JSON
    }
    throw new IRLError(errorCode, message, resp.status);
  }

  private static parseAgent(data: Record<string, unknown>): AgentProfile {
    return {
      id:             (data.agent_id ?? data.id) as string,
      name:           data.name as string,
      modelHashHex:   data.model_hash_hex as string,
      status:         data.status as AgentStatus,
      maxNotional:    data.max_notional as number,
      allowedRegimes: (data.allowed_regimes as number[] | null) ?? null,
      createdAt:      (data.created_at as string | undefined) ?? undefined,
    };
  }
}
