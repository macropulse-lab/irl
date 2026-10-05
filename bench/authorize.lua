-- IRL Engine — wrk benchmark script for POST /irl/authorize
--
-- Usage:
--   IRL_API_TOKEN=<token> AGENT_ID=<uuid> MODEL_HASH=<64-char-hex> \
--     wrk -t8 -c500 -d60s -s bench/authorize.lua http://localhost:4000/irl/authorize
--
-- Environment variables (set before running wrk):
--   IRL_API_TOKEN  — bearer token issued via POST /irl/admin/tokens
--   AGENT_ID       — UUID of a registered, Active agent
--   MODEL_HASH     — 64-char hex SHA-256 matching the agent's registered model_hash_hex
--
-- The script randomises trace_id, client_order_id, and agent_valid_time on every
-- request so that each authorize call is treated as a unique decision event.

local token      = os.getenv("IRL_API_TOKEN") or error("IRL_API_TOKEN not set")
local agent_id   = os.getenv("AGENT_ID")      or error("AGENT_ID not set")
local model_hash = os.getenv("MODEL_HASH")    or error("MODEL_HASH not set")

-- Validate model_hash length at startup (must be 64 hex chars = 32 bytes SHA-256)
if #model_hash ~= 64 then
    error("MODEL_HASH must be exactly 64 hex characters (32-byte SHA-256)")
end

math.randomseed(os.time())

-- Generate a random UUID v4 (simplified — sufficient for load testing)
local function uuid()
    local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
    return (template:gsub("[xy]", function(c)
        local v = (c == "x") and math.random(0, 15) or math.random(8, 11)
        return string.format("%x", v)
    end))
end

-- Return current Unix time in milliseconds
local function now_ms()
    -- wrk runs in Lua 5.1; socket.gettime() is not available without luasocket.
    -- os.time() returns seconds; multiply for ms.
    return os.time() * 1000
end

-- Randomise order parameters across a small set of realistic assets and venues
local assets  = { "BTC-USD", "ETH-USD", "SOL-USD", "AVAX-USD" }
local venues  = { "CBSE", "BINC", "KRKN" }
local actions = { "Long", "Short" }

function request()
    local asset      = assets[math.random(#assets)]
    local venue      = venues[math.random(#venues)]
    local action_str = actions[math.random(#actions)]
    local quantity   = math.random(1, 100) * 0.01          -- 0.01 – 1.00 units
    local notional   = quantity * math.random(20000, 70000) -- rough USD notional

    -- agent_valid_time must be strictly less than txn_time (server clock).
    -- Use now_ms() - 50ms so the bitemporal constraint is always satisfied.
    local valid_time_ms = now_ms() - 50

    local body = string.format([[{
  "agent_id":              "%s",
  "model_hash_hex":        "%s",
  "model_id":              "gpt-4o-bench",
  "prompt_version":        "v1.0.0",
  "feature_schema_id":     "schema-bench-v1",
  "hyperparameter_checksum": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
  "action":                {"%s": %s},
  "asset":                 "%s",
  "order_type":            "MARKET",
  "venue_id":              "%s",
  "quantity":              %s,
  "notional":              %s,
  "limit_price":           null,
  "client_order_id":       "%s",
  "agent_valid_time":      %s,
  "heartbeat":             null,
  "reduce_only":           false
}]],
        agent_id,
        model_hash,
        action_str, (action_str == "Neutral" and "null" or quantity),
        asset,
        venue,
        quantity,
        notional,
        uuid(),
        valid_time_ms
    )

    wrk.method  = "POST"
    wrk.body    = body
    wrk.headers["Content-Type"]  = "application/json"
    wrk.headers["Authorization"] = "Bearer " .. token

    return wrk.format(nil, "/irl/authorize")
end

function response(status, headers, body)
    -- Count non-2xx responses separately so they appear in wrk summary
    if status ~= 200 and status ~= 201 then
        io.stderr:write(string.format("[WARN] HTTP %d: %s\n", status, body))
    end
end

function done(summary, latency, requests)
    io.write("\n=== IRL Engine Benchmark Summary ===\n")
    io.write(string.format("Requests/sec : %.2f\n", summary.requests / (summary.duration / 1e6)))
    io.write(string.format("p50 latency  : %.2f ms\n", latency:percentile(50)  / 1000))
    io.write(string.format("p95 latency  : %.2f ms\n", latency:percentile(95)  / 1000))
    io.write(string.format("p99 latency  : %.2f ms\n", latency:percentile(99)  / 1000))
    io.write(string.format("p99.9 latency: %.2f ms\n", latency:percentile(99.9)/ 1000))
    io.write(string.format("Errors       : %d\n",      summary.errors.status + summary.errors.connect + summary.errors.timeout))
    io.write("=====================================\n")
end
