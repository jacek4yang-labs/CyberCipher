# Architecture

## Invariant

```text
Frontend is replaceable. The Rust engine is CyberCipher.
```

The engine exposes a plain Rust API usable from the GUI, a CLI, or a future
MCP server without rewriting algorithms.

## Layout

```text
crates/
  cybercipher-core      typed values, operation model, registry, errors, context
  cybercipher-codec     encoding / radix / byte operations (Milestone 1 set)
  cybercipher-engine    recipe format, incremental executor, registry aggregation
apps/
  cybercipher-gui       Tauri 2 desktop app (thin IPC adapter)
  cybercipher-cli       planned; same engine
ui/                     React + TypeScript frontend
compatibility/          upstream capability matrices
vectors/                test vector material (planned)
docs/
```

Planned crates (added with their milestones, not before): `cybercipher-crypto`
(symmetric/hash/MAC/KDF), `cybercipher-analysis` (entropy/scoring/language),
`cybercipher-attack` (RSA/PRNG/ECC labs), `cybercipher-file` (compression,
containers, carving).

## Typed value system

The engine is not `String -> String`. `cybercipher_core::Value` is an enum:

```rust
enum Value { Bytes(Vec<u8>), Text(String), Integer(BigInt), IntegerList(Vec<BigInt>),
             Json(serde_json::Value), List(Vec<Value>), Null }
```

Operations declare accepted input kinds and an output kind. The executor
coerces losslessly (Text ↔ Bytes only when the conversion is reversible) and
produces structured `InvalidInput` errors otherwise.

Large-data rule: data stays in Rust. The frontend receives `ValuePayload`
snapshots (base64 + lossy preview + size + entropy), not raw megabyte arrays.
Ranged/blob-store support for files arrives with the file milestone.

## Operation model

```rust
trait Operation: Send + Sync {
    fn spec(&self) -> &'static OperationSpec;
    fn execute(&self, input: &Value, params: &ParamMap, ctx: &ExecutionContext)
        -> OpResult<Value>;
}
```

`OperationSpec` carries stable ids, names, categories, input/output kinds, a
parameter schema (the GUI generates forms from it — no per-algorithm React),
cost class (`Instant | Interactive | Heavy | Solver | External`), security
classification (`Modern | Legacy | Broken | Hazmat`), aliases/tags for search,
and first-class `Provenance` (standard, implementation, test vectors).

The registry drives search with alias/tag awareness (e.g. `b64` → From
Base64, `sms4` will → SM4).

## Recipe format (public, versioned)

```json
{ "version": 1,
  "nodes": [ { "id": "n1", "op": "from-hex", "enabled": true, "params": {} } ],
  "edges": [ { "from": "input", "to": "n1" }, { "from": "n1", "to": "output" } ] }
```

Nodes are an ordered linear chain in v1; `edges` make flow explicit and are
validated. The format is stable JSON — Rust internals are never serialized
into it. DAG features (fork/merge/variables/conditions) will extend, not
break, this format.

## Incremental execution

Each stage's cache key chains from its input:

```text
stage_key = xxh3(node_id ‖ op_id ‖ canonical_params ‖ impl_version, prev_stage_key)
```

so changing operation 5 of 10 invalidates exactly stages 5–10. Disabled nodes
record a skip marker in the chain so downstream results cannot be reused from
an enabled run. `IMPL_VERSION` busts the cache when semantics change. The
cache is bounded (512 entries) and lives in the engine, shared by GUI/CLI.

Cost gating: `Auto` mode stops before the first `Heavy`/`Solver`/`External`
operation and reports `blocked_at`; `Manual` runs everything. Execution
context carries cancellation + deadlines; operations check them in loops, and
panics inside operations are caught and converted to `Internal` errors.

## Error model

`OperationError` is typed and serializable: `kind`, `message`, `parameter`,
`expected`, `actual`, `details`. The UI renders this structure directly —
no string parsing. Example: AES-CBC with a non-block-aligned ciphertext
reports the expected/actual lengths and suggested actions.

## Data plane vs control plane

Tauri IPC carries commands, metadata, parameter schemas, small payloads, and
execution control (run ids, cancellation). Multi-hundred-MB data movements
through IPC are explicitly out of scope for the architecture; file-backed
values with Rust-side storage land with the file milestone.

## Concurrency

Tauri commands run heavy work through `spawn_blocking`; CPU-parallel candidate
evaluation (Auto Decode, XOR cracking) will use Rayon; solvers get dedicated
blocking execution with budgets. Nothing CPU-heavy runs on the UI thread.
