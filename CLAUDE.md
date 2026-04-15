# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```bash
# Build (requires libndpi >= 5.0.0 system library, located via pkg-config)
cargo build --release

# Build the ndpiReader example
cargo build --examples

# Run all tests (need libndpi installed)
cargo test

# Run a single test file
cargo test --test ndpi_detection

# Run the example
cargo run --example ndpiReader -- -i sample.pcap
```

## Architecture

This is a safe Rust binding crate for libndpi (the nDPI deep packet inspection C library). The generated FFI bindings are not committed — `build.rs` runs at compile time, using `bindgen` to generate `src/ffi.rs` from the headers listed in `wrapper.h`.

**Layer stack (bottom-up):**

1. **`src/ffi.rs`** — Auto-generated raw C bindings (`include!`d from `$OUT_DIR/bindings.rs`). Contains all `ndpi_*` extern functions, types, and constants.

2. **`src/error.rs`** — `NdpiError` enum for library initialization failures.

3. **`src/version.rs`** — Queries the linked libndpi for revision, API version, and gcrypt version.

4. **`src/risk.rs`** — Converts risk bitfields to human-readable strings. Also re-exported as methods on `NdpiFlow`.

5. **`src/types.rs`** — `NdpiProtocol` (detection result: master/app protocol, breed, category) and `FlowHttp` (extracted HTTP metadata from a flow).

6. **`src/detection.rs`** — `NdpiGlobalCtx` and `NdpiDetection`. The global context is an optional shared init; each detection module wraps a `ndpi_detection_module_struct`. Provides `process_packet`, `giveup`, config get/set, and protocol/category name lookups.

7. **`src/flow.rs`** — `NdpiFlow` (per-flow state allocated with `ndpi_flow_malloc`) and `NdpiFlowInputInfo` (packet direction + flow-beginning flags). Exposes risk checks, protocol/category extraction, and HTTP metadata extraction.

8. **`src/lib.rs`** — Re-exports the main public types and adds free functions `get_breed_name` / `get_breed_by_name`.

**Key patterns:**
- All C allocation is RAII-wrapped: each wrapper struct has a `Drop` impl that calls the corresponding `ndpi_exit_*` / `ndpi_*_free` function.
- Opaque C struct pointers (`ndpi_detection_module_struct`, `ndpi_global_context`) are never dereferenced on the Rust side — all access goes through C API calls.
- C strings use `std::ffi::CStr`; string config values are returned as owned `String`.
- `NdpiDetection` must be configured before `.finalize()` is called; after finalization, config changes may not be allowed.

**Dependencies:** `libc` (runtime), `bindgen` + `pkg-config` (build-time). Example app additionally depends on `pcap`, `etherparse`, `clap`, `ctrlc`, `rapidhash`.

**License note:** This crate is MIT, but libndpi is LGPLv3 — binaries linking libndpi must comply with LGPLv3.
