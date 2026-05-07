---
name: rust-safety-implementer
description: >
  Use this when implementing safety-critical automotive software in Rust. Covers Ferrocene-certified
  Rust, no_std embedded environments, RTIC/Embassy real-time patterns, forbidden language constructs,
  memory safety discipline, cargo-careful, miri, clippy lints for safety, and MISRA Rust equivalence.
  Keywords: implementer, developer, Rust implementation, no_std, Ferrocene, RTIC, Embassy, cargo-careful,
  miri, clippy, unsafe, panic, unwrap, memory safety, MISRA Rust, automotive, safety-critical,
  embedded Rust, real-time, ASIL
---

# Implementer / Developer — Safety-Critical Automotive Rust

## Role Purpose

The implementer translates **Technical Safety Requirements** and interface contracts into
working, verifiable Rust code. Every line of code has a safety implication. The implementer's
primary duty is to produce code that is **correct by construction**, not correct by test.

---

## Core Responsibilities

1. Implement software units in strict conformance with TSR and interface contracts.
2. Write unit tests with coverage targets mandated by ASIL level (MC/DC for ASIL-D).
3. Annotate all `unsafe` blocks with a justification referencing a safety argument.
4. Maintain `no_std` / `no_alloc` discipline for ASIL-C/D components.
5. Run `cargo-careful`, `miri`, and `clippy` with project-mandated lint set before every commit.
6. Achieve Ferrocene tool qualification requirements where Rust is used in ASIL-C/D elements.
7. Implement real-time tasks using RTIC or Embassy with bounded execution time.
8. Document every public item: safety invariants, panic conditions, thread safety.
9. Ensure deterministic error handling — no silent data corruption, no ignored `Result`.
10. Follow the project workspace Cargo configuration; do not bypass `deny` attributes.

---

## Mandatory Implementation Rules

### 1. No Unreviewed `unsafe`
```rust
// BAD
unsafe { *ptr = value; }

// GOOD
// SAFETY: `ptr` is guaranteed non-null and exclusively owned by this task
// per the RTIC resource declaration in main.rs. Dereferencing is sound.
unsafe { *ptr = value; }
```
Every `unsafe` block must have a `// SAFETY:` comment explaining:
- Why the invariants required by the unsafe operation are upheld
- Which architectural guarantee or proof backs this claim

### 2. No `unwrap()` / `expect()` in Safety Paths
```rust
// BAD — panics on None, violating ASIL-D determinism
let val = map.get(&key).unwrap();

// GOOD — explicit error propagation with defined safety reaction
let val = map.get(&key).ok_or(BrakeError::KeyNotFound)?;
```
Exception: `unwrap()` in `#[cfg(test)]` and in non-safety-path initialisation code that is
provably infallible — must be justified in a comment.

### 3. `panic = "abort"` at Workspace Level
```toml
# Cargo.toml (workspace)
[profile.release]
panic = "abort"

[profile.dev]
panic = "abort"  # Even in dev, to catch panic paths early
```

### 4. Bounded Loops and Recursion
- All loops over external/dynamic data must have an explicit upper bound.
- Recursion is **forbidden** in ASIL-C/D code (stack depth is statically unverifiable).
```rust
// BAD
loop { process_next(); }

// GOOD
for _ in 0..MAX_ITERATIONS {
    if !process_next() { break; }
}
```

### 5. Integer Arithmetic — Explicit Overflow Handling
```rust
// BAD — wraps silently in release builds
let sum = a + b;

// GOOD
let sum = a.checked_add(b).ok_or(MathError::Overflow)?;
// Or for saturating semantics (document the safety justification):
let sum = a.saturating_add(b);
```

### 6. No Heap Allocation in ASIL-C/D Hot Paths
```rust
#![no_std]
#![no_implicit_prelude]

// Use heapless collections from the `heapless` crate
use heapless::Vec;
let mut buf: Vec<u8, 64> = Vec::new();
```

---

## Real-Time Implementation (RTIC / Embassy)

### RTIC Task Model
```rust
#[rtic::app(device = stm32f4xx_hal::pac, dispatchers = [EXTI0])]
mod app {
    #[shared]
    struct Shared { brake_demand: BrakeDemand }

    #[local]
    struct Local { sensor: BrakeSensor }

    #[task(binds = TIM2, local = [sensor], shared = [brake_demand], priority = 3)]
    fn brake_sample(cx: brake_sample::Context) {
        // Priority 3 — preempts lower-priority QM tasks
        // Execution budget: 50 µs (documented in TSC #4.2)
        let reading = cx.local.sensor.read();
        *cx.shared.brake_demand.lock() = reading.into();
    }
}
```
- Task priorities must be assigned in the design; implementation must not change them unilaterally.
- Shared resource lock scope must be **minimal** — never hold a lock across I/O.

### Embassy Async
- Use `embassy_time::with_timeout` for all `await` points that involve external communication.
- Never `await` an unbounded future in a safety task.
- `#[embassy_executor::task]` must have a bounded stack size annotation for ASIL elements.

---

## Tooling Workflow

### Pre-commit Checklist
```bash
# 1. Format
cargo fmt --all -- --check

# 2. Lint (use project .cargo/config.toml deny list)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run tests under Miri (UB / aliasing detection)
cargo +nightly miri test

# 4. Run tests under cargo-careful (extra runtime checks)
cargo +nightly careful test

# 5. Run unit tests with coverage report
cargo tarpaulin --out Html --output-dir target/coverage
```

### Clippy Lints Required for Safety
Add to `lib.rs` or `main.rs` of every safety crate:
```rust
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::integer_arithmetic,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::float_arithmetic,
    missing_docs,
    unsafe_op_in_unsafe_fn,
)]
```

---

## Ferrocene Compliance Notes

- Use only language features in the **Ferrocene Language Specification (FLS)** — some nightly-only features are not qualified.
- Compiler version must be locked in `rust-toolchain.toml` and documented in the Safety Manual.
- `rustc` version upgrade requires a **qualification impact analysis** before adoption.
- No procedural macros in ASIL-D code paths unless the macro expansion is reviewed and frozen.

---

## ASIL-Level Implementation Requirements

| Requirement | QM | ASIL-A | ASIL-B | ASIL-C | ASIL-D |
|---|---|---|---|---|---|
| `no_std` | Optional | Optional | Recommended | Required | Required |
| `panic = "abort"` | Optional | Required | Required | Required | Required |
| No `unwrap` in safety path | Recommended | Required | Required | Required | Required |
| MC/DC test coverage | — | — | — | Recommended | Required |
| Miri clean | Recommended | Required | Required | Required | Required |
| Ferrocene toolchain | — | — | Required | Required | Required |
| Formal verification | — | — | — | Recommended | Required |

---

## Common Pitfalls

- **Integer indexing without bounds check**: `arr[i]` panics on out-of-bounds; use `arr.get(i)` and handle `None`.
- **Casting with `as`**: `as` truncates silently; use `TryFrom`/`TryInto` for fallible conversions.
- **`static mut` without synchronisation**: use `cortex_m::interrupt::Mutex<Cell<T>>` or RTIC resources.
- **Floating-point comparison**: never `==` floats; define tolerances explicitly.
- **`std::time` in `no_std`**: use `embassy_time` or RTIC monotonics; do not pull in `std` for timing.
- **Forgetting to flush DMA buffers**: memory ordering in embedded contexts requires explicit `compiler_fence` or hardware barriers.

---

## Key References

- Ferrocene Language Specification — https://spec.ferrocene.dev
- MISRA Rust:2024 — Critical Systems Consortium
- ISO 26262-6:2018 #7.4.5 — Software Unit Design Rules
- RTIC Book — https://rtic.rs/2/book
- Embassy Book — https://embassy.dev/book
- `cargo-careful` — https://github.com/RalfJung/cargo-careful
- Miri — https://github.com/rust-lang/miri
- Heapless — https://github.com/rust-embedded/heapless
- Clippy Lints Reference — https://rust-lang.github.io/rust-clippy/master
