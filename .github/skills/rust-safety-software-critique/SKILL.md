---
name: rust-safety-software-critique
description: >
  Use this when performing adversarial software critique, formal analysis, static analysis,
  fuzzing, or worst-case execution time analysis on safety-critical automotive Rust code.
  Covers Kani model checker, Creusot/Prusti formal verification, cargo-fuzz, AFL, abstract
  interpretation, and structured fault injection. Keywords: software critique, adversarial review,
  formal verification, Kani, Creusot, Prusti, fuzzing, cargo-fuzz, AFL, static analysis,
  WCET, worst-case execution time, fault injection, robustness, safety-critical, automotive, Rust
---

# Software Critique — Safety-Critical Automotive Rust

## Role Purpose

The software critique role applies **adversarial, tool-assisted analysis** to find defects
that escape normal review and testing. This role does not accept "it looks correct" —
it demands **proof or evidence** that correctness holds under all relevant conditions,
including hardware faults, injection attacks, malformed inputs, and adversarial timing.

This role is distinct from the Reviewer: the Reviewer checks conformance; the Software Critique
**challenges** whether conformance is actually sufficient and hunts for latent defects.

---

## Core Responsibilities

1. Apply formal verification (Kani, Creusot, Prusti) to safety-critical state transitions.
2. Run fuzzing campaigns (cargo-fuzz, AFL++) against all external input parsers and deserialisers.
3. Perform structured fault injection to validate all safety reactions.
4. Conduct worst-case execution time (WCET) analysis for all ASIL-C/D real-time tasks.
5. Run abstract interpretation or data-flow analysis for integer overflow / array bounds.
6. Challenge the completeness of safety mechanisms: are all failure modes covered?
7. Verify that error paths are actually reachable and exercised.
8. Identify dead code, unreachable branches, and code that cannot be tested.
9. Analyse stack depth for all RTIC/Embassy tasks.
10. Produce a critique report with evidence or proof for each claim.

---

## Formal Verification with Kani

Kani is a bit-precise model checker for Rust — it exhaustively verifies properties over
all possible inputs within bounds.

### When to Use Kani
- Arithmetic invariants (no overflow in a specific computation)
- State machine completeness (every input leads to a defined next state)
- Pointer safety in `unsafe` abstractions
- Absence of panics in a bounded input domain

### Example: Proving No Overflow
```rust
#[cfg(kani)]
#[kani::proof]
fn verify_velocity_addition_no_overflow() {
    let a: i16 = kani::any();
    let b: i16 = kani::any();
    // Constrain to valid physical range
    kani::assume(a >= -1000 && a <= 1000);
    kani::assume(b >= -1000 && b <= 1000);
    // Should never overflow within these bounds
    let result = a.checked_add(b);
    assert!(result.is_some());
}
```

### Example: Proving Absence of Panics
```rust
#[cfg(kani)]
#[kani::proof]
fn verify_parse_no_panic() {
    let len: usize = kani::any();
    kani::assume(len <= 64);
    let mut buf = vec![0u8; len];
    // Kani will symbolically explore all byte values
    let _ = parse_frame(&buf); // must not panic
}
```

---

## Formal Verification with Creusot / Prusti

Use for **contract-based verification** — proving that `#[requires]` / `#[ensures]` hold:

```rust
// Creusot
#[requires(torque >= 0.0f32 && torque <= @MAX_TORQUE)]
#[ensures(result == Ok(()) -> actuator_engaged())]
pub fn engage_brake(torque: f32) -> Result<(), BrakeError> { ... }
```

Prioritise for:
- Safety-critical arithmetic (saturation, clamping)
- State machine transition guards
- Parser correctness proofs

---

## Fuzzing (cargo-fuzz / AFL++)

### Setup
```toml
# fuzz/Cargo.toml
[dependencies]
libfuzzer-sys = "0.4"
```

```rust
// fuzz/fuzz_targets/fuzz_frame_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic, must not produce UB
    let _ = FrameParser::parse(data);
});
```

```bash
cargo +nightly fuzz run fuzz_frame_parser -- -max_total_time=3600
```

### Fuzzing Targets (Mandatory for Safety)
- [ ] All network/bus message parsers (CAN, SOME/IP, DoIP, Ethernet)
- [ ] All deserialisation code (JSON config, binary config)
- [ ] All input validation functions at system boundaries
- [ ] Any `unsafe` code that processes external data

### Fuzzing Coverage Expectations
- ASIL-B: minimum 1 hour per fuzz target, no crashes
- ASIL-C/D: minimum 24 hours per fuzz target, structured corpus, no crashes

---

## Structured Fault Injection

### Software Fault Injection
Inject erroneous inputs at every external interface and verify safety reactions:

```rust
#[test]
fn fault_injection_comm_timeout_triggers_safe_state() {
    let mut sut = BrakeController::new(MockComm::timeout_after(Duration::from_millis(10)));
    sut.update(); // triggers timeout path
    assert_eq!(sut.state(), ControllerState::SafeState);
    assert_eq!(sut.actuator_demand(), ActuatorDemand::FullRelease);
}
```

### Fault Injection Matrix
For every safety mechanism in the TSC, there must be a corresponding fault injection test:

| Safety Mechanism | Fault Injected | Expected Reaction |
|---|---|---|
| Communication watchdog | Message timeout | → Safe state |
| Range check on sensor input | Out-of-range value | → Default / last valid |
| CRC / E2E check | Corrupted payload | → Frame discarded, counter incremented |
| Heartbeat / alive counter | Missing heartbeat | → Controlled shutdown |

---

## Worst-Case Execution Time (WCET)

### Methods
1. **Measurement-based**: instrument with cycle counters, run over representative + worst-case data.
2. **Static WCET tools**: OTAWA, AbsInt aiT — required for ASIL-D if measurement alone is insufficient.

### RTIC Task WCET Template
```rust
#[task(binds = TIM2, priority = 3)]
fn safety_task(cx: safety_task::Context) {
    let start = DWT::cycle_count();
    // --- task body ---
    let elapsed = DWT::cycle_count().wrapping_sub(start);
    // Assert: elapsed <= BUDGET_CYCLES (defined in TSC)
    debug_assert!(elapsed <= BUDGET_CYCLES, "WCET budget exceeded: {}", elapsed);
}
```

### Stack Depth Analysis
```bash
# cargo-call-stack — visualise stack depth per task
cargo +nightly call-stack --target thumbv7em-none-eabihf --example rtic_app > stack.dot
dot -Tpng stack.dot -o stack.png
```

---

## Static Analysis Beyond Clippy

### Abstract Interpretation
- Use `frama-c` with the `value` plugin on C FFI boundary code if applicable.
- For pure Rust: Kani covers most abstract interpretation use-cases.

### Data-Flow / Taint Analysis
- Identify all trust boundaries: network → Rust boundary → safety function.
- Trace every input to a safety function: does it pass through a validation step?
- Use `cargo-crev` for supply chain analysis of dependencies.

---

## Critique Report Structure

```
Critique Target: <crate/module>
Critique Type: [Formal | Fuzzing | Fault Injection | WCET | Static | Adversarial]
Date: <ISO date>
Analyst: <name>
ASIL Level: <QM/A/B/C/D>

Findings:
  - [PROOF]     <property> — Verified by Kani proof `<proof_fn>` — Evidence: <artefact>
  - [DEFECT]    <file>:<line> — <description> — Severity: Critical/Major/Minor
  - [GAP]       <missing coverage> — Description — Recommendation

Conclusion: ADEQUATE / INADEQUATE — requires rework before safety sign-off
```

---

## Common Pitfalls

- **Happy-path fuzzing**: only fuzzing valid inputs — fuzzers must explore invalid, truncated, and adversarial inputs.
- **Kani proof coverage gap**: writing proofs only for "interesting" functions, leaving unsafe abstractions unproved.
- **WCET optimism**: measuring best-case (cache warm, no interrupts) and treating it as WCET.
- **Fault injection completeness**: injecting only the faults the designer anticipated — a complete critique also considers faults the designer did not anticipate.
- **Ignoring `#[cfg(test)]` dead code**: test-only code is not in scope for safety, but dead code in production paths is.

---

## Key References

- Kani Verifier — https://github.com/model-checking/kani
- Creusot — https://github.com/creusot-rs/creusot
- Prusti — https://github.com/viperproject/prusti-dev
- cargo-fuzz — https://github.com/rust-fuzz/cargo-fuzz
- AFL++ Rust — https://github.com/rust-fuzz/afl.rs
- cargo-call-stack — https://github.com/japaric/cargo-call-stack
- ISO 26262-6:2018 #9 — Software Testing
- IEC 61508-3:2010 Annex B — Techniques for Software Testing
