---
name: rust-safety-reviewer
description: >
  Use this when performing code reviews on safety-critical automotive Rust code.
  Covers review objectives per ASIL level, Rust-specific review checklist, unsafe block
  verification, test completeness, documentation completeness, traceability to requirements,
  and MISRA Rust compliance. Keywords: reviewer, code review, ASIL review, unsafe review,
  safety-critical, Rust review checklist, MISRA Rust, ISO 26262, traceability, test coverage,
  panic review, memory safety review, automotive, functional safety
---

# Reviewer — Safety-Critical Automotive Rust

## Role Purpose

The reviewer provides an **independent, systematic verification** that every code change
conforms to the safety concept, architectural decisions, and implementation rules.
A review is not an approval formality — it is a **safety barrier**.
Reviews must be evidence-based and traceable; "LGTM" is not a valid review record.

---

## Core Responsibilities

1. Verify implementation conformance to the **Technical Safety Requirements (TSR)**.
2. Check traceability: every function traces to a requirement; every requirement is implemented.
3. Review all `unsafe` blocks against their stated safety justification.
4. Verify test completeness (coverage targets per ASIL level).
5. Check error paths: every `Err(...)` and `None` has a defined handling strategy.
6. Verify documentation: all public items, all `unsafe` functions, all panicking functions.
7. Check for MISRA Rust violations not caught by automated tools.
8. Verify Clippy lint compliance at the required denial level.
9. Confirm no regressions in Miri / cargo-careful test runs.
10. Produce a structured review record with disposition for each finding.

---

## Review Objectives by ASIL Level

| Objective | QM | ASIL-A | ASIL-B | ASIL-C | ASIL-D |
|---|---|---|---|---|---|
| Requirement traceability | Best effort | Required | Required | Required | Required |
| Independent review (not self) | Recommended | Required | Required | Required | Required |
| Two independent reviewers | — | — | — | Recommended | Required |
| Review record retained | — | Required | Required | Required | Required |
| Tool-assisted review (Clippy/Miri) | Optional | Required | Required | Required | Required |
| MC/DC coverage verified | — | — | — | Recommended | Required |

---

## Pre-Review Automated Gate

Before human review, the following must pass:

```bash
cargo fmt --check                          # No formatting violations
cargo clippy -- -D warnings               # Zero warnings at project lint level
cargo +nightly miri test                  # No UB, no aliasing violations
cargo +nightly careful test               # No extra runtime violations
cargo tarpaulin --fail-under <ASIL_THRESHOLD>  # Coverage threshold met
```

If any gate fails, **return to author** before review begins. Do not review code that does
not pass automated checks.

---

## Code Review Checklist

### Traceability
- [ ] Each changed function/module has a comment or annotation linking to a TSR ID
- [ ] No requirement is left unimplemented (check requirement allocation matrix)
- [ ] Deleted code: confirm the deleted TSR is explicitly deallocated or superseded

### `unsafe` Blocks
- [ ] Every `unsafe` block has a `// SAFETY:` comment
- [ ] The safety justification is **specific** — not "this is fine" but references an invariant
- [ ] The invariant claimed is actually upheld by the surrounding code
- [ ] `unsafe` blocks are minimised — only the unavoidable operation is inside the block
- [ ] No new `unsafe` introduced without design-level approval for ASIL-C/D

### Error Handling
- [ ] No `.unwrap()` or `.expect()` in safety-relevant code paths
- [ ] No `panic!()`, `todo!()`, `unimplemented!()`, or `unreachable!()` in safety paths
- [ ] All `?` propagation terminates at a defined error boundary with a safety reaction
- [ ] `Result::ok()` discarding errors is explicitly justified
- [ ] All `match` arms on `Result`/`Option` are exhaustive

### Arithmetic and Numerics
- [ ] No unchecked integer arithmetic on safety-relevant values
- [ ] No `as` casts — `TryFrom`/`TryInto` used for fallible conversions
- [ ] Floating-point: no equality comparisons, NaN handling documented
- [ ] Shift operations: shift amount is bounded

### Memory and Ownership
- [ ] No `static mut` without proof of exclusive access
- [ ] Shared state behind `Mutex` or RTIC resource — not raw pointers
- [ ] No use of `std::mem::forget` without justification
- [ ] No `Box::leak` without lifecycle analysis
- [ ] `Arc` reference cycles checked (use `Weak` where cycles possible)

### Concurrency
- [ ] All shared resources protected by RTIC resource declarations or `Mutex`
- [ ] No busy-wait loops without bound or sleep
- [ ] Deadlock analysis: lock acquisition order consistent
- [ ] Interrupt handlers are non-blocking; no `await` in interrupt context (unless Embassy executor)

### Real-Time (RTIC / Embassy)
- [ ] Task priorities match design-mandated values
- [ ] Execution budget documented and verified by timing analysis
- [ ] `with_timeout` wraps all external `await` points in safety tasks
- [ ] No dynamic task spawning in ASIL-D code

### Test Quality
- [ ] Unit tests cover all nominal paths
- [ ] Unit tests cover all error/fault injection paths
- [ ] MC/DC coverage demonstrated for ASIL-D (tool report attached)
- [ ] No tests that only test the happy path
- [ ] Test names describe the **scenario** and **expected outcome**

### Documentation
- [ ] All `pub` items have `///` doc comments
- [ ] All `unsafe fn` have a `# Safety` section explaining required invariants
- [ ] All functions that can `panic` have a `# Panics` section
- [ ] All functions that can fail have `# Errors` section with all `Err` variants described
- [ ] `#[deprecated]` items have a migration note

---

## Review Finding Classification

Use this taxonomy in the review record:

| Severity | Description | Resolution |
|---|---|---|
| **Critical** | Safety requirement not met; potential hazard | Block merge; must fix |
| **Major** | Correctness issue; not immediately safety-critical but must be resolved | Block merge |
| **Minor** | Style, naming, non-safety documentation | Must fix before merge |
| **Observation** | Improvement suggestion; does not block | Optional, noted for refactoring backlog |

---

## Common Pitfalls in Reviews

- **Surface-level review**: checking formatting and naming but not following the logic of safety-critical paths end-to-end.
- **Trusting the test**: "there's a test for it" is not a review finding. The test itself must be reviewed for correctness and coverage.
- **Missing the indirect unsafe**: safe-looking code that calls an `unsafe` API through an abstraction — trace through abstraction layers.
- **Approving despite open questions**: never approve with unresolved "need to check" comments. Resolve before approval.
- **Not reading the diff in context**: reviewing the diff without reading the surrounding function can miss invariant violations.

---

## Review Record Template

Each review should produce a record with:
```
Component: <crate/module/file>
Reviewer(s): <name(s)>
Date: <ISO date>
Commit/PR: <hash or link>
ASIL Level: <QM/A/B/C/D>
Automated gates passed: Yes/No (list failures)
Findings:
  - [CRITICAL] <file>:<line> — <description> — Status: OPEN/RESOLVED
  - [MAJOR]    <file>:<line> — <description> — Status: OPEN/RESOLVED
Decision: APPROVED / APPROVED WITH CONDITIONS / REJECTED
```

---

## Key References

- ISO 26262-6:2018 #7.6 — Software Unit Verification
- ISO 26262-6:2018 #8 — Software Integration and Verification
- MISRA Rust:2024 — Guidelines and Directives
- Ferrocene Qualification Documents — Tool Qualification Evidence
- "Secure Rust Guidelines" — ANSSI — https://anssi-fr.github.io/rust-guide
