---
name: rust-safety-usability-review
description: >
  Use this when evaluating the developer experience, API ergonomics, documentation quality,
  or learnability of safety-critical automotive Rust APIs. Covers making wrong usage
  a compile error, error message quality, documentation standards, and the principle that
  safety APIs must be hard to misuse. Keywords: usability review, API ergonomics, developer
  experience, documentation quality, compile-time safety, pit of success, Rust API guidelines,
  error messages, discoverability, safety API design, automotive, safety-critical
---

# Usability Review — Safety-Critical Automotive Rust

## Role Purpose

The usability reviewer evaluates whether a safety-critical API is **designed to be used correctly**.
In a safety-critical system, a confusing or error-prone API is itself a safety hazard:
it increases the probability that a developer will misuse it and introduce a defect.

The goal is the **Pit of Success**: the easiest path through the API must be the correct and safe path.
Incorrect usage must be a compile-time error wherever possible, and a clear runtime error where not.

---

## Core Responsibilities

1. Evaluate whether the API makes misuse **impossible or immediately obvious**.
2. Review documentation for clarity, completeness, and example quality.
3. Verify that error messages guide the developer toward the correct fix.
4. Assess discoverability: can a new developer understand what to do without reading source code?
5. Check that safety-relevant constraints are communicated at the call site, not buried in documentation.
6. Verify that API naming is unambiguous in the automotive/safety domain.
7. Test the API from a "new developer" perspective — attempt to misuse it intentionally.
8. Review IDE/tooling integration: rustdoc generation, `cargo doc`, doc-test compilation.
9. Ensure deprecation paths are clear and provide actionable migration guidance.
10. Produce a usability report with severity ratings and concrete improvement suggestions.

---

## The Pit of Success Principle

An API is in the Pit of Success when:
- The default usage is the safe usage
- Unsafe or incorrect usage requires **extra, deliberate steps**
- Compile errors point directly to what is wrong and how to fix it

### Anti-Pattern: Pit of Despair
```rust
// BAD: User must remember to call init() before use — no enforcement
pub struct Controller { ... }
impl Controller {
    pub fn new() -> Self { ... }
    pub fn init(&mut self) { ... }      // MUST be called first!
    pub fn process(&mut self) { ... }   // Panics if init() not called
}
```

### Good Pattern: Typestate Enforcement
```rust
// GOOD: Impossible to call process() before init() — compile error
pub struct Controller<S: ControllerState> { inner: ControllerInner, _s: PhantomData<S> }
pub struct Uninitialised;
pub struct Ready;
impl Controller<Uninitialised> {
    pub fn new() -> Self { ... }
    pub fn init(self) -> Result<Controller<Ready>, InitError> { ... }
}
impl Controller<Ready> {
    pub fn process(&mut self) -> Result<(), ProcessError> { ... }
}
```

---

## API Ergonomics Checklist

### Naming
- [ ] Names are domain-specific and unambiguous (e.g. `BrakeTorqueNm` not `BrakeValue`)
- [ ] Verb-noun pairs are consistent: `engage_brake`, `disengage_brake` — not `set_brake(true/false)`
- [ ] Boolean parameters replaced by enums: `Direction::Forward` not `true`
- [ ] No abbreviations that are not universally known in the automotive domain
- [ ] Units are in the name or in the type: `velocity_mps`, `VelocityMps`

### Construction and Initialisation
- [ ] Builder pattern used where construction has multiple optional steps
- [ ] `new()` is either infallible or returns `Result` — never panics
- [ ] Required parameters are positional; optional parameters use the builder
- [ ] No hidden global state that must be initialised before `new()` works
- [ ] `Default` implementation (if provided) is documented and safe

### Error Handling Ergonomics
- [ ] Error type implements `std::error::Error` (or `core::fmt::Display` for `no_std`)
- [ ] Error variants have human-readable messages that explain **what went wrong**
- [ ] Error messages suggest **how to fix** the problem where possible
- [ ] `?` operator works ergonomically: error types support `From` conversions
- [ ] No `()` error types — they communicate nothing to the caller

### Compile-Time Feedback
- [ ] Misuse of the API produces a clear, actionable compiler error (not "type mismatch")
- [ ] Where custom error messages are possible, `#[diagnostic::on_unimplemented]` is used
- [ ] Trait bounds are minimal and clearly named; opaque `T: A + B + C + D` discouraged
- [ ] Confusing `where` clauses are extracted into named helper traits

### Documentation Quality
- [ ] Every `pub` item has a one-line summary
- [ ] Every function documents: what it does, what it returns, all error cases, panic conditions
- [ ] At least one working example (`///` doctest) per non-trivial public function
- [ ] Doctests compile and pass: `cargo test --doc`
- [ ] Module-level documentation (`//!`) explains the module's purpose and typical usage
- [ ] `cargo doc --no-deps --open` produces a clean, navigable documentation site

### Safety Communication at Call Site
- [ ] Safety-critical functions have a visual indicator in their name or via `#[must_use]`
- [ ] `#[must_use]` applied to `Result` and to functions whose return value must be checked
- [ ] Functions that have ASIL-D implications are documented with a `# Safety Critical` section
- [ ] Rate limits, timing constraints, and ordering requirements are in the doc, not just the TSC

---

## Developer Journey Test

Perform a structured "new developer" test:

1. **Discovery**: Starting only from `cargo doc`, find the function to engage the brake actuator. Is it discoverable within 2 minutes?
2. **Basic usage**: Write a minimal working example from the documentation alone. Does it compile first try?
3. **Error case**: Trigger an error condition intentionally. Is the error message clear enough to fix without reading source?
4. **Misuse attempt**: Try calling a post-init function before init. What happens? (Should: compile error)
5. **Edge case**: Pass an out-of-range value. What happens? (Should: `Err(...)` with a descriptive error)

Document results and attach to the usability report.

---

## Common Usability Anti-Patterns

- **Magic numbers**: `fn set_mode(mode: u8)` — what are valid values? Use an enum.
- **Silent success for invalid input**: returning `Ok(default_value)` when input is out of range instead of `Err(...)` — hides errors.
- **Over-generic types**: `fn process<T: Into<f64> + Copy + PartialOrd>(val: T)` — intimidating, often unnecessary.
- **Inconsistent naming**: `get_velocity()` vs `read_pressure()` vs `fetch_temperature()` — pick one verb per action domain.
- **Undocumented panics**: functions that can panic in production without a `# Panics` section.
- **Leaky abstractions**: exposing raw hardware register types in a supposedly high-level API.

---

## Usability Report Template

```
Component: <crate/module>
Reviewer: <name>
Date: <ISO date>
ASIL Level: <QM/A/B/C/D>

Developer Journey Test Results:
  Discovery:    PASS/FAIL — notes
  Basic usage:  PASS/FAIL — notes
  Error case:   PASS/FAIL — notes
  Misuse:       PASS/FAIL — notes

Findings:
  - [HIGH]   <item> — <problem> — <recommended fix>
  - [MEDIUM] <item> — <problem> — <recommended fix>
  - [LOW]    <item> — <problem> — <recommended fix>

Overall: USABLE / NEEDS IMPROVEMENT / REDESIGN RECOMMENDED
```

---

## Key References

- Rust API Guidelines — https://rust-lang.github.io/api-guidelines
- "Designing for Humans" — Rust API Guidelines Checklist
- `#[diagnostic::on_unimplemented]` — RFC 3368
- ISO 26262-6:2018 #7.4.6 — Constraints on language use affecting developer error
- MISRA Rust:2024 — Readability and maintainability guidelines
- "The Typestate Pattern in Rust" — Cliffle (2021)
