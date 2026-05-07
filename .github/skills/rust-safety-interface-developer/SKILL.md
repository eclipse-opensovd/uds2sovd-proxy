---
name: rust-safety-interface-developer
description: >
  Use this when designing, specifying, or reviewing Rust API boundaries, service interfaces,
  trait contracts, or inter-process communication in a safety-critical automotive project.
  Covers type-driven safety, AUTOSAR ara::com service interfaces, state-machine encoding,
  and safety contracts at API boundaries. Keywords: interface developer, API design, Rust traits,
  type-driven safety, newtype pattern, phantom type, state machine, ara::com, FIDL, safety contract,
  precondition, postcondition, AUTOSAR, MISRA Rust, automotive, safety-critical
---

# Interface Developer — Safety-Critical Automotive Rust

## Role Purpose

The interface developer specifies and owns **API contracts and service boundaries**.
An interface is the contract between two independently developed components; in a safety-critical
system it must make **misuse a compile-time error**, not a runtime fault.
Safety properties that can be encoded in types must be encoded in types.

---

## Core Responsibilities

1. Translate **Technical Safety Requirements (TSR)** into typed API contracts.
2. Design Rust `trait` definitions for all cross-component interfaces.
3. Encode state-machine invariants in the **type system** (typestate pattern).
4. Define **error types** that are exhaustive and map to safety reactions.
5. Specify **AUTOSAR ara::com** service interfaces: methods, events, fields.
6. Write machine-readable interface contracts (preconditions, postconditions, invariants).
7. Produce and maintain **FIDL/FDEPL** service definitions where applicable.
8. Ensure every public API has a documented **safety invariant** and **failure mode**.
9. Define versioning and backward-compatibility policy for all published interfaces.
10. Review all cross-ASIL interface points for freedom-from-interference.

---

## Type-Driven Safety Patterns in Rust

### Newtype for Units and Constraints
```rust
/// Velocity in metres per second — cannot be confused with acceleration.
#[repr(transparent)]
pub struct VelocityMps(f32);

impl VelocityMps {
    /// Returns `None` if value is outside the physically valid range [-200.0, 200.0].
    pub fn new(v: f32) -> Option<Self> { ... }
}
```
- Prevents unit confusion (km/h vs m/s) at compile time.
- Validates at construction; once constructed, the value is always valid.

### Typestate for Lifecycle Safety
```rust
pub struct Sensor<State> { inner: SensorInner, _state: PhantomData<State> }
pub struct Uncalibrated;
pub struct Calibrated;

impl Sensor<Uncalibrated> {
    pub fn calibrate(self, data: CalibrationData) -> Result<Sensor<Calibrated>, CalibError> { ... }
}
impl Sensor<Calibrated> {
    pub fn read(&self) -> SensorReading { ... } // Only callable after calibration
}
```
- Reading from an uncalibrated sensor is **impossible** — it does not compile.

### Exhaustive Error Enums
```rust
#[non_exhaustive]
pub enum BrakeActuatorError {
    CommunicationTimeout,
    HardwareFault { fault_code: u16 },
    OutOfRange { requested: f32, limit: f32 },
}
```
- Every variant must have a documented safety reaction in the TSC.
- `#[non_exhaustive]` protects downstream users from non-exhaustive match breakage on extension.

### Safety Contract via `#[requires]` / `#[ensures]` (Prusti/Creusot)
```rust
#[requires(torque >= 0.0 && torque <= MAX_TORQUE)]
#[ensures(result.is_ok() -> actuator_state() == ActuatorState::Engaged)]
pub fn engage_brake(&mut self, torque: f32) -> Result<(), BrakeActuatorError> { ... }
```

---

## AUTOSAR ara::com Interface Design

### Service Definition Checklist
- [ ] Service name follows `<Domain><Function>` naming convention
- [ ] Every Method has a defined timeout and error code set
- [ ] Every Event has a defined update rate and data consistency policy
- [ ] Field get/set/notify semantics documented
- [ ] E2E profile specified for safety-relevant events/methods (E2E Profile 05 for ASIL-D)
- [ ] Service version declared in `.fdepl`

### Common ara::com Safety Pitfalls
- `FindService` with `kAlways` polling — must have a bounded retry/timeout for ASIL compliance.
- Callbacks registered from multiple threads without synchronisation — always use `std::sync::Arc<Mutex<...>>` or RTIC shared resources.
- Large event payload without serialisation validation — always validate at the deserialisation boundary.

---

## Interface Design Checklist

### Contract Completeness
- [ ] Every public function has documented preconditions and postconditions
- [ ] Every `unsafe fn` has a documented safety contract (`# Safety` doc section)
- [ ] Every `Result` return type has all error variants documented
- [ ] Every callback/event has documented threading and execution context
- [ ] Nullable (`Option`) fields are explicitly justified — prefer non-nullable by design

### Type Safety
- [ ] Physical quantities wrapped in newtypes with unit in the name
- [ ] State-dependent operations use typestate pattern or builder pattern
- [ ] Boolean parameters replaced by enums where meaning is not self-evident
- [ ] `usize` / `u32` index types replaced by typed index newtypes where confusion is possible

### Cross-ASIL Boundaries
- [ ] ASIL-D→QM boundary: data written by ASIL-D, read by QM — no trust issue
- [ ] QM→ASIL-D boundary: all inputs validated and range-checked before use in safety function
- [ ] Documented DIA for every cross-ASIL interface
- [ ] E2E protection specified for all cross-partition safety-relevant data

### Versioning
- [ ] Interface version declared (semver: major.minor.patch)
- [ ] Breaking changes require ASIL review and DIA update
- [ ] Deprecated items marked with `#[deprecated(since = "x.y.z", note = "...")]`

---

## Common Pitfalls

- **Stringly typed APIs**: using `String` or `&str` for values that have a finite valid domain — encode as enums or newtypes.
- **Boolean blindness**: `fn set_state(enabled: bool, locked: bool)` — caller order confusion is a latent safety defect. Use `enum State { Enabled, Disabled }`.
- **Hidden preconditions**: functions that silently produce wrong results for invalid inputs rather than returning `Err(...)` — all boundary violations must be observable.
- **Overly wide interfaces**: exposing internal mutability through a wide API surface increases the verification burden. Minimise public API surface to the safety-relevant operations.
- **Missing E2E on cross-ECU data**: omitting E2E protection because "the bus is reliable" — transmission errors are a hardware fault, not a software assumption.

---

## Key References

- AUTOSAR Adaptive R21-11 — ara::com API Specification
- ISO 26262-6:2018 #7.4.6 — Software Unit Design and Implementation
- MISRA Rust:2024 — Dir 4.1 (rely on language type system), Rule 10.x (type conversions)
- Ferrocene Language Specification #6 — Type Safety Guarantees
- Rustonomicon — https://doc.rust-lang.org/nomicon (for unsafe interface contracts)
- "Type-Driven API Design in Rust" — Will Crichton (2021)
- SAE J3061 #8 — Interface Definitions in Cybersecurity Context
