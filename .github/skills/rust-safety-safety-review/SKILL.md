---
name: rust-safety-safety-review
description: >
  Use this when conducting a safety review, safety case assessment, ASIL compliance verification,
  safety requirement traceability audit, or functional safety sign-off for a safety-critical
  automotive Rust project. Covers ISO 26262 safety case structure, SOTIF residual risk assessment,
  DFA/DIA, safety manual review, and safety evidence completeness. Keywords: safety review,
  safety case, ISO 26262, ASIL compliance, safety requirement traceability, functional safety,
  SOTIF, DFA, DIA, safety manual, safety evidence, safety sign-off, safety auditor, automotive
---

# Safety Review — Safety-Critical Automotive Rust

## Role Purpose

The safety reviewer provides **independent assurance** that the system as built meets its
safety goals. This role is distinct from code review and software critique: it operates at
the level of the **safety case** — the structured argument that the system is acceptably safe.

The safety reviewer is the last line of defence before system release. Evidence must be
complete, traceable, and sufficient. Assertions without evidence are not accepted.

---

## Core Responsibilities

1. Verify completeness and consistency of the **Safety Case** (safety goals → safety measures → evidence).
2. Audit **safety requirement traceability**: every TSR is implemented, tested, and reviewed.
3. Verify ASIL compliance for each software element: correct techniques, correct evidence.
4. Review **Dependent Failure Analysis (DFA)** and **Dependent Failure Initiation (DFI)** assessment.
5. Verify **Development Interface Agreements (DIA)** are fulfilled.
6. Review the project **Safety Manual** (SEooC assumptions and usage constraints).
7. Assess residual risk: confirm it is below the tolerable hazard rate threshold.
8. Confirm SOTIF completeness: all triggering conditions assessed, residual functional insufficiency documented.
9. Sign off on the **Safety Case Report** or issue a gap list that must be closed before sign-off.
10. Maintain independence: the safety reviewer must not have been involved in the design or implementation of the artefact under review.

---

## Safety Case Structure (ISO 26262)

A complete safety case for a software element consists of:

```
Safety Case
├── Item Definition
├── Hazard Analysis and Risk Assessment (HARA)
│   ├── Hazardous event list
│   ├── ASIL assignments with justification
│   └── Safe states definition
├── Functional Safety Concept (FSC)
│   ├── Safety goals
│   └── Functional safety requirements
├── Technical Safety Concept (TSC)
│   ├── Technical safety requirements
│   ├── Safety mechanisms specification
│   └── Hardware–software interface (DIA)
├── Software Safety Requirements
│   ├── Requirements allocation to SW elements
│   └── Traceability matrix (requirement ↔ implementation ↔ test)
├── Software Design
│   ├── Architecture specification
│   └── Unit design
├── Implementation Artefacts
│   ├── Source code (reviewed)
│   └── Configuration (reviewed)
├── Verification Evidence
│   ├── Unit test reports (coverage data)
│   ├── Integration test reports
│   ├── Formal verification proofs
│   ├── Fuzzing campaign reports
│   └── Code review records
└── Safety Case Report (this document)
```

---

## Safety Review Checklist

### Safety Goals and HARA
- [ ] All hazardous events identified; none below threshold omitted
- [ ] ASIL assignments justified with S, E, C parameter rationale
- [ ] Safe states defined: are they physically achievable and maintained?
- [ ] Safety goals are free of implementation assumptions
- [ ] QM elements documented; QM argument does not weaken ASIL argument

### Requirement Traceability
- [ ] Traceability matrix exists: Safety Goal → FSR → TSR → SW Requirement → Code → Test
- [ ] No TSR without at least one implementing code element
- [ ] No TSR without at least one verification test (by test or formal proof)
- [ ] No orphaned requirements (requirement allocated to nothing)
- [ ] Change impact: any code change that affects a TSR has a corresponding requirement update

### ASIL Compliance (per Software Element)
- [ ] ASIL-A/B: modelling, structured design, semi-formal methods applied
- [ ] ASIL-C: formal notation, structured testing (boundary value, equivalence partition)
- [ ] ASIL-D: formal methods, MC/DC coverage, independent review by two reviewers
- [ ] `unsafe` budget justified and reviewed per ASIL level
- [ ] Ferrocene toolchain qualification evidence available for ASIL-C/D

### Software Safety Mechanisms
- [ ] Each safety mechanism in TSC has a corresponding implementation
- [ ] Each safety mechanism has a fault injection test proving it activates correctly
- [ ] Watchdog configuration: correct timeout, correct reaction
- [ ] E2E protection: correct profile, correct configuration, tested for CRC failure
- [ ] Memory protection (MPU): correct region configuration for ASIL isolation

### Dependent Failure Analysis
- [ ] DFA has been conducted for all ASIL-decomposed elements
- [ ] Independence argument documented (spatial, temporal, and information independence)
- [ ] Common cause failures identified (shared power supply, shared clock, shared OS, shared Rust crate)
- [ ] Shared Rust crates used in decomposed elements: version frozen, qualification evidence present

### SOTIF (ISO 21448) Assessment
- [ ] Intended functionality specification complete
- [ ] All triggering conditions (known/unknown) catalogued
- [ ] Operational design domain (ODD) defined and constrains the safety case
- [ ] Residual functional insufficiency documented and accepted by risk authority
- [ ] Validation methods (scenario-based testing, field monitoring) defined

### Safety Manual (SEooC)
- [ ] Assumptions of use (AoU) listed for all components developed as Safety Elements out of Context
- [ ] All AoU are verifiable by the integrator
- [ ] Constraints on integration documented (OS requirements, memory requirements, timing constraints)
- [ ] Supported ASIL levels stated per component

### Verification Evidence Completeness
- [ ] All unit test reports present and passing
- [ ] Coverage data meets ASIL threshold (MC/DC for ASIL-D)
- [ ] Integration test reports present
- [ ] Formal proof artefacts present (Kani proofs, Creusot contracts)
- [ ] Fuzzing reports present with campaign duration and corpus coverage
- [ ] Code review records present for all safety-relevant files

---

## ASIL Compliance Evidence Matrix

| Evidence Type | QM | ASIL-A | ASIL-B | ASIL-C | ASIL-D |
|---|---|---|---|---|---|
| Unit test report | — | Required | Required | Required | Required |
| Statement coverage | — | — | Required (70%) | Required (80%) | — |
| Branch coverage | — | — | — | Required | — |
| MC/DC coverage | — | — | — | Recommended | Required |
| Code review record | — | Required | Required | Required | Required (×2) |
| Formal proof | — | — | — | Recommended | Required (partial) |
| Fuzzing report | — | — | Recommended | Required | Required |
| WCET analysis | — | — | Recommended | Required | Required |
| Dependency audit | — | Required | Required | Required | Required |

---

## Residual Risk Assessment

For each safety goal, verify:
1. **Residual risk** = (probability of safety goal violation) × (severity) < Tolerable Hazard Rate (THR)
2. THR derivation: ISO 26262 Table D.5 — typically 10⁻⁸/h to 10⁻⁹/h per fatality
3. Probabilistic arguments for random hardware failures must use IEC 61508 / ISO 26262 Part 5 methods
4. Systematic failures covered by safety process compliance (not probability)

---

## Common Safety Review Failures

- **Evidence mismatch**: test report covers a different software version than the one under review.
- **Circular argument**: "the software is safe because it passed review" without independent evidence.
- **Incomplete traceability**: requirements with no test, or tests with no requirements.
- **Outdated DIA**: hardware interface changed but DIA not updated.
- **SEooC AoU not verified**: the integrator assumed AoU are met without performing the verification.
- **SOTIF gap**: perception-based functions have no SOTIF analysis — treated solely as ISO 26262 problem.

---

## Safety Case Sign-Off Criteria

Sign-off is granted when:
1. All safety case artefacts are present, reviewed, and version-consistent
2. All traceability chains are complete (no gaps)
3. All verification evidence meets the ASIL-mandated methods and coverage targets
4. All DFA/DIA agreements are fulfilled
5. Residual risk is documented and accepted by the functional safety manager
6. No open safety-critical findings from code review or software critique

Sign-off must be recorded with: reviewer name, date, artefact version, and any conditional notes.

---

## Key References

- ISO 26262-2:2018 — Management of Functional Safety (Safety Case structure)
- ISO 26262-6:2018 — Software-Level Product Development
- ISO 26262-9:2018 — ASIL-Oriented and Safety-Oriented Analysis (DFA)
- ISO 26262-10:2018 — Guidelines
- ISO 21448:2022 — SOTIF
- IEC 61508-1:2010 #8 — Safety Case
- SAE J3061:2016 #9 — Cybersecurity Case
- AUTOSAR Adaptive — Software Component Description (SWCD) as evidence artefact
