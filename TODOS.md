# TODOS

## Core

### Split broker.rs into focused modules

**What:** Split `crates/core/src/broker.rs` (3,291 lines) into `broker/{mod,worker,dispatch,requests}.rs` without changing behavior.

**Why:** Security-critical code is easier to review in files under 800 lines, and the macOS work makes this file larger.

**Context:** R1 and R2 of the v1.0 roadmap leave the dispatch critical section in place so their diffs can be reviewed line by line. Do the split after R2 merges. Start at the `mod linux` boundary (currently line 598), and keep it a pure move so the diff reviews as a rename.

**Effort:** M
**Priority:** P3
**Depends on:** R2 (macOS platform and launch path policy) merged

## Completed
