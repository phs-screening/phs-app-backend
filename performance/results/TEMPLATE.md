# Issue 1 performance result

## Run identity

| Field | Value |
| --- | --- |
| Result type | baseline / comparison |
| Date and timezone | |
| Operator | |
| Scenario version | |
| Workload profile | single-user / active-50 / burst-50 |
| Run number | 1 / 2 / 3 |
| Frontend commit | |
| Frontend worktree | clean / dirty |
| Backend commit | |
| Backend worktree | clean / dirty |
| Command | |
| Raw output location | |

## Environment

| Field | Value |
| --- | --- |
| Test-runner location and specification | |
| Backend location and specification | |
| Backend instance count | |
| Node version | |
| MongoDB tier and region | |
| MongoDB driver/pool configuration | |
| Dataset or snapshot identifier | |
| Seeded patient count | |
| Reserved write-patient range | |
| Frontend hosting/build mode | |

## Primary results

| Metric | p50/mean | p95 | p99 | Target | Pass? |
| --- | ---: | ---: | ---: | ---: | --- |
| Patient-selection duration (ms) | | | | 1,000 ms p95 | |
| Form-save duration (ms) | | | | 1,000 ms p95 | |
| Happy-flow failure rate (%) | | | | <1% | |
| Patient-selection DB commands | | | | <=5 p95 | |
| Form-save critical-path DB commands | | | | <=5 p95 | |

## Secondary results

| Metric | p50/mean | p95 | p99 | Notes |
| --- | ---: | ---: | ---: | --- |
| Station-recalculation duration (ms) | | | | |
| Patient-selection HTTP requests | | | | |
| Form-save consistency delay (ms) | | | | |
| HTTP requests/s | | | | |
| Iteration duration (ms) | | | | |
| MongoDB pool wait (ms) | | | | unavailable if not instrumented |

## Correctness checks

| Check | Failures |
| --- | ---: |
| Expected HTTP status | |
| `result: true` | |
| Correct patient selected | |
| Expected station state | |
| Form persisted | |
| Station counts converged | |
| Form A queued exactly once | |

## Comparison

Complete this section for an optimized run.

| Metric | Baseline | Current | Change |
| --- | ---: | ---: | ---: |
| Patient-selection p95 | | | |
| Form-save p95 | | | |
| Patient-selection DB commands p95 | | | |
| Form-save DB commands p95 | | | |
| Happy-flow failure rate | | | |

## Observations and deviations

- None.

## Conclusion

Pending.
