# Indexed name-search execution-plan evidence

Captured on 8 August 2026 against `phs_dev` after the name-prefix backfill and
index creation. This is read-only `executionStats` evidence, not a comparative
load-test result. The original baseline files were not changed.

| Query | Operation | Returned | Keys examined | Docs examined | Time |
| --- | --- | ---: | ---: | ---: | ---: |
| `Tan` | autocomplete result | 20 | 20 | 0 | 0 ms |
| `Tan` | autocomplete count | 0 | 43 | 0 | 0 ms |
| `Tan` | patient result | 10 | 19 | 19 | 1 ms |
| `Tan` | patient count | 0 | 43 | 0 | 0 ms |
| `Tan` | pre-registration result | 10 | 10 | 10 | 0 ms |
| `Tan` | pre-registration count | 0 | 12 | 0 | 0 ms |
| `Tan M` | autocomplete result | 8 | 42 | 42 | 1 ms |
| `Tan M` | patient result | 8 | 50 | 50 | 1 ms |
| `Tan M` | pre-registration result | 3 | 11 | 11 | 0 ms |
| `Zzxq` | autocomplete result | 0 | 0 | 0 | 0 ms |
| `Zzxq` | patient result | 0 | 0 | 0 | 0 ms |
| `Zzxq` | pre-registration result | 0 | 0 | 0 | 0 ms |

All captured result plans used `IXSCAN`; count plans used `COUNT_SCAN` or
indexed `COUNT` stages. No blocking sort or collection scan was present. The
ignored raw evidence is `2026-08-08-name-search-indexed-explain.json`.
