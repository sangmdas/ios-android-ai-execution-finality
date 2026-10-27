# Executed 400-Case Test Matrix and Coverage Boundaries

## Actually executed software-model tests

This repository has **400 passed pytest test cases**: 190 original test cases
in `tests/test_*.py` plus 210 additional, distinctly identified cases in
`tests/test_extended_210.py` (10 groups of 21). See `docs/TEST_CATALOG.csv`
for the complete catalog of `pytest` node IDs.

| ID prefix | New cases | Check and failure boundary | Series source orientation |
| --- | ---: | --- | --- |
| x01 | 21 | Canonical JSON commitments and semantic equality, including Unicode and nested fields | CW-1, Parts 1/3/7 |
| x02 | 21 | Malformed candidate inputs and nested data rejection | CW-1, Parts 1/2 |
| x03 | 21 | Resource/operation/route grant scoping and denial | CW-1, Parts 1/3/5 |
| x04 | 21 | Authenticated observation of *different* actual operation burns non-bearer nonce | CW-1, Parts 4/7 |
| x05 | 21 | Multi-field tampering of signed enablement cannot poison legitimate nonce state | CW-1, Parts 3/4 |
| x06 | 21 | Inauthentic modification of trusted gateway observation is rejected without burning nonce | CW-1, Parts 3/4/11 |
| x07 | 21 | Current clock versus expiry; strict inclusive cutoff | CW-1, Parts 3/10 |
| x08 | 21 | Two simultaneously prepared effects compete against current sink-local quota | Emb. 11/22 (limited concept), Parts 5/12 |
| x09 | 21 | Accepted actual local mock predecessor effect is bound to exact successor dependency digest | CW-2, Emb. 2 (limited concept), Part 6 |
| x10 | 21 | Precommit crash, commit/ACK loss and replay across effect families | Emb. 12/16 (limited concepts), Part 8 |
| existing | 190 | Earlier canonicalization, source scoping, actual-operation binding, generation changes, quota races, receipts, and crash behavior | Selected CW-1/CW-2 / Part 1 core |
| **Total** | **400** | **Executed reference model only** | **Not a 40-embodiment implementation** |

## Major gaps — NOT implemented or covered by these 400 tests

- No real iOS, iPadOS, macOS or Android privileged/kernel-level enforcement.
- No Linux LSM/eBPF mediation, TEE, HSM, DPU, SmartNIC, satellite or physical-actuator command control.
- No real multi-domain atomicity or independently witnessed external-payment settlement.
- No verified secure implementation of every numbered Embodiment 1–40 or M-category embodiment.
- No real OAuth/COSE/RATS protocol conformance tests or certified platform integration.
- No machine-checked formal security proof, fuzzing coverage assurance, or third-party security audit.
- No proof that product systems from Apple, Google, Meta or other vendors use this architecture.

The **400 tests are a rigorous sample suite for this limited executable core**, not
400 complete embodiment conformance tests. More modules and implementation
capabilities are necessary for true full-series test coverage.

## Reproducibility criteria

Run `python -m pytest -q` after installing the package and `pytest`.
Save environment versions, console output, JUnit XML and the repository commit
hash when publishing. Mark results as local/model-only and date them. See
`docs/TEST_REPORT.md` and `docs/TEST_CATALOG.csv`.
