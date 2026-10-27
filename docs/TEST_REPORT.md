# Executed Python Reference Test Report

- Execution date: **2026-10-27** (local working environment).
- Execution command: `PYTHONPATH=src python -m pytest -q`.
- Result: **400 passed, 0 failed**.
- Composition: **190 pre-existing cases + 210 newly executed cases**.
- Extended cases: `tests/test_extended_210.py`, ten semantically distinct security/boundary categories with 21 identified cases each.
- Test runner: `pytest 9.0.2` in this working container.
- Runtime: Local Python 3.13 with SQLite, mock sink effects and HMAC-signed evidence.
- Reports: `docs/pytest-console.txt`, `docs/pytest-junit.xml`, and `docs/TEST_CATALOG.csv`.

**What these results prove:** The asserted reference-model behavior held for
these 400 inputs under the local test environment. The suite exercises real
Python code and SQLite transactions; test collection alone is not counted as a
pass.

**What they do not prove:** Formal patent validity, coverage of every
embodiment, independent real remote-effect attestation, end-to-end trust in
privileged mobile platforms, IETF conformance, or production-grade security.
Existing tests use a mock local effect, not irreversible real-world actions.
