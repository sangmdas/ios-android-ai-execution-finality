# DAS Execution-Finality: Runnable Reference Model and 400 Executed Tests

> **Experimental research code**. A small, vendor-neutral Python/SQLite reference model,
> **not** production authorization software, an operating-system enforcement module,
> certified hardware security, or evidence that any commercial system uses the invention.

**Research series:** *Secure AI Execution-Finality, Cross-Platform Interoperability,
 and Hardware Security — A Twelve-Part Technical Specification Series*.

**Technical origin:** *iOS and Android Interoperability for Secure Third Party AI Tools —
 Cross-Platform Execution Finality, Hardware Security, and Interoperability
 (3,567-Page Specification)*, [Zenodo record 23657985](https://zenodo.org/records/23657985),
 DOI [10.5281/zenodo.23657985](https://doi.org/10.5281/zenodo.23657985).
 Principal patent disclosure identified by the inventor: **PCT/IB2026/055615**,
 filed **4 June 2026** (WO 2026/150382); patent/IPR status and licensing
 require separate verification and formal disclosures. This software was assembled
 as a later experimental companion; it does **not** inherit the priority date of
 the original patent filing merely by referring to it.

**Published Part 1 IETF reference:** [draft-das-interoperable-consequence-authority-01](https://datatracker.ietf.org/doc/draft-das-interoperable-consequence-authority/) — *Secure AI Execution-Finality for iOS, Android, and Cross-Platform AI Agents, Part 1: Foundational Consequential Authority and Common Workflows*. See [versioned IETF and IPR notes](docs/IETF_PART1_REFERENCE.md).

**Repository licensing:** [Non-Commercial Research and Evaluation License v1.0](LICENSE). Read and test for personal/academic research and limited internal, non-production evaluation, including technical assessment by engineers employed by commercial organizations. Commercial product use and production deployment require separate written permission. **No patent license is granted.** This GitHub software license does not apply to the IETF Internet-Draft. This custom license is not OSI approved.

**Test status:** **400 / 400 pytest cases passed locally on 27 October 2026** for this limited Python/SQLite model (190 original cases plus 210 expanded security/boundary cases). See [the test report](docs/TEST_REPORT.md), [test matrix](docs/TEST_MATRIX.md) and [full test catalog](docs/TEST_CATALOG.csv). Passing the model suite does not validate every patent embodiment or production platform.

## What the prototype actually executes

A real Python program enforces mock consequential operations through a protected-state
simulation using SQLite transactions. It demonstrates:

1. **Candidate Act** — canonical operation descriptor and exact SHA-256 commitment.
2. **Non-Effective State** — issuing protected evidence does not execute the effect.
3. **Protected authority check** — source grant, principal, tenant, route, resource, operation,
   device owner, bounded quota, expiry, and current generation.
4. **Protected evidence preparation** — operation-bound HMAC-signed enablement.
5. **Simulated trusted gateway observation** — independent HMAC-signed actual operation.
6. **Finality Sink** — actual-operation reconstruction/verification against the bound
   descriptor, policy, sink identity, authority generation and mock sink-local state.
7. **Single use and refusal** — authenticated failed attempts burn the scoped nonce;
   unauthenticated forged data cannot burn legitimate state.
8. **Atomic local accounting** — consumption, quota and the mock resource effect
   commit within *one* SQLite transaction.
9. **Causal receipts** — an accepted receipt must identify a recorded actual **local mock**
   predecessor effect and match the successor's exact predecessor-effect digest.
10. **Revocation, ownership epochs, replay, crash simulation and lost ACKs**.

## What it does NOT implement

- Privileged iOS, iPadOS, macOS or Android system hooks, Binder interception,
  sandbox egress interception, Linux LSM, eBPF, TEE, HSM or a SmartNIC/DPU gate.
- Genuine platform-backed non-bearer cryptographic capability guarantees. The
  gateway-signing authority is separate by *model assumption*, not OS-enforced isolation.
- Remotely verifiable effect completion, payment settlement, actual actuator output,
  or an atomic transaction spanning independent systems. The SQLite mock effect
  is local. A real remote connector needs a separately qualified receipt,
  idempotent resource semantics, transaction reconciliation and an audited trust model.
- All 40 numbered embodiments, M-category embodiments, or every workflow variation
  described across the twelve drafts.
- A formal security proof, third-party penetration test, patent-claim evaluation,
  production security certification, or validation of deployed vendor products.

**Do not attach real production credentials or connect this reference to a payment,
cloud, vehicle, telecom, or medical-system command interface.**

## Requirements

Python 3.10+; the reference *runtime* uses only the Python standard library.
Tests use `pytest` (a development dependency).

### Run without installing the package (pytest installed)

```bash
export PYTHONPATH=src
python -m pytest -q
python examples/demo.py
```

Windows PowerShell:

```powershell
$env:PYTHONPATH = 'src'
python -m pytest -q
python examples/demo.py
```

### Install the package on a machine with normal package access

```bash
python -m pip install -e '.[test]'
python -m pytest -q
python examples/demo.py
```

The GitHub Actions workflow runs the 400-case test suite on Python 3.10, 3.12 and 3.13 after upload to GitHub; CI results must be checked after publication.

## How the mocked sink works

```text
  Original permission           Agent-proposed Candidate Act (CA)
           |                                |
           v                                v
  Source authority registry     CA remains non-effective
           |                                |
           +-----------> Protected controller
                               |
                      Operation-bound enablement
                               |
       Trusted observation      v
  Adapter -> signed actual operation -> Finality Sink
                                          |
                           +--------------+-------------+
                           |                            |
                    MATCH / CURRENT                 INVALID / STALE
                           |                            |
                   BEGIN IMMEDIATE                Burn valid nonce
                     record effect                & refuse effect
                   consume nonce/quota                 |
                       COMMIT                      NO EFFECT
                           |
                  Local mock-effect receipt
                  (subject to qualification)
```

No claim is made that a generic HMAC receipt or upstream agent signature is
sufficient to prove a real effect at an uncontrolled remote resource.

## Testing strategy

This repository begins with **190 executed pytest cases** (including individually
collected parametrized examples). They are not 190 independent mathematical proofs,
and do not cover every embodiment. The recommended full-series target is **400 distinct
traceable cases**:

| Family | Target cases |
| --- | ---: |
| CW-1, CW-2, CW-3 (12 each) | 36 |
| Embodiments 1–40 (6 each) | 240 |
| M-1 and M-2 (12 each) | 24 |
| Cross-platform and cross-part interoperability | 60 |
| Adversarial fault injection, crash and integration | 40 |
| **Total** | **400** |

Each future case should have a stable ID, link to the disclosure section,
preconditions, expected acceptance/refusal, observable assertions, and a recorded
execution result. Do not count duplicate tests across draft chapters twice.

The twelve XML drafts previously propose about **332 test descriptions in aggregate**;
these are not yet demonstrated as 332 unique runnable tests.

See [TEST_MATRIX.md](docs/TEST_MATRIX.md) and [LIMITATIONS.md](docs/LIMITATIONS.md).

## Files

```text
src/dasfinality/model.py              canonical operation and evidence structures
src/dasfinality/engine.py             protected-state / sink mock enforcement
examples/demo.py                     runnable allow + replay refusal demonstration
tests/                               executable pytest tests
docs/TEST_MATRIX.md                  draft / embodiment coverage and 400-case roadmap
docs/LIMITATIONS.md                   assumptions, limitations and security gaps
docs/TEST_REPORT.md                  observed local test run summary
.github/workflows/ci.yml             automated multi-version test execution
LICENSE-STATUS.md                    licensing pending explicit author decision
```

## Publication and IPR notice

This code is an explanatory reference model and does not change any previously
filed or published patent specification. Full patent-family details and any
applicable IETF intellectual-property disclosures should be filed separately
under the relevant rules; an IPR paragraph in an Internet-Draft alone does not
replace required formal disclosures.

**Licensing:** No copyright or patent license is granted by this ZIP.
Select and publish the desired LICENSE and any patent licensing statement
before public reuse. If a non-commercial source release is intended, specify it
explicitly; do not label that as an OSI-approved open-source license.
