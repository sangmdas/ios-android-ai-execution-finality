# Publishing guide for the 400-test reference repository

1. Create a new GitHub repository named `das-execution-finality-reference`.
2. Download and extract `das-execution-finality-reference-400-tests-noncommercial.zip`.
3. Upload the **contents of the extracted `das-execution-finality-reference` folder**
   to the repository root, including hidden `.github/workflows/ci.yml`.
4. On GitHub, set the repository description from `GITHUB_METADATA.md`.
5. Explain that the `LICENSE` is a custom source-available NON-COMMERCIAL research
   license (not an OSI-approved open-source license); keep the exact file intact.
6. Verify GitHub Actions runs the suite on Python 3.10, 3.12, and 3.13. Local
   results do not guarantee all CI environments will pass until the runs finish.
7. Link the published Part 1 Internet-Draft:
   https://datatracker.ietf.org/doc/draft-das-interoperable-consequence-authority/
   Current referenced version: `draft-das-interoperable-consequence-authority-01`.
8. For future Internet-Draft revisions, use a verified GitHub URL and commit ID.
9. Make any required patent/IPR disclosure separately through IETF's IPR system;
   do not insert the GitHub software's non-commercial license as a restriction on
   the IETF Contribution. The public Part 1 -01 contains an IPR section that
   should be reviewed for compliance with RFC 8179 on its next revision.

## Test commands

```bash
python -m pip install -e '.[test]'
python -m pytest -q
python examples/demo.py
```

Expected **local** outcome from the package assembled on 27 October 2026:
`400 passed`. The GitHub-hosted test outcome should be checked independently.

## Copyright / patent separation

- `LICENSE` applies to the independent GitHub reference code, tests and repo docs.
- BCP 78 applies to the IETF Internet-Draft Contribution.
- BCP 79 / RFC 8179 governs applicable patent disclosures and separate licensing
  statements in the IETF process.
- The license does not convey patent rights and does not make an IETF
  standardization, infringement or essentiality assertion.
