# Security Assumptions and Limitations

1. **Trust boundary is modeled.** The controller, gateway, and sink are Python
   objects in one process. Separate keys and interfaces simulate authority separation;
   they do not prevent arbitrary local code from accessing both keys.
2. **HMAC is illustrative.** It provides message authentication in this model,
   not a hardware-backed, non-bearer, key-extraction-resistant authority primitive.
3. **Canon is a local JSON profile.** It is not the JSON Canonicalization Scheme
   (RFC 8785), a CBOR canonicalization implementation, or an interoperable IETF wire format.
4. **Effect is a SQLite row.** No external payment, network transmission, file export,
   physical actuation, or irreversible consequence is performed.
5. **Atomicity is local.** A SQLite transaction records consumption, cost, and the
   mock effect, but no distributed atomic commit is guaranteed.
6. **Actual-effect receipts are local evidence only.** They do not prove remote
   observation, independent causation, or recipient-side finality.
7. **Authenticated denial burns only the scoped nonce.** This is a modeled policy
   choice, not a general proof against all denial-of-service or concurrent races.
8. **Time is injected / local.** There is no protected clock, secure time attestation,
   bounded skew across hardware domains or partition-safe global revocation.
9. **Integration not completed.** App Intents/Shortcuts, Android Intent/Binder/Keystore,
   Linux eBPF/LSM, hardware command gates, RATS, OAuth, COSE and TEEP remain
   potential integration targets, not verified implementations.
10. **No security guarantee outside controlled paths.** If a real-world alternate
   effectuation path bypasses the mock gateway or its finality sink, the model
   has no way to contain it. The deployment must establish actual coverage.
11. **Tests not independent certification.** Passing locally-run pytest cases
   demonstrates particular modeled predicates; it does not establish patent
   validity, novelty, non-obviousness, production readiness, or freedom to operate.
12. **Further hardening needed.** Key management, canonical wire formats,
   resource-specific exact-effect reconstructors, distributed replay control,
   fault-tolerant logs, validated trusted observations and real-world adversarial
   red-teaming are prerequisites before live deployment.
