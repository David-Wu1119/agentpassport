# Security

AgentPassport v0.1 is a local CLI and SDK for signed agent identity documents, capability tokens, revocation lists, and action receipts.

## Protected In v0.1

- Passport and receipt tampering is detected with Ed25519 signatures.
- Expired passports and capability tokens are rejected.
- Agent-level revocations can block passport verification.
- Private keys are stored outside passport documents and written with mode `0600`.
- Capability checks can block actions outside declared scopes or resources.

## Not Protected In v0.1

- Private key theft from a compromised machine.
- Enterprise key custody, HSM storage, or hardware-backed signing.
- Network distribution of revocation lists.
- A malicious runtime that ignores capability decisions.
- Legal identity proofing of the human or organization that issued a passport.

Do not commit `.agentpassport/` state. Treat generated private keys as credentials.
