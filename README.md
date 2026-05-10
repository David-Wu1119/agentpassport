# AgentPassport

AgentPassport is a local-first CLI and TypeScript SDK for verifiable AI-agent identity, scoped delegation, revocation, and signed action receipts.

It gives an agent a signed JSON passport that answers:

- who the agent is
- who it acts for
- which scopes and resources it can use
- when the delegation expires
- which public key verifies its action receipts

## Install

```bash
corepack pnpm install
corepack pnpm build
node dist/cli.js --help
```

## CLI Demo

```bash
node dist/cli.js issue \
  --agent code-review-agent \
  --acting-for david@example.com \
  --scope 'github:pull_request:*' \
  --resource github:David-Wu1119/agentpassport \
  --expires 2h

node dist/cli.js verify .agentpassport/passports/*.passport.json
```

Wildcard scopes should be quoted in zsh/bash.

## Commands

```bash
agentpassport init
agentpassport issue
agentpassport verify <passport-or-receipt.json>
agentpassport revoke --agent-id <agent_id>
agentpassport rotate-key <passport.json>
agentpassport receipt --passport <passport.json> --action <scope> --resource <resource> --policy-hash <hash> --tool <tool> --server <server>
```

## Local State

The CLI writes local state under `.agentpassport/`:

```txt
.agentpassport/
  keys/
  passports/
  receipts/
  revocations/
```

Private keys are written with mode `0600`. The repository ignores `.agentpassport/` so local keys and receipts are not committed accidentally.

## Threat Model

AgentPassport v0.1 proves local document integrity and scoped delegation with Ed25519 signatures. It does not replace a production identity provider, secret manager, HSM, or enterprise revocation distribution system.

Use it as a reference format and local control point for MCPGuard, BrowserGuard, AgentTrail, AIAttest, and agent runtime policy checks.

## Verification

```bash
corepack pnpm install
corepack pnpm format:check
corepack pnpm check
npm pack --dry-run
```
