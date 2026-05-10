# Contributing

AgentPassport is intentionally narrow for v0.1: local signed passports, scoped delegation, revocation lists, action receipts, and a TypeScript SDK.

## Local Setup

```bash
corepack pnpm install
corepack pnpm format:check
corepack pnpm check
npm pack --dry-run
```

## Development Rules

- Keep the CLI runnable on Node.js 20.18+.
- Do not invent custom cryptography.
- Do not write private keys into passport or receipt documents.
- Validate new schema fields in both issue and verify paths.
- Add tests for signature, expiration, revocation, and capability behavior.

## Security Changes

Changes to signing, verification, revocation, key rotation, or capability decisions need a test and a short threat-model note when they change the protected surface.
