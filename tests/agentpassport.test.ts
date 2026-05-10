import { describe, expect, it } from "vitest";
import {
  checkCapability,
  issueAgentPassport,
  revokeAgent,
  rotateAgentKey,
  signActionReceipt,
  verifyActionReceipt,
  verifyAgentPassport,
} from "../src/index.js";

describe("AgentPassport SDK", () => {
  it("issues, verifies, signs receipts, revokes, and rotates keys", async () => {
    const bundle = await issueAgentPassport({
      agentName: "code-review-agent",
      actingFor: "david@example.com",
      scopes: ["github:pull_request:*"],
      resources: ["github:David-Wu1119/agentpassport"],
      expiresIn: "2h",
      purpose: "Review pull requests",
    });

    await expect(verifyAgentPassport(bundle.passport)).resolves.toEqual({
      valid: true,
      reasons: [],
    });

    expect(
      checkCapability(
        bundle.passport,
        "github:pull_request:comment",
        "github:David-Wu1119/agentpassport/pull/42",
      ),
    ).toEqual({
      action: "allow",
      reason: "capability_allowed",
    });

    expect(
      checkCapability(
        bundle.passport,
        "github:repo:delete",
        "github:David-Wu1119/agentpassport",
      ),
    ).toEqual({
      action: "block",
      reason: "scope_not_allowed",
    });

    const receipt = await signActionReceipt({
      passport: bundle.passport,
      privateKeyPem: bundle.privateKeyPem,
      action: "github:pull_request:comment",
      resource: "github:David-Wu1119/agentpassport/pull/42",
      policyHash: "sha256:test",
      tool: {
        name: "github.comment_pr",
        server: "github-mcp",
      },
    });

    expect(receipt.decision).toBe("allowed");
    await expect(
      verifyActionReceipt(receipt, bundle.passport),
    ).resolves.toEqual({ valid: true, reasons: [] });

    const revoked = await revokeAgent(
      bundle.passport.identity.agent_id,
      undefined,
      { reason: "test revocation" },
    );
    await expect(
      verifyAgentPassport(bundle.passport, revoked),
    ).resolves.toEqual({
      valid: false,
      reasons: ["agent_revoked"],
    });

    const rotated = await rotateAgentKey(bundle.passport);
    await expect(verifyAgentPassport(rotated.passport)).resolves.toEqual({
      valid: true,
      reasons: [],
    });
    expect(rotated.passport.identity.public_key.kid).not.toBe(
      bundle.passport.identity.public_key.kid,
    );
  });

  it("records requires_approval as a receipt decision instead of allowing the action", async () => {
    const bundle = await issueAgentPassport({
      agentName: "deploy-agent",
      actingFor: "ops@example.com",
      scopes: ["github:pull_request:*"],
      resources: ["github:example/repo"],
      expiresIn: "2h",
      requiresHumanApproval: ["github:pull_request:merge"],
    });

    const receipt = await signActionReceipt({
      passport: bundle.passport,
      privateKeyPem: bundle.privateKeyPem,
      action: "github:pull_request:merge",
      resource: "github:example/repo/pull/7",
      policyHash: "sha256:test",
      tool: {
        name: "github.merge_pr",
        server: "github-mcp",
      },
    });

    expect(receipt.decision).toBe("requires_approval");
  });
});
