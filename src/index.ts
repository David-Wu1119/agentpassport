import type {
  ActionReceipt,
  AgentPassport,
  CapabilityDecision,
  IssuedPassportBundle,
  IssuePassportInput,
  KeyRotationResult,
  RevocationList,
  SignReceiptInput,
  VerificationResult,
} from "./types.js";
import { createEd25519KeyPair, signJson, verifyJson } from "./crypto.js";
import { createId } from "./ids.js";
import { addDuration, isExpired, nowIso } from "./time.js";

export * from "./types.js";
export { sha256, stableStringify } from "./crypto.js";

export async function issueAgentPassport(
  input: IssuePassportInput,
): Promise<IssuedPassportBundle> {
  validateIssueInput(input);

  const issuedAt = new Date();
  const expiresAt = addDuration(issuedAt, input.expiresIn).toISOString();
  const agentId = createId("agent");
  const capabilityId = createId("cap");
  const passportId = createId("passport");
  const kid = createId("key");
  const keys = createEd25519KeyPair(kid);
  const owner = input.owner ?? { type: "user" as const, id: input.actingFor };

  const unsignedPassport: Omit<AgentPassport, "signature"> = {
    version: "0.1",
    passport_id: passportId,
    issued_at: issuedAt.toISOString(),
    identity: {
      version: "0.1",
      agent_id: agentId,
      issuer: input.issuer ?? "https://agenttrust.dev",
      name: input.agentName,
      owner,
      organization: input.organization ?? "local-dev",
      purpose: input.purpose ?? "AgentPassport local development agent",
      created_at: issuedAt.toISOString(),
      expires_at: expiresAt,
      public_key: keys.publicJwk,
    },
    delegation: {
      version: "0.1",
      agent_id: agentId,
      acting_for: { type: "user", id: input.actingFor },
      delegated_by: input.delegatedBy ?? owner,
      approved_by: input.approvedBy ?? owner,
      reason:
        input.purpose ??
        `Agent ${input.agentName} acting for ${input.actingFor}`,
      created_at: issuedAt.toISOString(),
      expires_at: expiresAt,
    },
    capability_token: {
      version: "0.1",
      capability_id: capabilityId,
      agent_id: agentId,
      scopes: input.scopes,
      resources: input.resources,
      constraints: {
        ...(input.maxCostUsd === undefined
          ? {}
          : { max_cost_usd: input.maxCostUsd }),
        ...(input.requiresHumanApproval?.length
          ? { requires_human_approval: input.requiresHumanApproval }
          : {}),
        ...(input.deniedTools?.length
          ? { denied_tools: input.deniedTools }
          : {}),
      },
      created_at: issuedAt.toISOString(),
      expires_at: expiresAt,
    },
  };

  return {
    passport: {
      ...unsignedPassport,
      signature: signJson(unsignedPassport, keys.privateKeyPem),
    },
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
  };
}

export async function verifyAgentPassport(
  passport: AgentPassport,
  revocationList?: RevocationList,
): Promise<VerificationResult> {
  const reasons: string[] = [];

  if (passport.version !== "0.1") {
    reasons.push("unsupported_passport_version");
  }

  if (
    passport.identity.agent_id !== passport.delegation.agent_id ||
    passport.identity.agent_id !== passport.capability_token.agent_id
  ) {
    reasons.push("agent_id_mismatch");
  }

  if (
    isExpired(passport.identity.expires_at) ||
    isExpired(passport.delegation.expires_at) ||
    isExpired(passport.capability_token.expires_at)
  ) {
    reasons.push("passport_expired");
  }

  if (
    revocationList?.entries.some(
      (entry) =>
        entry.type === "agent" && entry.id === passport.identity.agent_id,
    )
  ) {
    reasons.push("agent_revoked");
  }

  const { signature, ...unsigned } = passport;
  if (!verifyJson(unsigned, signature, passport.identity.public_key)) {
    reasons.push("invalid_signature");
  }

  return { valid: reasons.length === 0, reasons };
}

export async function revokeAgent(
  agentId: string,
  existing?: RevocationList,
  options: { issuer?: string; reason?: string } = {},
): Promise<RevocationList> {
  const issuedAt = nowIso();
  if (
    existing?.entries.some(
      (entry) => entry.type === "agent" && entry.id === agentId,
    )
  ) {
    return existing;
  }

  return {
    version: "0.1",
    revocation_list_id: existing?.revocation_list_id ?? createId("rev"),
    issuer: options.issuer ?? existing?.issuer ?? "https://agenttrust.dev",
    issued_at: issuedAt,
    entries: [
      ...(existing?.entries ?? []),
      {
        type: "agent",
        id: agentId,
        reason: options.reason ?? "agent revoked",
        revoked_at: issuedAt,
      },
    ],
    signature: "unsigned-local-revocation-list",
  };
}

export async function rotateAgentKey(
  passport: AgentPassport,
): Promise<KeyRotationResult> {
  const keys = createEd25519KeyPair(createId("key"));
  const { signature: _previousSignature, ...currentUnsigned } = passport;
  const unsigned: Omit<AgentPassport, "signature"> = {
    ...currentUnsigned,
    identity: {
      ...passport.identity,
      public_key: keys.publicJwk,
    },
  };
  const nextPassport = {
    ...unsigned,
    signature: signJson(unsigned, keys.privateKeyPem),
  };

  return {
    passport: nextPassport,
    privateKeyPem: keys.privateKeyPem,
    publicKeyPem: keys.publicKeyPem,
  };
}

export async function signActionReceipt(
  input: SignReceiptInput,
): Promise<ActionReceipt> {
  const passportVerification = await verifyAgentPassport(input.passport);
  if (!passportVerification.valid) {
    throw new Error(
      `Cannot sign receipt with invalid passport: ${passportVerification.reasons.join(", ")}`,
    );
  }

  const capabilityDecision = checkCapability(
    input.passport,
    input.action,
    input.resource,
  );
  const decision =
    input.decision ??
    mapCapabilityActionToReceiptDecision(capabilityDecision.action);
  const unsigned: Omit<ActionReceipt, "signature"> = {
    version: "0.1",
    receipt_id: createId("receipt"),
    agent_id: input.passport.identity.agent_id,
    acting_for: input.passport.delegation.acting_for.id,
    action: input.action,
    resource: input.resource,
    decision,
    policy_hash: input.policyHash,
    tool: input.tool,
    timestamp: nowIso(),
  };

  return {
    ...unsigned,
    signature: signJson(unsigned, input.privateKeyPem),
  };
}

export async function verifyActionReceipt(
  receipt: ActionReceipt,
  passport: AgentPassport,
): Promise<VerificationResult> {
  const reasons: string[] = [];

  const passportVerification = await verifyAgentPassport(passport);
  if (!passportVerification.valid) {
    reasons.push(
      ...passportVerification.reasons.map((reason) => `passport_${reason}`),
    );
  }

  if (receipt.agent_id !== passport.identity.agent_id) {
    reasons.push("agent_id_mismatch");
  }

  if (isExpired(passport.identity.expires_at)) {
    reasons.push("passport_expired");
  }

  const { signature, ...unsigned } = receipt;
  if (!verifyJson(unsigned, signature, passport.identity.public_key)) {
    reasons.push("invalid_signature");
  }

  return { valid: reasons.length === 0, reasons };
}

export function checkCapability(
  passport: AgentPassport,
  action: string,
  resource: string,
): CapabilityDecision {
  const token = passport.capability_token;

  if (isExpired(token.expires_at)) {
    return { action: "block", reason: "capability_token_expired" };
  }

  if (token.constraints.denied_tools?.includes(action)) {
    return { action: "block", reason: "tool_denied" };
  }

  if (
    token.constraints.requires_human_approval?.some((required) =>
      actionMatches(action, required),
    )
  ) {
    return { action: "requires_approval", reason: "human_approval_required" };
  }

  if (!token.scopes.some((scope) => actionMatches(action, scope))) {
    return { action: "block", reason: "scope_not_allowed" };
  }

  if (!token.resources.some((allowed) => resourceMatches(resource, allowed))) {
    return { action: "block", reason: "resource_not_allowed" };
  }

  return { action: "allow", reason: "capability_allowed" };
}

function validateIssueInput(input: IssuePassportInput): void {
  if (!input.agentName.trim()) {
    throw new Error("agentName is required.");
  }
  if (!input.actingFor.trim()) {
    throw new Error("actingFor is required.");
  }
  if (input.scopes.length === 0) {
    throw new Error("at least one scope is required.");
  }
  if (input.resources.length === 0) {
    throw new Error("at least one resource is required.");
  }
}

function actionMatches(action: string, allowed: string): boolean {
  return (
    action === allowed ||
    (allowed.endsWith(":*") && action.startsWith(allowed.slice(0, -1)))
  );
}

function resourceMatches(resource: string, allowed: string): boolean {
  return resource === allowed || resource.startsWith(`${allowed}/`);
}

function mapCapabilityActionToReceiptDecision(
  action: CapabilityDecision["action"],
): ActionReceipt["decision"] {
  if (action === "allow") {
    return "allowed";
  }
  if (action === "block") {
    return "blocked";
  }
  return "requires_approval";
}
