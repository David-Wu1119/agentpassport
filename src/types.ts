export type Actor = {
  type: "user" | "team" | "service" | "organization";
  id: string;
};

export type PublicKeyJwk = {
  kty: "OKP";
  crv: "Ed25519";
  kid: string;
  x: string;
};

export type AgentIdentity = {
  version: "0.1";
  agent_id: string;
  issuer: string;
  name: string;
  owner: Actor;
  organization: string;
  purpose: string;
  created_at: string;
  expires_at: string;
  public_key: PublicKeyJwk;
};

export type DelegationChain = {
  version: "0.1";
  agent_id: string;
  acting_for: Actor;
  delegated_by: Actor;
  approved_by: Actor;
  reason: string;
  created_at: string;
  expires_at: string;
};

export type CapabilityToken = {
  version: "0.1";
  capability_id: string;
  agent_id: string;
  scopes: string[];
  resources: string[];
  constraints: {
    max_cost_usd?: number;
    requires_human_approval?: string[];
    allowed_tools?: string[];
    denied_tools?: string[];
  };
  created_at: string;
  expires_at: string;
};

export type AgentPassport = {
  version: "0.1";
  passport_id: string;
  issued_at: string;
  identity: AgentIdentity;
  delegation: DelegationChain;
  capability_token: CapabilityToken;
  signature: string;
};

export type IssuePassportInput = {
  agentName: string;
  actingFor: string;
  scopes: string[];
  resources: string[];
  expiresIn: string;
  issuer?: string;
  organization?: string;
  purpose?: string;
  owner?: Actor;
  delegatedBy?: Actor;
  approvedBy?: Actor;
  maxCostUsd?: number;
  requiresHumanApproval?: string[];
  deniedTools?: string[];
};

export type IssuedPassportBundle = {
  passport: AgentPassport;
  privateKeyPem: string;
  publicKeyPem: string;
};

export type VerificationResult = {
  valid: boolean;
  reasons: string[];
};

export type RevocationList = {
  version: "0.1";
  revocation_list_id: string;
  issuer: string;
  issued_at: string;
  entries: RevocationEntry[];
  signature: string;
};

export type RevocationEntry = {
  type: "agent" | "key" | "capability_token" | "receipt" | "attestation";
  id: string;
  reason: string;
  revoked_at: string;
};

export type ActionReceipt = {
  version: "0.1";
  receipt_id: string;
  agent_id: string;
  acting_for: string;
  action: string;
  resource: string;
  decision: "allowed" | "blocked" | "requires_approval";
  policy_hash: string;
  tool: {
    name: string;
    server: string;
  };
  timestamp: string;
  signature: string;
};

export type SignReceiptInput = {
  passport: AgentPassport;
  privateKeyPem: string;
  action: string;
  resource: string;
  decision?: ActionReceipt["decision"];
  policyHash: string;
  tool: {
    name: string;
    server: string;
  };
};

export type CapabilityDecision = {
  action: "allow" | "block" | "requires_approval";
  reason: string;
};

export type KeyRotationResult = {
  passport: AgentPassport;
  privateKeyPem: string;
  publicKeyPem: string;
};
