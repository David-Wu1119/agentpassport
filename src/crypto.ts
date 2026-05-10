import crypto, { type JsonWebKey } from "node:crypto";

export type Ed25519KeyPair = {
  privateKeyPem: string;
  publicKeyPem: string;
  publicJwk: JsonWebKey & {
    kty: "OKP";
    crv: "Ed25519";
    kid: string;
    x: string;
  };
};

export function createEd25519KeyPair(kid: string): Ed25519KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as JsonWebKey & {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
  };

  if (!publicJwk.x) {
    throw new Error("Failed to export Ed25519 public key JWK coordinate.");
  }

  return {
    privateKeyPem: privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString(),
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }).toString(),
    publicJwk: {
      kty: "OKP",
      crv: "Ed25519",
      kid,
      x: publicJwk.x,
    },
  };
}

export function signJson(payload: unknown, privateKeyPem: string): string {
  return crypto
    .sign(null, Buffer.from(stableStringify(payload)), privateKeyPem)
    .toString("base64url");
}

export function verifyJson(
  payload: unknown,
  signature: string,
  publicJwk: JsonWebKey,
): boolean {
  try {
    const publicKey = crypto.createPublicKey({ key: publicJwk, format: "jwk" });
    return crypto.verify(
      null,
      Buffer.from(stableStringify(payload)),
      publicKey,
      Buffer.from(signature, "base64url"),
    );
  } catch {
    return false;
  }
}

export function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(
        ([key, nested]) => `${JSON.stringify(key)}:${stableStringify(nested)}`,
      )
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

export function sha256(value: unknown): string {
  return `sha256:${crypto.createHash("sha256").update(stableStringify(value)).digest("hex")}`;
}
