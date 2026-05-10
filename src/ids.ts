import crypto from "node:crypto";

export function createId(prefix: string): string {
  return `${prefix}_${Date.now().toString(36)}${crypto.randomBytes(6).toString("base64url")}`;
}
