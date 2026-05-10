#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import {
  checkCapability,
  issueAgentPassport,
  revokeAgent,
  rotateAgentKey,
  signActionReceipt,
  verifyActionReceipt,
  verifyAgentPassport,
  type ActionReceipt,
  type AgentPassport,
  type RevocationList,
} from "./index.js";

const DEFAULT_DIR = ".agentpassport";

type IssueOptions = {
  agent: string;
  actingFor: string;
  scope: string[];
  resource: string[];
  expires: string;
  issuer?: string;
  organization?: string;
  purpose?: string;
  maxCostUsd?: string;
  requiresHumanApproval: string[];
  deniedTool: string[];
  outDir: string;
};

type VerifyOptions = {
  passport?: string;
  revocations?: string;
};

type RevokeOptions = {
  agentId: string;
  reason?: string;
  issuer?: string;
  revocations: string;
};

type RotateOptions = {
  outDir: string;
};

type ReceiptOptions = {
  passport: string;
  privateKey?: string;
  action: string;
  resource: string;
  policyHash: string;
  tool: string;
  server: string;
  outDir: string;
};

async function main(): Promise<void> {
  const program = new Command()
    .name("agentpassport")
    .description(
      "OpenAgentID reference SDK and CLI for agent identities, capabilities, revocation, and signed action receipts.",
    )
    .version("0.1.0-alpha.0");

  program
    .command("init")
    .description("Create local AgentPassport directories.")
    .option("--dir <path>", "AgentPassport state directory.", DEFAULT_DIR)
    .action(async (options: { dir: string }) => {
      const dirs = await ensureStateDirs(options.dir);
      console.log(pc.green("AgentPassport initialized"));
      console.log(`State: ${path.resolve(options.dir)}`);
      console.log(`Keys: ${dirs.keys}`);
      console.log(`Passports: ${dirs.passports}`);
      console.log(`Receipts: ${dirs.receipts}`);
      console.log(`Revocations: ${dirs.revocations}`);
    });

  program
    .command("issue")
    .description(
      "Issue a local AgentPassport with an Ed25519 key pair and capability token.",
    )
    .requiredOption("--agent <name>", "Agent name.")
    .requiredOption(
      "--acting-for <id>",
      "Human or service identity the agent acts for.",
    )
    .option(
      "--scope <scope>",
      "Allowed scope. Repeat for multiple scopes.",
      collect,
      [],
    )
    .option(
      "--resource <resource>",
      "Allowed resource. Repeat for multiple resources.",
      collect,
      [],
    )
    .option("--expires <duration>", "Duration like 30m, 2h, or 7d.", "2h")
    .option("--issuer <url>", "Issuer URL.")
    .option("--organization <name>", "Owning organization.")
    .option("--purpose <text>", "Operational purpose.")
    .option("--max-cost-usd <amount>", "Optional max cost constraint.")
    .option(
      "--requires-human-approval <scope>",
      "Scope/action that requires human approval. Repeat for multiple values.",
      collect,
      [],
    )
    .option(
      "--denied-tool <tool>",
      "Tool/action that is always denied. Repeat for multiple values.",
      collect,
      [],
    )
    .option("--out-dir <path>", "AgentPassport state directory.", DEFAULT_DIR)
    .action(async (options: IssueOptions) => {
      const dirs = await ensureStateDirs(options.outDir);
      const maxCostUsd =
        options.maxCostUsd === undefined
          ? undefined
          : Number.parseFloat(options.maxCostUsd);
      if (
        maxCostUsd !== undefined &&
        (!Number.isFinite(maxCostUsd) || maxCostUsd < 0)
      ) {
        throw new Error("--max-cost-usd must be a non-negative number.");
      }

      const bundle = await issueAgentPassport({
        agentName: options.agent,
        actingFor: options.actingFor,
        scopes: options.scope,
        resources: options.resource,
        expiresIn: options.expires,
        issuer: options.issuer,
        organization: options.organization,
        purpose: options.purpose,
        maxCostUsd,
        requiresHumanApproval: options.requiresHumanApproval,
        deniedTools: options.deniedTool,
      });

      const agentId = bundle.passport.identity.agent_id;
      const kid = bundle.passport.identity.public_key.kid;
      const passportPath = path.join(
        dirs.passports,
        `${agentId}.passport.json`,
      );
      const privateKeyPath = path.join(dirs.keys, `${kid}.private.pem`);
      const publicKeyPath = path.join(dirs.keys, `${kid}.public.pem`);

      await writeJsonFile(passportPath, bundle.passport);
      await writeTextFile(privateKeyPath, bundle.privateKeyPem, 0o600);
      await writeTextFile(publicKeyPath, bundle.publicKeyPem, 0o644);

      console.log(pc.green("Issued AgentPassport"));
      console.log("");
      console.log(`Agent: ${bundle.passport.identity.name}`);
      console.log(`Agent ID: ${agentId}`);
      console.log(`Acting for: ${bundle.passport.delegation.acting_for.id}`);
      console.log("Scopes:");
      for (const scope of bundle.passport.capability_token.scopes) {
        console.log(`- ${scope}`);
      }
      console.log("");
      console.log(`Expires: ${bundle.passport.identity.expires_at}`);
      console.log(`Passport: ${passportPath}`);
      console.log(`Private key: ${privateKeyPath}`);
      console.log(`Public key: ${publicKeyPath}`);
    });

  program
    .command("verify <file>")
    .description("Verify an AgentPassport or action receipt JSON file.")
    .option(
      "--passport <path>",
      "Passport path required when verifying a receipt.",
    )
    .option(
      "--revocations <path>",
      "Revocation list path for passport verification.",
    )
    .action(async (file: string, options: VerifyOptions) => {
      const object = await readJsonFile<Record<string, unknown>>(file);
      if (typeof object.receipt_id === "string") {
        if (!options.passport) {
          throw new Error(
            "--passport is required when verifying an action receipt.",
          );
        }
        const passport = await readJsonFile<AgentPassport>(options.passport);
        const result = await verifyActionReceipt(
          object as ActionReceipt,
          passport,
        );
        printVerification(result.valid, result.reasons, "Action receipt");
        return;
      }

      const revocations = options.revocations
        ? await readOptionalJsonFile<RevocationList>(options.revocations)
        : undefined;
      const result = await verifyAgentPassport(
        object as AgentPassport,
        revocations,
      );
      printVerification(result.valid, result.reasons, "AgentPassport");
    });

  program
    .command("revoke")
    .description("Add an agent revocation to the local revocation list.")
    .requiredOption("--agent-id <id>", "Agent ID to revoke.")
    .option("--reason <text>", "Revocation reason.")
    .option("--issuer <url>", "Revocation list issuer.")
    .option(
      "--revocations <path>",
      "Revocation list path.",
      path.join(DEFAULT_DIR, "revocations", "revocation-list.json"),
    )
    .action(async (options: RevokeOptions) => {
      await fs.mkdir(path.dirname(options.revocations), { recursive: true });
      const existing = await readOptionalJsonFile<RevocationList>(
        options.revocations,
      );
      const next = await revokeAgent(options.agentId, existing, {
        reason: options.reason,
        issuer: options.issuer,
      });
      await writeJsonFile(options.revocations, next);
      console.log(pc.green("Agent revoked"));
      console.log(`Agent ID: ${options.agentId}`);
      console.log(`Revocation list: ${options.revocations}`);
    });

  program
    .command("rotate-key <passport>")
    .description(
      "Rotate the signing key for an existing AgentPassport and write a new passport.",
    )
    .option("--out-dir <path>", "AgentPassport state directory.", DEFAULT_DIR)
    .action(async (passportPath: string, options: RotateOptions) => {
      const dirs = await ensureStateDirs(options.outDir);
      const current = await readJsonFile<AgentPassport>(passportPath);
      const rotated = await rotateAgentKey(current);
      const agentId = rotated.passport.identity.agent_id;
      const kid = rotated.passport.identity.public_key.kid;
      const rotatedPath = path.join(
        dirs.passports,
        `${agentId}.rotated.passport.json`,
      );
      const privateKeyPath = path.join(dirs.keys, `${kid}.private.pem`);
      const publicKeyPath = path.join(dirs.keys, `${kid}.public.pem`);

      await writeJsonFile(rotatedPath, rotated.passport);
      await writeTextFile(privateKeyPath, rotated.privateKeyPem, 0o600);
      await writeTextFile(publicKeyPath, rotated.publicKeyPem, 0o644);

      console.log(pc.green("AgentPassport key rotated"));
      console.log(`Agent ID: ${agentId}`);
      console.log(`Rotated passport: ${rotatedPath}`);
      console.log(`Private key: ${privateKeyPath}`);
      console.log(`Public key: ${publicKeyPath}`);
    });

  program
    .command("receipt")
    .description(
      "Create a signed action receipt for a passport capability decision.",
    )
    .requiredOption("--passport <path>", "AgentPassport JSON path.")
    .option(
      "--private-key <path>",
      "Private key PEM path. Defaults to .agentpassport/keys/<kid>.private.pem.",
    )
    .requiredOption("--action <action>", "Action/scope being performed.")
    .requiredOption("--resource <resource>", "Resource being acted on.")
    .requiredOption(
      "--policy-hash <hash>",
      "Policy hash attached to the receipt.",
    )
    .requiredOption("--tool <name>", "Tool name.")
    .requiredOption("--server <name>", "Tool server name.")
    .option("--out-dir <path>", "AgentPassport state directory.", DEFAULT_DIR)
    .action(async (options: ReceiptOptions) => {
      const dirs = await ensureStateDirs(options.outDir);
      const passport = await readJsonFile<AgentPassport>(options.passport);
      const privateKeyPath =
        options.privateKey ??
        path.join(dirs.keys, `${passport.identity.public_key.kid}.private.pem`);
      const privateKeyPem = await readTextFile(privateKeyPath);
      const capability = checkCapability(
        passport,
        options.action,
        options.resource,
      );
      const receipt = await signActionReceipt({
        passport,
        privateKeyPem,
        action: options.action,
        resource: options.resource,
        policyHash: options.policyHash,
        tool: {
          name: options.tool,
          server: options.server,
        },
      });
      const receiptPath = path.join(
        dirs.receipts,
        `${receipt.receipt_id}.receipt.json`,
      );
      await writeJsonFile(receiptPath, receipt);

      console.log(
        receipt.decision === "allowed"
          ? pc.green("Action receipt signed")
          : pc.yellow("Action receipt signed with non-allow decision"),
      );
      console.log(`Decision: ${receipt.decision}`);
      console.log(`Capability reason: ${capability.reason}`);
      console.log(`Receipt: ${receiptPath}`);
    });

  await program.parseAsync(process.argv);
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

async function ensureStateDirs(baseDir: string): Promise<{
  keys: string;
  passports: string;
  receipts: string;
  revocations: string;
}> {
  const dirs = {
    keys: path.join(baseDir, "keys"),
    passports: path.join(baseDir, "passports"),
    receipts: path.join(baseDir, "receipts"),
    revocations: path.join(baseDir, "revocations"),
  };
  await Promise.all(
    Object.values(dirs).map((dir) => fs.mkdir(dir, { recursive: true })),
  );
  return dirs;
}

async function readJsonFile<T>(filePath: string): Promise<T> {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8")) as T;
  } catch (error) {
    throw new Error(
      `Failed to read JSON file ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

async function readOptionalJsonFile<T>(
  filePath: string,
): Promise<T | undefined> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return undefined;
    }
    throw new Error(
      `Failed to read JSON file ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

async function readTextFile(filePath: string): Promise<string> {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch (error) {
    throw new Error(
      `Failed to read file ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
}

async function writeJsonFile(filePath: string, value: unknown): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function writeTextFile(
  filePath: string,
  value: string,
  mode: number,
): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, value, { encoding: "utf8", mode });
  await fs.chmod(filePath, mode);
}

function printVerification(
  valid: boolean,
  reasons: string[],
  subject: string,
): void {
  if (valid) {
    console.log(pc.green(`${subject} verified`));
    console.log("Signature: valid");
    return;
  }

  console.log(pc.red(`${subject} verification failed`));
  for (const reason of reasons) {
    console.log(`- ${reason}`);
  }
  process.exitCode = 1;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

main().catch((error: unknown) => {
  console.error(pc.red(error instanceof Error ? error.message : String(error)));
  process.exitCode = 1;
});
