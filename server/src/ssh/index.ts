import ssh2 from "ssh2";
const { Client, utils } = ssh2;
import crypto from "node:crypto";

export interface SshTarget {
  address: string; port: number; user: string; privateKey: string;
  sudoMode: "none" | "nopasswd";
  hostKey?: string | null; // "<type> <base64>" learned on first connect
}

export interface ExecResult { code: number | null; stdout: string; stderr: string; durationMs: number; truncated: boolean; hostKey: string }

const MAX_OUTPUT = 1024 * 1024;

function shellQuote(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

export function wrapCommand(cmd: string, sudoMode: SshTarget["sudoMode"]): string {
  return sudoMode === "nopasswd" ? `sudo -n bash -c ${shellQuote(cmd)}` : `bash -c ${shellQuote(cmd)}`;
}

export function keyFingerprint(publicKeyLine: string): string {
  const parsed = utils.parseKey(publicKeyLine);
  if (parsed instanceof Error) throw parsed;
  const pub = (Array.isArray(parsed) ? parsed[0] : parsed).getPublicSSH();
  return "SHA256:" + crypto.createHash("sha256").update(pub).digest("base64").replace(/=+$/, "");
}

export function generateEd25519(comment: string): { publicKey: string; privateKey: string } {
  const r = utils.generateKeyPairSync("ed25519", { comment });
  return { publicKey: r.public.trim(), privateKey: r.private };
}

export function publicFromPrivate(privateKey: string): string {
  const parsed = utils.parseKey(privateKey);
  if (parsed instanceof Error) throw parsed;
  const k = Array.isArray(parsed) ? parsed[0] : parsed;
  return `${k.type} ${k.getPublicSSH().toString("base64")} ${k.comment ?? ""}`.trim();
}

/**
 * Execute one command over SSH. Host key: trust-on-first-use; if a key is stored it must match.
 */
export function sshExec(t: SshTarget, command: string, timeoutMs = 60_000): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const started = Date.now();
    let stdout = "", stderr = "", truncated = false, seenHostKey = "";
    const timer = setTimeout(() => { conn.end(); reject(new Error(`ssh timeout after ${timeoutMs}ms`)); }, timeoutMs + 10_000);

    conn.on("ready", () => {
      conn.exec(wrapCommand(command, t.sudoMode), { pty: false }, (err, stream) => {
        if (err) { clearTimeout(timer); conn.end(); return reject(err); }
        const killer = setTimeout(() => { stream.close(); stderr += "\n[edr-console] command timeout"; }, timeoutMs);
        stream.on("data", (d: Buffer) => { if (stdout.length < MAX_OUTPUT) stdout += d.toString("utf8"); else truncated = true; });
        stream.stderr.on("data", (d: Buffer) => { if (stderr.length < MAX_OUTPUT) stderr += d.toString("utf8"); else truncated = true; });
        stream.on("close", (code: number | null) => {
          clearTimeout(killer); clearTimeout(timer); conn.end();
          resolve({ code, stdout: stdout.slice(0, MAX_OUTPUT), stderr: stderr.slice(0, MAX_OUTPUT), durationMs: Date.now() - started, truncated, hostKey: seenHostKey });
        });
      });
    });
    conn.on("error", (e) => { clearTimeout(timer); reject(e); });
    conn.connect({
      host: t.address, port: t.port, username: t.user, privateKey: t.privateKey,
      readyTimeout: 15_000, keepaliveInterval: 10_000,
      hostVerifier: (key: Buffer) => {
        const parsed = utils.parseKey(key);
        const k = parsed instanceof Error ? null : (Array.isArray(parsed) ? parsed[0] : parsed);
        seenHostKey = k ? `${k.type} ${k.getPublicSSH().toString("base64")}` : key.toString("base64");
        if (!t.hostKey) return true; // TOFU: caller persists seenHostKey
        return t.hostKey === seenHostKey;
      },
    });
  });
}
