/**
 * Approval gate: deterministic read / write / unknown classification of a shell command.
 *
 * The LLM never decides this. The command string is tokenised with a small POSIX-sh aware
 * scanner (quotes, escapes, operators, redirections, heredocs, command substitution), split into
 * simple commands, and every simple command must match the read-only allowlist.
 *
 * EDR-87 (2026-10-23): investigation commands should not stop for approval.
 *  - $(...), `...`, <(...) and bash/sh -c '...' are no longer rejected wholesale: their contents are
 *    classified recursively, and the command is read only if everything inside is read.
 *  - xargs CMD, find -exec CMD, docker/podman exec CTR CMD: the inner command is classified.
 *  - for / while / if / { } / standalone VAR=value are understood.
 *  - Heredoc bodies are data (stdin), not commands. The command that reads them is what counts.
 *  - newline is a command separator (previously "cat a\nrm b" was a single segment — fixed).
 *  - allowArgs looks at the sub-command position (first positional), so "systemctl stop status"
 *    or "ip route add" are no longer read. denyArgs match whole tokens (no substring hits such as
 *    "-d" inside "meta-data").
 *  - curl: POST / -d to search-only endpoints (_search, _count, _cat ...) is read.
 *  - A variable or substitution as an argument of a restricted command (one with allow/deny
 *    rules) is a write, because it could expand into a mutating flag.
 */
import fs from "node:fs";
import YAML from "yaml";

export type Classification = "read" | "write" | "unknown";

export interface AllowRule {
  cmd: string;
  /** sub-commands (matched at the first positional) or flags (any position) that make the call read-only */
  allowArgs?: string[];
  /** regex (on the joined arguments) that makes the call read-only — alternative to allowArgs */
  allowPattern?: string;
  /** tokens that make the call a write. "a b" = consecutive tokens, "x*" = prefix, "-x" also matches "-x=..." */
  denyArgs?: string[];
  /** regex on the joined arguments that makes the call a write */
  denyPattern?: string;
  /** flags that take a value (skipped when looking for the sub-command) */
  valueFlags?: string[];
  /** no arguments at all is read */
  allowBare?: boolean;
  /** at least one of these tokens (or regex if it starts with "re:") must be present */
  requireArgs?: string[];
  /** every positional argument must be one of these */
  allowPositional?: string[];
  /** any positional argument makes it a write (e.g. hostname NEWNAME) */
  noPositional?: boolean;
  /** at most this many positional arguments (uniq IN OUT writes OUT) */
  maxPositional?: number;
  note?: string;
}
export interface Allowlist {
  readonly: AllowRule[];
  unknown_if_contains?: string[];
  /** EDR-89: regexes of secret files — any command that mentions one needs approval (prevents read-then-exfiltrate) */
  sensitive_paths?: string[];
  /** EDR-89: hostnames (or "*.domain") curl/wget may reach without approval, in addition to loopback/private/tailnet addresses */
  egress_allow?: string[];
}

export interface Segment { argv: string[]; redirects: string[]; classification: Classification; reason: string }
export interface ClassifyResult {
  classification: Classification;
  reason: string;
  segments: Segment[];
}

export function loadAllowlist(path: string): Allowlist {
  const doc = YAML.parse(fs.readFileSync(path, "utf8")) as Allowlist;
  if (!doc || !Array.isArray(doc.readonly)) throw new Error("invalid allowlist: readonly[] missing");
  doc.readonly = doc.readonly.map((r) => ({ ...r, cmd: String(r.cmd), allowArgs: r.allowArgs?.map(String), denyArgs: r.denyArgs?.map(String) }));
  return doc;
}

// ---------- placeholders for expansions ----------
/** $(...) / `...` / <(...) substitution result */
export const SUB = "\u0001";
/** $VAR / ${VAR} / $1 / $? ... */
export const VAR = "\u0002";
/** the same inside double quotes (no word splitting) */
export const SUBQ = "\u0003";
export const VARQ = "\u0004";
const DYN = /[\u0001-\u0004]/;
const isDynamic = (s: string) => DYN.test(s);
/** could this argument expand into a flag or several words? (starts with an expansion, or has an unquoted one) */
const isRiskyArg = (s: string) => /^[\u0001-\u0004]/.test(s) || s.includes(SUB) || s.includes(VAR);

// ---------- tokeniser ----------
type Tok = { t: "word"; v: string; quoted: boolean } | { t: "op"; v: string } | { t: "redir"; v: string };

const OPS = ["||", "&&", "|&", ";;", "|", ";", "&", "(", ")"];
const REDIR_RE = /^(&>>|&>|>>|>\||<<<|<<-|<<|<>|<&|>&|>|<)/;

/** Find the index of the ")" that closes a "(" at src[open]. Respects quotes and nesting. -1 if none. */
function matchParen(src: string, open: number): number {
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (c === "\\") { i++; continue; }
    if (c === "'") { const j = src.indexOf("'", i + 1); if (j < 0) return -1; i = j; continue; }
    if (c === '"') { let j = i + 1; while (j < src.length && src[j] !== '"') { if (src[j] === "\\") j++; j++; } if (j >= src.length) return -1; i = j; continue; }
    if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) return i; }
  }
  return -1;
}

export interface Tokenized { tokens: Tok[]; unsupported: string | null; subs: { kind: "cmd" | "procin" | "procout"; src: string }[] }

export function tokenize(src: string): Tokenized {
  const tokens: Tok[] = [];
  const subs: Tokenized["subs"] = [];
  let i = 0, cur = "", inWord = false, quoted = false, unsupported: string | null = null;
  const heredocs: { delim: string; strip: boolean; quoted: boolean }[] = [];
  let expectHeredocDelim: { strip: boolean } | null = null;
  const push = () => {
    if (inWord) {
      if (expectHeredocDelim) { heredocs.push({ delim: cur, strip: expectHeredocDelim.strip, quoted }); expectHeredocDelim = null; }
      tokens.push({ t: "word", v: cur, quoted }); cur = ""; inWord = false; quoted = false;
    }
  };
  /** handle "$" at position k (inside or outside double quotes). Returns new index, appends placeholder to cur. */
  const dollar = (k: number, dq = false): number => {
    const V = dq ? VARQ : VAR, S = dq ? SUBQ : SUB;
    const n = src[k + 1];
    if (n === "(" && src[k + 2] === "(") { // arithmetic $(( ))
      const close = src.indexOf("))", k + 3);
      if (close < 0) { unsupported = "unterminated $(( ))"; return src.length; }
      const inner = src.slice(k + 3, close);
      if (inner.includes("$(") || inner.includes("`")) { unsupported = "command substitution inside $(( ))"; }
      cur += V; inWord = true; return close + 2;
    }
    if (n === "(") {
      const close = matchParen(src, k + 1);
      if (close < 0) { unsupported = "unterminated $( )"; return src.length; }
      subs.push({ kind: "cmd", src: src.slice(k + 2, close) });
      cur += S; inWord = true; return close + 1;
    }
    if (n === "{") {
      const close = src.indexOf("}", k + 2);
      if (close < 0) { unsupported = "unterminated ${ }"; return src.length; }
      const inner = src.slice(k + 2, close);
      if (/[$`]/.test(inner)) { unsupported = "nested expansion inside ${ }"; }
      cur += V; inWord = true; return close + 1;
    }
    if (n === "'") { unsupported = "ANSI-C $'...' quoting"; return src.length; }
    const m = src.slice(k + 1).match(/^([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])/);
    if (m) { cur += V; inWord = true; return k + 1 + m[0].length; }
    cur += "$"; inWord = true; return k + 1; // a lone "$" is a literal
  };
  const backtick = (k: number, dq = false): number => {
    let j = k + 1, s = "";
    while (j < src.length && src[j] !== "`") { if (src[j] === "\\" && j + 1 < src.length) { s += src[j + 1]; j += 2; continue; } s += src[j]; j++; }
    if (j >= src.length) { unsupported = "unterminated backtick"; return src.length; }
    subs.push({ kind: "cmd", src: s });
    cur += dq ? SUBQ : SUB; inWord = true; return j + 1;
  };
  while (i < src.length && !unsupported) {
    const c = src[i];
    if (c === "\\" && i + 1 < src.length) { if (src[i + 1] !== "\n") { cur += src[i + 1]; inWord = true; } i += 2; continue; }
    if (c === "'") { const j = src.indexOf("'", i + 1); if (j < 0) { unsupported = "unterminated single quote"; break; } cur += src.slice(i + 1, j); inWord = true; quoted = true; i = j + 1; continue; }
    if (c === '"') {
      let j = i + 1;
      inWord = true; quoted = true;
      while (j < src.length && src[j] !== '"' && !unsupported) {
        if (src[j] === "\\" && j + 1 < src.length) { cur += src[j + 1]; j += 2; continue; }
        if (src[j] === "$") { j = dollar(j, true); continue; }
        if (src[j] === "`") { j = backtick(j, true); continue; }
        cur += src[j]; j++;
      }
      if (unsupported) break;
      if (j >= src.length) { unsupported = "unterminated double quote"; break; }
      i = j + 1; continue;
    }
    if (c === "$") { i = dollar(i); continue; }
    if (c === "`") { i = backtick(i); continue; }
    if (c === "\n") {
      push();
      tokens.push({ t: "op", v: ";" });
      i++;
      // consume heredoc bodies that start after this newline
      while (heredocs.length) {
        const h = heredocs.shift()!;
        let found = false;
        while (i <= src.length) {
          const nl = src.indexOf("\n", i);
          const line = src.slice(i, nl < 0 ? src.length : nl);
          i = nl < 0 ? src.length + 1 : nl + 1;
          const cmp = h.strip ? line.replace(/^\t+/, "") : line;
          if (cmp === h.delim) { found = true; break; }
          if (!h.quoted && /\$\(|`/.test(line)) { unsupported = "command substitution inside unquoted heredoc"; }
          if (nl < 0) break;
        }
        if (!found) { unsupported = unsupported ?? `heredoc '${h.delim}' is not terminated`; }
        if (i > src.length) i = src.length;
      }
      continue;
    }
    if (/\s/.test(c)) { push(); i++; continue; }
    if (c === "#" && !inWord) { const nl = src.indexOf("\n", i); i = nl < 0 ? src.length : nl; continue; } // comment
    // process substitution <(...) / >(...)
    if ((c === "<" || c === ">") && src[i + 1] === "(") {
      const close = matchParen(src, i + 1);
      if (close < 0) { unsupported = "unterminated process substitution"; break; }
      subs.push({ kind: c === "<" ? "procin" : "procout", src: src.slice(i + 2, close) });
      cur += SUBQ; inWord = true; i = close + 1; continue;
    }
    const m = src.slice(i).match(REDIR_RE);
    if (m) {
      if (inWord && /^\d+$/.test(cur) && !quoted) { cur = ""; inWord = false; } // fd prefix like 2>&1
      push();
      tokens.push({ t: "redir", v: m[1] });
      if (m[1] === "<<" || m[1] === "<<-") expectHeredocDelim = { strip: m[1] === "<<-" };
      i += m[0].length; continue;
    }
    const op = OPS.find((o) => src.startsWith(o, i));
    if (op) { push(); tokens.push({ t: "op", v: op }); i += op.length; continue; }
    cur += c; inWord = true; i++;
  }
  push();
  if (!unsupported && heredocs.length) unsupported = `heredoc '${heredocs[0].delim}' has no body`;
  return { tokens, unsupported, subs };
}

// ---------- segmentation ----------
function segments(tokens: Tok[]): { argv: string[]; redirects: string[] }[] {
  const out: { argv: string[]; redirects: string[] }[] = [];
  let cur = { argv: [] as string[], redirects: [] as string[] };
  let expectRedirTarget = false;
  for (const tk of tokens) {
    if (tk.t === "op") { if (tk.v === "(" || tk.v === ")") { if (cur.argv.length || cur.redirects.length) out.push(cur); cur = { argv: [], redirects: [] }; continue; } if (cur.argv.length || cur.redirects.length) out.push(cur); cur = { argv: [], redirects: [] }; expectRedirTarget = false; continue; }
    if (tk.t === "redir") { cur.redirects.push(tk.v); expectRedirTarget = true; continue; }
    if (expectRedirTarget) { cur.redirects[cur.redirects.length - 1] += " " + tk.v; expectRedirTarget = false; continue; }
    cur.argv.push(tk.v);
  }
  if (cur.argv.length || cur.redirects.length) out.push(cur);
  return out;
}

const WRAPPERS = new Set(["sudo", "doas", "nice", "ionice", "timeout", "env", "nohup", "stdbuf", "command", "time"]);
const WRAPPER_FLAGS_WITH_ARG: Record<string, Set<string>> = { sudo: new Set(["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"]), timeout: new Set(["-s", "-k", "--signal", "--kill-after"]), nice: new Set(["-n"]), ionice: new Set(["-c", "-n", "-p"]), env: new Set(["-u", "-C", "-S"]), stdbuf: new Set(["-i", "-o", "-e"]) };
/** environment variables that are harmless as a prefix (LC_ALL=C sort ...) */
const SAFE_ENV = /^(LC_[A-Z]+|LANG|LANGUAGE|TZ|COLUMNS|LINES|TERM|NO_COLOR|SYSTEMD_PAGER|SYSTEMD_COLORS|PAGER|GREP_COLORS?|TIME_STYLE)=/;
/** variables that change how later commands run — never "read" */
const DANGEROUS_VAR = /^(PATH|LD_[A-Z_]+|BASH_ENV|ENV|IFS|PROMPT_COMMAND|SHELLOPTS|BASHOPTS|PS4|BASH_FUNC_.*|PYTHON[A-Z_]*|NODE_OPTIONS|PERL5OPT|PERL5LIB|RUBYOPT|GCONV_PATH)=/;

/** Strip leading wrappers (sudo, timeout 30, env FOO=bar ...) and return the real command argv. */
export function unwrap(argv: string[]): { argv: string[]; wrappers: string[]; bad?: string } {
  const wrappers: string[] = [];
  let a = [...argv];
  for (let guard = 0; guard < 8 && a.length; guard++) {
    // prefix assignments: LC_ALL=C sort
    while (a.length > 1 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(a[0])) {
      if (!SAFE_ENV.test(a[0])) return { argv: a, wrappers, bad: `environment prefix ${a[0].split("=")[0]}` };
      wrappers.push(a[0].split("=")[0] + "="); a = a.slice(1);
    }
    const head = basename(a[0]);
    if (!WRAPPERS.has(head)) break;
    if (head === "command" && (a[1] === "-v" || a[1] === "-V")) return { argv: ["which", ...a.slice(2)], wrappers: [...wrappers, "command"] };
    wrappers.push(head);
    a = a.slice(1);
    const flagsWithArg = WRAPPER_FLAGS_WITH_ARG[head] ?? new Set<string>();
    while (a.length) {
      if (a[0] === "--") { a = a.slice(1); break; }
      if (head === "timeout" && /^\d+(\.\d+)?[smhd]?$/.test(a[0])) { a = a.slice(1); break; }
      if (head === "env" && /^[A-Za-z_][A-Za-z0-9_]*=/.test(a[0])) { if (!SAFE_ENV.test(a[0])) return { argv: a, wrappers, bad: `environment ${a[0].split("=")[0]}` }; a = a.slice(1); continue; }
      if (a[0].startsWith("-")) { const f = a[0]; a = a.slice(1); if (flagsWithArg.has(f)) a = a.slice(1); continue; }
      break;
    }
  }
  return { argv: a, wrappers };
}

function basename(p: string): string { return p.includes("/") ? p.slice(p.lastIndexOf("/") + 1) : p; }

function matchRule(rules: AllowRule[], argv: string[]): AllowRule | undefined {
  const head = argv[0];
  return rules.find((r) => r.cmd === head || basename(r.cmd) === basename(head) && (r.cmd.includes("/") ? r.cmd === head : true));
}

const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "ash", "busybox"]);
const INTERPRETERS = new Set(["eval", "exec", "source", ".", "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua", "Rscript", "pwsh", "powershell", "osascript", "expect", "tclsh", "deno", "bun"]);
const VERSION_FLAGS: Record<string, RegExp> = { php: /^(-v|--version|-m|-i|--ini)$/, default: /^(-v|-V|-VV|--version)$/ };
const PY_READ_MODULES = new Set(["json.tool", "pip", "site", "platform", "sysconfig"]);
const PIP_READ = new Set(["list", "show", "freeze", "check", "--version", "-V", "index", "inspect", "config"]);
const SHELL_KEYWORDS_PREFIX = new Set(["then", "do", "else", "elif", "if", "while", "until", "!", "{", "time"]);
const SHELL_KEYWORDS_ALONE = new Set(["fi", "done", "esac", "}", "then", "do", "else", ":", "true", "false", "break", "continue"]);

type Ctx = { allow: Allowlist; depth: number };

function positionals(rest: string[], valueFlags: string[] = []): string[] {
  const out: string[] = [];
  for (let k = 0; k < rest.length; k++) {
    const x = rest[k];
    if (x === "--") { out.push(...rest.slice(k + 1)); break; }
    if (x.startsWith("-") && x.length > 1) { if (valueFlags.includes(x)) k++; continue; }
    out.push(x);
  }
  return out;
}

function denyHit(rest: string[], deny: string[]): string | undefined {
  for (const d of deny) {
    if (d.includes(" ")) { const seq = d.split(/\s+/); for (let k = 0; k + seq.length <= rest.length; k++) if (seq.every((s, n) => rest[k + n] === s)) return d; continue; }
    if (d.endsWith("*")) { const p = d.slice(0, -1); if (rest.some((x) => x.startsWith(p))) return d; continue; }
    if (rest.some((x) => x === d || (d.startsWith("-") && x.startsWith(d + "=")))) return d;
  }
  return undefined;
}

function restricted(rule: AllowRule): boolean {
  return !!(rule.allowArgs?.length || rule.allowPattern || rule.denyArgs?.length || rule.denyPattern || rule.requireArgs?.length || rule.allowPositional || rule.noPositional || rule.maxPositional !== undefined);
}

/** Check a command against its allow rule. `dynamicTail` = more arguments will be appended at run time (xargs / find -exec). */
function checkRule(head: string, rule: AllowRule, rest: string[], dynamicTail: boolean): { classification: Classification; reason: string } {
  const joined = rest.join(" ");
  if (restricted(rule) && (dynamicTail || rest.some(isRiskyArg))) return { classification: "write", reason: `'${head}' is restricted and gets arguments that are only known at run time` };
  const d = rule.denyArgs ? denyHit(rest, rule.denyArgs) : undefined;
  if (d) return { classification: "write", reason: `'${head}' with mutating argument (${d})` };
  if (rule.denyPattern && new RegExp(rule.denyPattern).test(joined)) return { classification: "write", reason: `'${head}' arguments match a mutating pattern` };
  const pos = positionals(rest, rule.valueFlags);
  if (rule.maxPositional !== undefined && pos.length > rule.maxPositional) return { classification: "write", reason: `'${head}' with ${pos.length} file arguments may write the last one` };
  if (rule.noPositional && pos.length) return { classification: "write", reason: `'${head} ${pos[0]}' changes state` };
  if (rule.allowPositional && pos.some((p) => !rule.allowPositional!.includes(p))) return { classification: "write", reason: `'${head}' target is not allowed` };
  if (rule.requireArgs?.length && !rule.requireArgs.some((r) => r.startsWith("re:") ? new RegExp(r.slice(3)).test(joined) : rest.includes(r))) return { classification: "write", reason: `'${head}' needs one of ${rule.requireArgs.join(", ")}` };
  if (rule.allowArgs?.length || rule.allowPattern) {
    if (!rest.length && rule.allowBare) return { classification: "read", reason: `${head} (no arguments)` };
    const posJoined = pos.join(" ");
    const okArgs = (rule.allowArgs ?? []).some((a) => a.includes(" ") ? (posJoined === a || posJoined.startsWith(a + " ")) : a.startsWith("-") ? rest.includes(a) : pos[0] === a);
    const okPat = rule.allowPattern ? new RegExp(rule.allowPattern).test(joined) : false;
    if (!okArgs && !okPat) {
      if (rule.allowBare && !pos.length && !(rule.allowArgs ?? []).some((a) => a.startsWith("-"))) return { classification: "read", reason: `${head} (no sub-command)` };
      return { classification: "write", reason: `'${(head + " " + (pos[0] ?? rest[0] ?? "")).trim()}' is not an allowed read-only sub-command` };
    }
  }
  return { classification: "read", reason: `${head} allowed` };
}

// --- curl: GET is read; POST / -d only to search-style endpoints ---
const CURL_VALUE_FLAGS = new Set(["-u", "--user", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--data-ascii", "--json", "-X", "--request", "-o", "--output", "-A", "--user-agent", "-e", "--referer", "-b", "--cookie", "-c", "--cookie-jar", "--cacert", "--capath", "--cert", "--key", "--cert-type", "--key-type", "-m", "--max-time", "--connect-timeout", "-w", "--write-out", "-x", "--proxy", "--resolve", "--connect-to", "-K", "--config", "-F", "--form", "-T", "--upload-file", "-r", "--range", "-Y", "-y", "--retry", "--retry-delay", "--retry-max-time", "-E", "--url", "-D", "--dump-header", "--interface", "--oauth2-bearer", "--aws-sigv4", "-U", "--proxy-user", "--limit-rate", "--max-filesize", "--trace", "--trace-ascii", "--stderr", "-z", "--time-cond"]);
const CURL_READ_ENDPOINT = /\/(_search|_msearch|_count|_field_caps|_mappings?|_validate\/query|_explain|_sql|_plugins\/_sql|_plugins\/_ppl|_cat(\/[^?\s]*)?|_cluster\/health|_cluster\/stats|_nodes(\/[^?\s]*)?\/stats|_search\/scroll|_analyze|_termvectors|_mget|_rank_eval)(\/|\?|$)|\/security\/user\/authenticate(\/|\?|$)/;
const CURL_WRITE_ENDPOINT = /_(update|delete)_by_query|_bulk|\/_doc(\/|\?|$)|_reindex|_update\/|_create\/|_close|_open|_forcemerge|_flush|_refresh|_shrink|_split|_rollover|_aliases|_settings|_template|_ilm|_plugins\/_ism|_snapshot|_tasks\/.*\/_cancel/;
let egressAllow: string[] = [];
const PRIVATE_HOST = /^(localhost|127\.\d+\.\d+\.\d+|::1|\[::1\]|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.169\.254|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+|[\w-]+)$/;
/** null if the URL may be fetched without approval, otherwise a short reason */
export function egressBlocked(url: string, allowList: string[]): string | null {
  if (isDynamic(url)) return "a URL built at run time";
  let host = "";
  try { host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `http://${url}`).hostname.toLowerCase(); } catch { return "an unparsable URL"; }
  host = host.replace(/^\[|\]$/g, "");
  if (PRIVATE_HOST.test(host) || host === "::1") return null; // loopback, RFC1918, tailnet, metadata, single-label LAN names
  if (allowList.some((a) => a.startsWith("*.") ? host === a.slice(2) || host.endsWith(a.slice(1)) : host === a.toLowerCase())) return null;
  return `external host ${host}`;
}
function classifyCurl(rest: string[]): { classification: Classification; reason: string } {
  // normalise to [flag, value?] / url items (expands clusters like -sSo FILE, -XPOST, --data=...)
  const items: { f?: string; v?: string; url?: string }[] = [];
  for (let k = 0; k < rest.length; k++) {
    const x = rest[k];
    if (x.startsWith("--") && x.length > 2) {
      const eq = x.indexOf("=");
      const f = eq > 0 ? x.slice(0, eq) : x;
      if (CURL_VALUE_FLAGS.has(f)) items.push({ f, v: eq > 0 ? x.slice(eq + 1) : rest[++k] ?? "" }); else items.push({ f });
      continue;
    }
    if (x.startsWith("-") && x.length > 1) {
      for (let c = 1; c < x.length; c++) {
        const f = "-" + x[c];
        if (CURL_VALUE_FLAGS.has(f)) { const v = x.slice(c + 1); items.push({ f, v: v.length ? v : rest[++k] ?? "" }); break; }
        items.push({ f });
      }
      continue;
    }
    items.push({ url: x });
  }
  let method = "", data = false, getMode = false;
  const urls: string[] = [];
  for (const it of items) {
    if (it.url !== undefined) { urls.push(it.url); continue; }
    const f = it.f!, v = it.v ?? "";
    switch (f) {
      case "-O": case "--remote-name": case "--remote-name-all": case "-J": case "--remote-header-name": return { classification: "write", reason: "curl saves a file (-O)" };
      case "-o": case "--output": case "-D": case "--dump-header": case "--trace": case "--trace-ascii": case "--stderr":
        if (!["/dev/null", "-", "/dev/stdout", "/dev/stderr"].includes(v)) return { classification: "write", reason: `curl writes a file (${f} ${v})` };
        break;
      case "-c": case "--cookie-jar": return { classification: "write", reason: "curl writes a cookie jar" };
      case "-T": case "--upload-file": case "-F": case "--form": return { classification: "write", reason: `curl uploads (${f})` };
      case "-K": case "--config": return { classification: "write", reason: "curl reads options from a config file" };
      case "-X": case "--request": method = v.toUpperCase(); break;
      case "-G": case "--get": getMode = true; break;
      case "-I": case "--head": method = method || "HEAD"; break;
      case "-d": case "--data": case "--data-raw": case "--data-binary": case "--data-urlencode": case "--data-ascii": case "--json": data = true; break;
      case "--url": urls.push(v); break;
    }
  }
  if (method && (isDynamic(method) || !["GET", "HEAD", "POST", "OPTIONS"].includes(method))) return { classification: "write", reason: `curl -X ${method}` };
  // EDR-89: outbound HTTP only to internal / allow-listed destinations without approval (blocks read-then-exfiltrate)
  for (const u of urls) { const why = egressBlocked(u, egressAllow); if (why) return { classification: "write", reason: `curl to ${why}` }; }
  const sends = method === "POST" || (data && !getMode);
  if (!sends) return { classification: "read", reason: "curl GET" };
  if (urls.some((u) => CURL_WRITE_ENDPOINT.test(u))) return { classification: "write", reason: "curl to a mutating API endpoint" };
  if (urls.length && urls.every((u) => !isDynamic(u) && CURL_READ_ENDPOINT.test(u))) return { classification: "read", reason: "curl POST to a search/read-only endpoint" };
  return { classification: "write", reason: "curl sends data (POST / -d) to an endpoint that is not known to be read-only" };
}

function strictInner(inner: string[], ctx: Ctx, via: string): { classification: Classification; reason: string } {
  if (!inner.length) return { classification: "read", reason: `${via} (echo)` };
  const r = classifySegmentInner({ argv: inner, redirects: [] }, ctx, true);
  return { classification: r.classification, reason: `${via} → ${r.reason}` };
}

function classifySegmentInner(seg: { argv: string[]; redirects: string[] }, ctx: Ctx, dynamicTail = false): { classification: Classification; reason: string } {
  const allow = ctx.allow;
  const badRedir = seg.redirects.find((r) => {
    const x = r.replace(/\s+/g, "");
    if (!/^(&>>|&>|>>|>\||>|<>|>&)/.test(x)) return false;      // input redirections / heredocs are fine
    if (/^>&([0-9]|-)$/.test(x)) return false;                    // 2>&1, >&2
    return !/^(&>>|&>|>>|>\||>|>&)(\/dev\/null|\/dev\/stdout|\/dev\/stderr)$/.test(x);
  });
  if (badRedir) return { classification: "write", reason: `output redirection: ${badRedir}` };
  let argv0 = [...seg.argv];
  // shell syntax
  while (argv0.length && SHELL_KEYWORDS_PREFIX.has(argv0[0]) && !(argv0[0] === "time" && argv0.length === 1)) argv0 = argv0.slice(1);
  while (argv0.length > 1 && argv0[argv0.length - 1] === "}") argv0 = argv0.slice(0, -1);
  if (!argv0.length) return { classification: "read", reason: "shell syntax" };
  if (argv0.length === 1 && SHELL_KEYWORDS_ALONE.has(argv0[0])) return { classification: "read", reason: "shell syntax" };
  if (argv0[0] === "for" || argv0[0] === "select") return { classification: "read", reason: "loop header" };
  if (argv0[0] === "case" || argv0[0] === "function") return { classification: "unknown", reason: `shell construct: ${argv0[0]}` };
  // standalone assignments: X=$(...) / export X=... / local X=...
  if (["export", "local", "declare", "readonly", "typeset"].includes(argv0[0]) && argv0.length > 1 && argv0.slice(1).every((x) => /^[A-Za-z_][A-Za-z0-9_]*(=|$)/.test(x) || /^-[a-zA-Z]+$/.test(x))) argv0 = argv0.slice(1).filter((x) => !x.startsWith("-"));
  if (argv0.every((x) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(x))) {
    const bad = argv0.find((x) => DANGEROUS_VAR.test(x));
    return bad ? { classification: "unknown", reason: `assignment to ${bad.split("=")[0]}` } : { classification: "read", reason: "variable assignment" };
  }
  if (argv0.every((x) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(x)) && seg.argv[0] === "export") return { classification: "read", reason: "export" };

  const { argv, wrappers, bad } = unwrap(argv0);
  if (bad) return { classification: "unknown", reason: bad };
  if (!argv.length) {
    if (wrappers[wrappers.length - 1] === "env" || wrappers[wrappers.length - 1] === "time") return { classification: "read", reason: `${wrappers[wrappers.length - 1]} (prints only)` };
    return { classification: "unknown", reason: `wrapper without command: ${wrappers.join(" ")}` };
  }
  if (isDynamic(argv[0])) return { classification: "unknown", reason: "command name comes from a variable or substitution" };
  const head = basename(argv[0]);
  const rest = argv.slice(1);
  const w = wrappers.length ? wrappers.join(" ") + " " : "";

  // bash -c '...' / sh -lc '...' → classify the script itself
  if (SHELLS.has(head)) {
    let k = 0, script: string | undefined;
    let a = rest;
    if (head === "busybox") { if (!a.length || !SHELLS.has(a[0]) || a[0] === "busybox") return classifySegmentInner({ argv: a, redirects: [] }, ctx, dynamicTail); a = a.slice(1); }
    for (; k < a.length; k++) {
      const x = a[k];
      if (x === "-o" || x === "+o") { k++; continue; }
      if (/^[-+][a-zA-Z]+$/.test(x)) { if (x.includes("c")) { script = a[k + 1]; break; } continue; }
      break;
    }
    if (script === undefined) return { classification: "unknown", reason: `nested shell without -c: ${head}` };
    if (isDynamic(script)) return { classification: "unknown", reason: `${head} -c script contains variables or substitutions from the outer shell` };
    if (ctx.depth >= 3) return { classification: "unknown", reason: "nesting too deep" };
    const r = classifyCommand(script, allow, ctx.depth + 1);
    return { classification: r.classification, reason: `${w}${head} -c → ${r.reason}` };
  }
  if (INTERPRETERS.has(head) || /^python[0-9.]*$/.test(head)) {
    const vf = VERSION_FLAGS[head] ?? VERSION_FLAGS.default;
    if (rest.length === 1 && vf.test(rest[0]) && !["eval", "exec", "source", "."].includes(head)) return { classification: "read", reason: `${head} version/info query` };
    if (/^python[0-9.]*$/.test(head) && rest[0] === "-m" && PY_READ_MODULES.has(rest[1] ?? "")) {
      const mod = rest[1];
      if (mod === "pip") return PIP_READ.has(rest[2] ?? "") && !rest.includes("--upgrade") ? { classification: "read", reason: `${head} -m pip ${rest[2]}` } : { classification: "write", reason: `${head} -m pip ${rest[2] ?? ""}` };
      if (mod === "json.tool" && positionals(rest.slice(2)).length > 1) return { classification: "write", reason: "json.tool with an output file" };
      return { classification: "read", reason: `${head} -m ${mod}` };
    }
    return { classification: "unknown", reason: `nested interpreter: ${head}` };
  }
  // xargs CMD → classify CMD (appended args are unknown, so restricted commands become writes)
  if (head === "xargs") {
    let k = 0;
    const withVal = new Set(["-I", "-n", "-P", "-L", "-d", "-s", "-E", "-a", "--delimiter", "--max-args", "--max-procs", "--max-lines", "--arg-file", "--replace"]);
    for (; k < rest.length; k++) {
      const x = rest[k];
      if (!x.startsWith("-")) break;
      if (withVal.has(x)) { k++; continue; }
      if (/^-(I|n|P|L|d|s|E|a).+/.test(x) || x.includes("=")) continue;
      if (x === "-p" || x === "--interactive") return { classification: "unknown", reason: "xargs -p" };
    }
    return strictInner(rest.slice(k), ctx, `${w}xargs`);
  }
  // docker/podman exec [opts] CTR CMD...
  if ((head === "docker" || head === "podman") && rest[0] === "exec") {
    const r = rest.slice(1);
    let k = 0;
    const withVal = new Set(["-u", "--user", "-w", "--workdir", "-e", "--env", "--env-file", "--detach-keys"]);
    for (; k < r.length; k++) {
      const x = r[k];
      if (!x.startsWith("-")) break;
      if (x === "--privileged") return { classification: "write", reason: `${head} exec --privileged` };
      if (withVal.has(x)) { k++; continue; }
    }
    const inner = r.slice(k + 1);
    if (!r[k] || !inner.length) return { classification: "unknown", reason: `${head} exec without a command` };
    const ir = classifySegmentInner({ argv: inner, redirects: [] }, ctx, dynamicTail);
    return { classification: ir.classification, reason: `${w}${head} exec ${r[k]} → ${ir.reason}` };
  }
  // find ... -exec CMD {} \; → classify CMD
  if (head === "find") {
    const rule = matchRule(allow.readonly, argv);
    if (!rule) return { classification: "write", reason: "'find' is not in the read-only allowlist" };
    const outer: string[] = [];
    for (let k = 0; k < rest.length; k++) {
      const x = rest[k];
      if (["-exec", "-execdir", "-ok", "-okdir"].includes(x)) {
        let e = k + 1; const inner: string[] = [];
        while (e < rest.length && rest[e] !== ";" && rest[e] !== "+") { if (rest[e] !== "{}") inner.push(rest[e]); e++; }
        const ir = strictInner(inner, ctx, `find ${x}`);
        if (ir.classification !== "read") return ir;
        k = e; continue;
      }
      outer.push(x);
    }
    const r = checkRule("find", rule, outer, dynamicTail);
    return r.classification === "read" ? { classification: "read", reason: `${w}find allowed` } : r;
  }
  // EDR-89: name lookups / probes with run-time data in the name can carry data out (DNS exfiltration)
  if (["dig", "nslookup", "host", "whois", "ping", "ping6", "traceroute", "tracepath", "wget", "nc", "ncat", "telnet"].includes(head) && rest.some(isDynamic)) return { classification: "write", reason: `${head} with a target built at run time` };
  if (head === "curl") {
    if (dynamicTail) return { classification: "write", reason: "curl with arguments only known at run time" };
    const r = classifyCurl(rest);
    return { classification: r.classification, reason: `${w}${r.reason}` };
  }
  const rule = matchRule(allow.readonly, argv);
  if (!rule) return { classification: "write", reason: `'${head}' is not in the read-only allowlist` };
  const r = checkRule(head, rule, rest, dynamicTail);
  return r.classification === "read" ? { classification: "read", reason: `${w}${r.reason}` } : r;
}

export function classifySegment(seg: { argv: string[]; redirects: string[] }, allow: Allowlist): { classification: Classification; reason: string } {
  return classifySegmentInner(seg, { allow, depth: 0 });
}

export function classifyCommand(command: string, allow: Allowlist, depth = 0): ClassifyResult {
  egressAllow = allow.egress_allow ?? [];
  for (const re of allow.sensitive_paths ?? []) {
    const m = command.match(new RegExp(re, "i"));
    if (m) return { classification: "write", reason: `touches a secret file (${m[0]}) — needs approval`, segments: [] };
  }
  for (const needle of allow.unknown_if_contains ?? []) {
    if (command.includes(needle)) return { classification: "unknown", reason: `contains '${needle.trim()}'`, segments: [] };
  }
  const { tokens, unsupported, subs } = tokenize(command);
  if (unsupported) return { classification: "unknown", reason: unsupported, segments: [] };
  // substitutions first: $(...) `...` <(...) must themselves be read-only
  for (const s of subs) {
    if (s.kind === "procout") return { classification: "unknown", reason: "output process substitution >(...)", segments: [] };
    if (depth >= 3) return { classification: "unknown", reason: "nesting too deep", segments: [] };
    const r = classifyCommand(s.src, allow, depth + 1);
    if (r.classification !== "read") return { classification: r.classification, reason: `inside $(${s.src.slice(0, 60)}): ${r.reason}`, segments: r.segments };
  }
  const ctx: Ctx = { allow, depth };
  const segs: Segment[] = segments(tokens).map((s) => ({ ...s, ...classifySegmentInner(s, ctx) }));
  if (!segs.length) return { classification: subs.length ? "read" : "unknown", reason: subs.length ? "substitution only" : "empty command", segments: [] };
  const worst = segs.find((s) => s.classification === "unknown") ?? segs.find((s) => s.classification === "write");
  const show = (a: string[]) => a.join(" ").replace(/[\u0001\u0003]/g, "$(…)").replace(/[\u0002\u0004]/g, "$VAR");
  if (worst) return { classification: worst.classification, reason: `${worst.reason} [${show(worst.argv)}]`, segments: segs };
  return { classification: "read", reason: `${segs.length} read-only segment(s)${subs.length ? ` + ${subs.length} substitution(s)` : ""}`, segments: segs };
}

// ---------- change scope (EDR-87: retry of an approved change without asking again) ----------
export interface ChangeScope { paths: string[]; services: string[]; heads: string[]; opaque: boolean }
const SCRATCH = /^\/(tmp|dev|proc)\//;
const FS_PATH = /(?<![\w.$<>\\\/-])\/(?:etc|var|opt|usr|home|root|srv|lib|lib64|boot|run|mnt|data|app|sbin|bin|tmp)\/[\w.@+\/*-]*/g;
function normPath(p: string): string {
  let x = p.split(DYN)[0].replace(/[),;'"]+$/, "").replace(/\/+$/, "");
  x = x.replace(/\.(bak|backup|orig|old|before|save)([._-][\w.*-]*)?$/i, "").replace(/[.*_-]+$/, "");
  return x;
}
/** What a (write) plan touches: absolute paths outside /tmp, services it restarts, command names it runs. */
export function changeScope(steps: string[], allow: Allowlist): ChangeScope {
  const paths = new Set<string>(), services = new Set<string>(), heads = new Set<string>();
  let opaque = false;
  for (const cmd of steps) {
    const r = classifyCommand(cmd, allow);
    if (r.classification === "read") continue;
    // filesystem paths only (not XML closing tags like </ossec_config> or sed addresses like /^<\/x>$/)
    for (const m of cmd.matchAll(FS_PATH)) { const p = normPath(m[0]); if (p.length > 1 && !SCRATCH.test(p + "/")) paths.add(p); }
    if (!r.segments.length) opaque = true;
    for (const s of r.segments) {
      if (s.classification === "read") continue;
      const { argv } = unwrap(s.argv);
      if (!argv.length) continue;
      const h = basename(argv[0]);
      heads.add(h);
      if (h === "systemctl") { const pos = positionals(argv.slice(1)); if (/^(restart|reload|start|stop|try-restart|reload-or-restart)$/.test(pos[0] ?? "")) for (const u of pos.slice(1)) services.add(u.replace(/\.service$/, "")); }
      if (h === "service" && argv[1]) services.add(argv[1]);
      if (h === "wazuh-control") services.add("wazuh-manager");
    }
  }
  return { paths: [...paths], services: [...services], heads: [...heads], opaque };
}
// ---------- EDR-94: operations that always need a human, whatever self-drive allowance was granted ----------
const MUST_ASK: { label: string; re: RegExp }[] = [
  { label: "外部リポジトリの追加", re: /config-manager\s+[^;&|\n]*--add-repo|add-apt-repository|yum-config-manager|\/etc\/yum\.repos\.d\/|\/etc\/apt\/sources\.list|\brpm\s+(-\S+\s+)*-[iU]\S*\s+https?:|\b(dnf|yum|apt|apt-get)\s+[^;&|\n]*install\s+[^;&|\n]*(epel-release|remi-release|rpmfusion|https?:\/\/)|\bcurl\s[^|\n]*\|\s*(sudo\s+)?(-E\s+)?(bash|sh)\b|\bwget\s[^|\n]*\|\s*(sudo\s+)?(bash|sh)\b/i },
  { label: "OS 全体のアップグレード", re: /system-upgrade|--releasever|do-release-upgrade|\b(dnf|yum)\s+(-\S+\s+)*(upgrade|update|distro-sync)(\s+-\S+)*\s*($|[;&|)'"\n])|\bapt(-get)?\s+(-\S+\s+)*(dist-upgrade|full-upgrade|upgrade)\b/i },
  { label: "パッケージの削除", re: /\b(dnf|yum|microdnf)\s+(-\S+\s+)*(remove|erase|autoremove)\b|\brpm\s+(-\S+\s+)*(-e|--erase)\b|--nodeps|\bapt(-get)?\s+(-\S+\s+)*(remove|purge|autoremove)\b/i },
  { label: "処理の強制終了", re: /(^|[\s;&|(`'"])(kill|pkill|killall)\s|\bsystemctl\s+kill\b/i },
  { label: "ソースからのビルド・システムのプログラム差し替え", re: /\bmake\s+(-\S+\s+)*install\b|(^|[\s;&|])\.\/configure\b|\b(ln|cp|mv|install)\s+[^;&|\n]*\s\/(usr\/(local\/)?)?s?bin\//i },
  { label: "ファイアウォールの方針変更", re: /\biptables\s+(-\S+\s+)*-P\b|\bufw\s+(default|disable|enable|reset)\b|firewall-cmd\s+[^;&|\n]*--(set-default-zone|panic-on)|\bnft\s+flush\s+ruleset/i },
  { label: "再起動・停止", re: /(^|[\s;&|(`'"])(reboot|shutdown|poweroff|halt)\b|\binit\s+[06]\b|\bsystemctl\s+(reboot|poweroff|halt|kexec)\b/i },
];
/** EDR-94: which "always ask a human" operations a plan contains (empty = none). Matched on the raw command text. */
export function mustAskOps(steps: string[]): string[] {
  const text = steps.join("\n");
  return MUST_ASK.filter((m) => m.re.test(text)).map((m) => m.label);
}

// ---------- EDR-113: operations the AI must never run, even with approval (a human does them by hand if really needed) ----------
const PKG = String.raw`(dnf|dnf-3|dnf5|yum|rpm|rpmdb|microdnf|apt|apt-get|aptitude|dpkg|unattended-upgrades?|packagekitd)`;
const FORBIDDEN: { label: string; re: RegExp; productionOnly?: boolean }[] = [
  { label: "パッケージ管理の処理を強制終了", re: new RegExp(String.raw`\b(pkill|killall)\b[^;&|\n]*\b${PKG}\b|\bkill\b[^;&|\n]*\$\(\s*(pgrep|pidof)\b[^)]*\b${PKG}\b|\b(pgrep|pidof)\b[^;&|\n]*\b${PKG}\b[^;&\n]*\|\s*(sudo\s+)?xargs\s+(-\S+\s+)*(sudo\s+)?kill\b|\bsystemctl\s+kill\s+[^;&|\n]*\b(dnf-makecache|packagekit|apt-daily|unattended-upgrades)`, "i") },
  { label: "パッケージ管理のロック削除", re: /\brm\b[^;&|\n]*(\/var\/lib\/rpm\/\.rpm\.lock|\/var\/lib\/rpm\/__db|\/var\/lib\/dpkg\/lock|\/var\/lib\/apt\/lists\/lock|\/var\/cache\/apt\/archives\/lock|\/var\/run\/yum\.pid|\/var\/lib\/dnf\/[^\s;&|]*lock)/i },
  { label: "本番ホストでのソースビルド", productionOnly: true, re: /\bmake\s+(-\S+\s+)*(install\b|-j\d*(\s|$))|(^|[\s;&|(])\.\/(configure|buildconf)\b|\b(dnf|yum|apt|apt-get)\s+(-\S+\s+)*install\s+[^;&|\n]*\b(gcc|gcc-c\+\+|g\+\+|autoconf|automake|bison|re2c|build-essential)\b|\b(dnf|yum)\s+(-\S+\s+)*group(install|\s+install)\b/i },
];
/** EDR-113: which never-run operations a plan contains (empty = none). env = host.environment. */
export function forbiddenOps(steps: string[], env?: string | null): string[] {
  const text = steps.join("\n");
  return FORBIDDEN.filter((f) => (!f.productionOnly || env === "production") && f.re.test(text)).map((f) => f.label);
}
/** EDR-114: package transactions that can outlive the SSH timeout — run them detached and poll (see runtime). */
const LONG_RE = /\b(dnf|yum|microdnf)\s+(-\S+\s+)*(upgrade|update|install|reinstall|remove|erase|downgrade|distro-sync|groupinstall|history\s+(undo|redo|rollback))\b|--releasever|\bapt(-get)?\s+(-\S+\s+)*(upgrade|dist-upgrade|full-upgrade|install|reinstall|remove|purge|autoremove)\b|\bdo-release-upgrade\b|\bunattended-upgrade\b/i;
export function isLongStep(command: string): boolean { return LONG_RE.test(command); }

/** commands that only edit files / validate / restart — allowed in a retry even if the first attempt used a different one */
const RETRY_SAFE_HEADS = new Set(["cp", "sed", "tee", "mv", "cat", "chown", "chmod", "install", "base64", "echo", "printf", "sleep", "touch", "wazuh-analysisd", "systemctl", "service", "wazuh-control", "test", "diff", "grep", "awk", "head", "tail", "cut", "ls", "mkdir", "python3", "xmllint", "wazuh-logcollector"]);
/** Is `next` within `base`? Returns null if yes, otherwise the reason it is not. */
export function scopeCovers(base: ChangeScope, next: ChangeScope): string | null {
  if (next.opaque && !base.opaque) return "the new plan contains a part the console cannot analyse";
  const outPath = next.paths.find((p) => !base.paths.includes(p));
  if (outPath) return `touches ${outPath}, which the approved plan did not`;
  const outSvc = next.services.find((s) => !base.services.includes(s));
  if (outSvc) return `restarts ${outSvc}, which the approved plan did not`;
  const outHead = next.heads.find((h) => !base.heads.includes(h) && !RETRY_SAFE_HEADS.has(h));
  if (outHead) return `runs '${outHead}', which the approved plan did not`;
  if (!next.paths.length && !next.services.length) return "the new plan does not touch the approved files or services";
  return null;
}
