import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { llmInput, interpret, checkAction, parseLooseJson } from "./interpret.js";
import { diffFacts } from "./scan.js";
import { linuxScript, describe as describeOp } from "./actions.js";
import type { Facts } from "./collect.js";

function facts(over: Partial<Facts> = {}): Facts {
  return {
    version: 1, collected_at: "2026-10-25T00:00:00Z",
    host: { id: 1, name: "pc1", kind: "agent_only", os_family: "windows", os: "Windows 11", agent_id: "001", agent_status: "active", agent_last_seen: null, address: "10.0.0.5", environment: "lab" },
    system: { os: "Windows 11", ips: ["10.0.0.5"], has_public_ip: false },
    listening: [{ id: "port:tcp/445", proto: "tcp", port: 445, local_ip: "0.0.0.0", exposure: "all", process: "System", pid: 4, service: null, known: "SMB" }, { id: "port:tcp/3389", proto: "tcp", port: 3389, local_ip: "0.0.0.0", exposure: "all", process: "svchost.exe", pid: 900, service: "TermService", known: "RDP" }],
    services: [{ id: "svc:TermService", name: "TermService", state: "RUNNING", pid: 900 }], services_total: 200,
    software: { total: 2, items: [{ id: "pkg:AnyDesk", name: "AnyDesk", version: "8", vendor: null, installed: null }, { id: "pkg:taro-tools", name: "taro-tools", version: "1", vendor: null, installed: null }], hotfixes: 1, latest_hotfixes: ["KB1"], browser_extensions: [] },
    users: [{ id: "user:taro", name: "taro", type: "local", admin: true, groups: ["Administrators"], logons_7d: 12, logon_types: { "10": 3 } }, { id: "user:guest", name: "guest", type: "local", admin: false, groups: [] }],
    processes: [{ id: "proc:AnyDesk.exe", name: "AnyDesk.exe", count: 1, sample_cmd: "C:\\Users\\taro\\AnyDesk.exe --run" }], processes_total: 1,
    connections: [{ id: "conn:203.0.113.9", remote_ip: "203.0.113.9", remote_port: 443, process: "AnyDesk.exe", count: 2 }],
    activity: { heatmap: Array.from({ length: 7 }, () => Array(24).fill(0)), total_7d: 0, top_rules: [] },
    vulns: { total: 0, by_severity: {}, top_packages: [] }, sca: [], limits: {},
    ...over,
  } as Facts;
}

describe("host scan: pseudonymization", () => {
  it("replaces user names in users and free text, but not inside other words", () => {
    const { text, map } = llmInput(facts(), true);
    expect(text).not.toMatch(/user:taro"/);
    expect(text).toContain("user:U01");
    expect(text).toContain("C:\\\\Users\\\\U01\\\\AnyDesk.exe"); // command line scrubbed
    expect(text).toContain("pkg:taro-tools");                   // package id untouched (evidence must still match)
    expect(map.get("U01")).toBe("taro");
  });
  it("keeps names when pseudonymization is off", () => {
    expect(llmInput(facts(), false).text).toContain("user:taro");
  });
});

describe("host scan: interpretation is evidence-checked", () => {
  const fake = (json: any) => ({ name: "fake", model: "fake-1", chat: async () => ({ message: { role: "assistant" as const, content: JSON.stringify(json) }, usage: { input: 10, output: 5 }, model: "fake-1", finish: "stop" }) });
  it("drops items without valid evidence, restores names, validates actions", async () => {
    const r = await interpret(fake({
      summary: "U01 が RDP で使う PC", role_tags: ["端末"], confidence: 0.8,
      services: [{ name: "SMB", port: "tcp/445", purpose: "ファイル共有", confidence: 0.9, evidence: ["port:tcp/445"] }, { name: "Ghost", purpose: "x", evidence: ["port:tcp/9999"] }],
      software_highlights: [{ name: "AnyDesk", why: "リモート操作", evidence: ["pkg:AnyDesk"] }],
      users: [{ name: "U01", finding: "管理者で RDP", evidence: ["user:U01"] }],
      usage: { primary_use: "業務 PC", notes: [], evidence: [] },
      risks: [{ title: "SMB 公開", severity: "medium", detail: "", suggested_action: "block_port", params: { proto: "tcp", port: 445 }, evidence: ["port:tcp/445"] }, { title: "bad", severity: "high", detail: "", suggested_action: "block_port", params: { proto: "tcp", port: 22 }, evidence: ["port:tcp/3389"] }, { title: "rm -rf", severity: "high", suggested_action: "run_command", evidence: ["proc:AnyDesk.exe"] }],
    }) as any, facts(), { pseudonymize: true, maxTokens: 60000 });
    expect(r.profile.services.map((s) => s.name)).toEqual(["SMB"]);
    expect(r.profile.dropped).toBe(1);
    expect(r.profile.summary).toContain("taro");
    expect(r.profile.users[0].name).toBe("taro");
    expect(r.profile.risks[0].suggested_action).toBe("block_port");
    expect(r.profile.risks[1].suggested_action).toBeNull(); // port 22 is not listening
    expect(r.profile.risks[2].suggested_action).toBeNull(); // not in the catalog
  });
  it("tolerates schema drift: severity critical, string confidence, one broken item", async () => {
    const r = await interpret(fake({
      summary: "x", confidence: "0.7",
      services: [{ name: "SMB", port: 445, confidence: "90", evidence: ["port:tcp/445"] }, { purpose: "no name", evidence: ["port:tcp/445"] }],
      risks: [{ title: "SMB 公開", severity: "critical", evidence: ["port:tcp/445"] }],
    }) as any, facts(), { pseudonymize: true, maxTokens: 60000 });
    expect(r.profile.confidence).toBe(0.7);
    expect(r.profile.services[0].port).toBe("445");
    expect(r.profile.services[0].confidence).toBe(0.9);
    expect(r.profile.risks[0].severity).toBe("high");
    expect(r.profile.dropped).toBe(1);
  });
  it("parseLooseJson repairs fences, trailing commas and cut-off answers", () => {
    expect(parseLooseJson('```json\n{"a":[1,2,],}\n```')).toEqual({ a: [1, 2] });
    expect(parseLooseJson('{"a":"x","b":[{"c":1},{"d":"cut')).toEqual({ a: "x", b: [{ c: 1 }] });
    expect(parseLooseJson("no json")).toBeNull();
  });
  it("checkAction accepts only existing targets", () => {
    expect(checkAction("stop_service", { service: "TermService" }, facts()).suggested_action).toBe("stop_service");
    expect(checkAction("stop_service", { service: "Nope" }, facts()).suggested_action).toBeNull();
    expect(checkAction("block_ip", { ip: "203.0.113.9" }, facts()).suggested_action).toBe("block_ip");
    expect(checkAction("block_ip", { ip: "8.8.8.8" }, facts()).suggested_action).toBeNull();
  });
});

describe("host scan: diff", () => {
  it("reports new exposed ports, admins and remote tools; ignores dynamic ports", () => {
    const prev = facts({ software: { total: 1, items: [{ id: "pkg:taro-tools", name: "taro-tools", version: "1", vendor: null, installed: null }], hotfixes: 0, latest_hotfixes: [], browser_extensions: [] }, processes: [], users: [{ id: "user:guest", name: "guest", type: "local", admin: false, groups: [] }], listening: [{ id: "port:tcp/3389", proto: "tcp", port: 3389, local_ip: "0.0.0.0", exposure: "all", process: "svchost.exe", pid: 900, service: "TermService", known: "RDP" }] });
    const cur = facts({ listening: [...facts().listening, { id: "port:tcp/50123", proto: "tcp", port: 50123, local_ip: "0.0.0.0", exposure: "all", process: "lsass.exe", pid: 1, service: null, known: null }] });
    const d = diffFacts(prev, cur);
    expect(d.new_exposed_ports.map((x) => x.port)).toEqual(["tcp/445"]);
    expect(d.new_admins).toEqual(["taro"]);
    expect(d.new_remote_tools).toContain("AnyDesk");
    expect(d.important).toBe(true);
    expect(diffFacts(null, cur).first).toBe(true);
  });
});

describe("host actions: generated Linux scripts", () => {
  const ops: [any, any][] = [["stop_service", { service: "nginx" }], ["block_port", { proto: "tcp", port: 8080 }], ["block_ip", { ip: "203.0.113.9" }], ["block_ip", { ip: "2001:db8::1" }], ["isolate", { allow_dns: true }]];
  for (const [op, p] of ops) for (const revert of [false, true]) {
    it(`${op} ${JSON.stringify(p)} revert=${revert} is valid bash`, () => {
      const s = linuxScript(42, op, p, revert, "100.64.1.2", 22);
      for (const part of [s.apply, s.revert]) execFileSync("bash", ["-n"], { input: part });
      if (op !== "stop_service") expect(s.network).toBe(true);
      expect(describeOp(op, p, revert).length).toBeGreaterThan(3);
    });
  }
  it("isolation keeps SSH from MamorAI and the Wazuh ports", () => {
    const s = linuxScript(1, "isolate", {}, false, "100.64.1.2", 2222);
    expect(s.apply).toContain("ip saddr 100.64.1.2 tcp dport 2222 accept");
    expect(s.apply).toContain("1514, 1515");
    expect(s.revert).toContain("nft delete table inet mamorai_iso");
  });
});
