import { describe, it, expect } from "vitest";
import { buildScript, parse } from "./pkgCandidates.js";

// a lab Amazon Linux 2023 web server on 2026-10-24, before the fix
const AL2023_FIXTURE = [
  "OS=amzn|2023|Amazon Linux 2023.12.20260918",
  "MEM=419|87", "SWAP=1269",
  "REL=2023.12.20260918",
  "INST=php8.3|8.3.33-1.amzn2023.0.1", "INST=php8.3-common|8.3.33-1.amzn2023.0.1", "INST=php8.3-fpm|8.3.33-1.amzn2023.0.1",
  "CUR=php8.3|8.3.33-1.amzn2023.0.1", "CUR=php8.3-common|8.3.33-1.amzn2023.0.1", "CUR=php8.3-fpm|8.3.33-1.amzn2023.0.1",
  "NEWREL=2023.12.20261021",
  "LATEST=php8.3|8.3.36-1.amzn2023.0.1", "LATEST=php8.3-common|8.3.36-1.amzn2023.0.1", "LATEST=php8.3-fpm|8.3.36-1.amzn2023.0.1",
].join("\n");

describe("EDR-114 pkg_candidates", () => {
  it("builds a script and rejects odd names", () => {
    expect(buildScript("php8.3")).toContain("--releasever=latest");
    expect(() => buildScript("php; rm -rf /")).toThrow();
    expect(() => buildScript("$(id)")).toThrow();
  });
  it("AL2023: fix only in a newer release → needs_release_upgrade (the sidekick/33 case)", () => {
    const r = parse("web01-al2023", "php8.3", AL2023_FIXTURE, "8.3.36");
    expect(r.verdict).toBe("needs_release_upgrade");
    expect(r.plan_hint).toContain("--releasever=2023.12.20261021");
    expect(r.long_running).toBe(true);
    expect(r.os.family).toBe("amzn");
  });
  it("AL2023 without a fixed version: newest available is the target", () => {
    expect(parse("h", "php8.3", AL2023_FIXTURE, null).verdict).toBe("needs_release_upgrade");
  });
  it("after the fix → up_to_date", () => {
    const after = AL2023_FIXTURE.replace(/INST=(php8\.3[\w-]*)\|8\.3\.33/g, "INST=$1|8.3.36").replace(/CUR=(php8\.3[\w-]*)\|8\.3\.33/g, "CUR=$1|8.3.36");
    expect(parse("h", "php8.3", after, "8.3.36").verdict).toBe("up_to_date");
  });
  it("fix not shipped anywhere → not_available", () => {
    const none = AL2023_FIXTURE.replace(/LATEST=(php8\.3[\w-]*)\|8\.3\.36/g, "LATEST=$1|8.3.33");
    expect(parse("h", "php8.3", none, "8.3.36").verdict).toBe("not_available");
  });
  it("update in the current release", () => {
    const cur = AL2023_FIXTURE.replace(/CUR=(php8\.3[\w-]*)\|8\.3\.33/g, "CUR=$1|8.3.36");
    expect(parse("h", "php8.3", cur, "8.3.36").verdict).toBe("update_in_release");
  });
  it("Debian: candidate from apt-cache policy", () => {
    const deb = ["OS=debian|12|Debian GNU/Linux 12", "MEM=2000|1200", "INST=php8.2|8.2.20-1~deb12u1", "CUR=php8.2|8.2.35-1~deb12u1"].join("\n");
    const r = parse("d", "php8.2", deb, "8.2.35");
    expect(r.verdict).toBe("update_in_release");
    expect(r.plan_hint).toContain("apt-get install --only-upgrade");
  });
  it("not installed", () => {
    expect(parse("h", "nginx", "OS=amzn|2023|AL\nINST=nginx|", null).verdict).toBe("not_installed");
  });
  it("busy package manager is reported", () => {
    const r = parse("h", "php8.3", AL2023_FIXTURE + "\nBUSY=2423920 dnf", "8.3.36");
    expect(r.package_manager_busy.length).toBe(1);
    expect(r.plan_hint).toContain("kill しない");
  });
});
