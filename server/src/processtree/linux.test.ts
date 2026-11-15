import { describe, it, expect } from "vitest";
import { parseExec, isLinuxFocus } from "./linux.js";

const G = "\x1d";
const ok = `type=SYSCALL msg=audit(1792521848.979:111572): arch=c000003e syscall=59 success=yes exit=0 ppid=308337 pid=309222 comm="sh" exe="/usr/bin/dash" key="edr48_web_exec"${G}ARCH=x86_64 SYSCALL=execve AUID="unset" UID="daemon" EUID="daemon" type=EXECVE msg=audit(1792521848.979:111572): argc=3 a0="sh" a1="-c" a2=2F7573722F7362696E2F73656E646D61696C202D74202D69 type=CWD msg=audit(1792521848.979:111572): cwd="/opt/bitnami/wordpress" type=PATH msg=audit(1792521848.979:111572): item=0 name="/bin/sh" inode=262800`;
const fail = `type=SYSCALL msg=audit(1792521848.979:111573): arch=c000003e syscall=59 success=no exit=-2 ppid=309222 pid=309223 comm="sh" exe="/usr/bin/dash" key="edr48_web_exec"${G}ARCH=x86_64 SYSCALL=execve UID="daemon" EUID="daemon" type=CWD msg=audit(1792521848.979:111573): cwd="/opt/bitnami/wordpress" type=PATH msg=audit(1792521848.979:111573): item=0 name="/usr/sbin/sendmail" nametype=UNKNOWN type=PROCTITLE msg=audit(1792521848.979:111573): proctitle=7368002D63002F7573722F7362696E2F73656E646D61696C202D74202D69`;

describe("linux process tree parsing", () => {
  it("decodes hex execve args and kernel time", () => {
    const e = parseExec({ _id: "x", timestamp: "2026-10-21T03:44:09.240+0900", full_log: ok, data: { audit: { id: "111572", pid: "309222", ppid: "308337", syscall: "59", success: "yes", exe: "/usr/bin/dash", execve: { argc: "3", a0: "sh", a1: "-c" } } } });
    expect(e.args).toEqual(["sh", "-c", "/usr/sbin/sendmail -t -i"]);
    expect(e.ts).toBe("2026-10-20T18:44:08.979Z");
    expect(e.user).toBe("daemon");
    expect(e.ppid).toBe(308337);
  });
  it("uses PATH item 0 as the target of a failed execve and proctitle as argv", () => {
    const e = parseExec({ _id: "y", timestamp: "2026-10-21T03:44:09.240+0900", full_log: fail, data: { audit: { id: "111573", pid: "309223", ppid: "309222", syscall: "59", success: "no", exit: "-2", exe: "/usr/bin/dash" } } });
    expect(e.success).toBe(false);
    expect(e.target).toBe("/usr/sbin/sendmail");
    expect(e.args.join(" ")).toBe("sh -c /usr/sbin/sendmail -t -i");
  });
  it("recognises focus ids", () => {
    expect(isLinuxFocus("audit:111573")).toBe(true);
    expect(isLinuxFocus("{ABC-123}")).toBe(false);
  });
});
