import { describe, it, expect } from "vitest";
import { deriveDisplay } from "./displayStatus.js";
const ap = (id: number, decision: string, exec: any = null, run_after: string | null = null) => ({ id, decision, exec_result: exec ? JSON.stringify(exec) : null, run_after });

describe("EDR-172 session card states", () => {
  it("running approved plan is 実行中, not 承認待ち", () => {
    const d = deriveDisplay({ status: "waiting_approval", approvals: [ap(1, "approved", { status: "running", win_update: { items: [{ state: "installed" }, { state: "downloading" }, { state: "pending" }] } })], actions: [], schedules: [] });
    expect(d.key).toBe("executing"); expect(d.note).toBe("1/3");
  });
  it("pending card", () => { expect(deriveDisplay({ status: "waiting_approval", approvals: [ap(1, "pending")], actions: [], schedules: [] }).key).toBe("waiting_approval"); });
  it("scheduled approval", () => {
    const d = deriveDisplay({ status: "waiting_user", approvals: [ap(1, "approved", { status: "scheduled" }, "2030-01-01T13:00:00.000Z")], actions: [], schedules: [] });
    expect(d.key).toBe("scheduled"); expect(d.note).toContain("22:00");
  });
  it("contained beats everything", () => {
    const d = deriveDisplay({ status: "done", approvals: [ap(1, "approved", { status: "executed" })], actions: [{ op: "isolate", status: "active" }], schedules: [{ enabled: 1, state: "active", next_run_at: null }] });
    expect(d.key).toBe("contained"); expect(d.extra).toContain("monitoring");
  });
  it("reboot wait / monitoring / rejected / failed / base", () => {
    expect(deriveDisplay({ status: "waiting_user", approvals: [ap(1, "approved", { status: "running" })], actions: [{ op: "reboot", status: "running" }], schedules: [] }).key).toBe("executing");
    expect(deriveDisplay({ status: "waiting_user", approvals: [ap(1, "approved", { status: "executed" })], actions: [{ op: "reboot", status: "active" }], schedules: [] }).key).toBe("reboot_wait");
    expect(deriveDisplay({ status: "done", approvals: [], actions: [], schedules: [{ enabled: 1, state: "active", next_run_at: null }] }).key).toBe("monitoring");
    expect(deriveDisplay({ status: "waiting_user", approvals: [ap(1, "rejected")], actions: [], schedules: [] }).key).toBe("waiting_user");
    expect(deriveDisplay({ status: "done", approvals: [ap(1, "rejected")], actions: [], schedules: [] }).key).toBe("rejected");
    expect(deriveDisplay({ status: "done", approvals: [ap(1, "approved", { status: "failed" })], actions: [], schedules: [] }).key).toBe("failed");
    expect(deriveDisplay({ status: "running", approvals: [], actions: [], schedules: [] }).key).toBe("investigating");
    expect(deriveDisplay({ status: "waiting_external", approvals: [], actions: [], schedules: [] }).key).toBe("waiting_external");
    expect(deriveDisplay({ status: "cancelled", approvals: [], actions: [], schedules: [] }).key).toBe("cancelled");
  });
});
