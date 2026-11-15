import { describe, it, expect } from "vitest";
import { normalizeTranscript, PENDING_TOOL_RESULT } from "./index.js";

const A = (ids: string[]) => ({ role: "assistant" as const, content: "", tool_calls: ids.map((id) => ({ id, name: "apply_change", args: {} })) });
const T = (id: string, c = "ok") => ({ role: "tool" as const, tool_call_id: id, name: "apply_change", content: c });
const U = (c: string) => ({ role: "user" as const, content: c });

describe("EDR-145 transcript while an approval is pending", () => {
  it("adds a pending placeholder and turns the late result into a note", () => {
    const out = normalizeTranscript([U("q"), A(["c1"]), U("ゼロになった"), { role: "assistant", content: "よかった" }, T("c1", "executed")] as any);
    expect(out.map((m) => m.role)).toEqual(["user", "assistant", "tool", "user", "assistant", "user"]);
    expect(out[2]).toMatchObject({ tool_call_id: "c1", content: PENDING_TOOL_RESULT });
    expect(out[5].content).toContain("executed");
  });
  it("keeps a normal transcript unchanged", () => {
    const src = [U("q"), A(["a", "b"]), T("a"), T("b"), { role: "assistant", content: "done" }] as any;
    expect(normalizeTranscript(src)).toEqual(src);
  });
  it("fills only the missing call of a multi-call turn", () => {
    const out = normalizeTranscript([A(["a", "b"]), T("a"), U("hi")] as any);
    expect(out.map((m: any) => m.tool_call_id ?? m.role)).toEqual(["assistant", "a", "b", "user"]);
  });
});
