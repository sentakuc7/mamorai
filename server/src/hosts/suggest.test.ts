import { describe, it, expect } from "vitest";
import { suggestionsFor } from "./suggest.js";

const prof = (pk = "dev-pc", use = "business") => ({ usage: { primary_use: "開発用 PC" }, role_tags: ["開発"], suggest: { notes: "開発用ノート PC。VS Code・Docker", tags: ["windows", "dev"], use, use_reason: "平日毎日使用", purpose_key: pk } });
const host = (o: any = {}) => ({ id: 1, notes: null, tags: JSON.stringify(["windows"]), os_family: "windows", environment: "lab", ai_decisions: null, ...o });

describe("EDR-155 AI suggestions for host settings", () => {
  it("suggests empty / automatic fields and the environment", () => {
    const s = suggestionsFor(host(), prof());
    expect(s.map((x) => x.field).sort()).toEqual(["environment", "notes", "tags"]);
    expect(s.find((x) => x.field === "environment")!.value).toBe("production");
    expect(s.find((x) => x.field === "tags")!.value).toEqual(["windows", "dev"]);
  });
  it("never suggests over values a person typed", () => {
    const s = suggestionsFor(host({ notes: "経理の PC", tags: JSON.stringify(["windows", "経理"]), ai_decisions: JSON.stringify({ environment: { state: "manual", purpose_key: "dev-pc", at: "" } }) }), prof());
    expect(s).toEqual([]);
  });
  it("decided fields come back only when the purpose changes", () => {
    const dec = JSON.stringify({ notes: { state: "dismissed", purpose_key: "dev-pc", at: "" }, tags: { state: "dismissed", purpose_key: "dev-pc", at: "" }, environment: { state: "dismissed", purpose_key: "dev-pc", at: "" } });
    expect(suggestionsFor(host({ ai_decisions: dec }), prof()).length).toBe(0);
    const s = suggestionsFor(host({ ai_decisions: dec }), prof("web-server"));
    expect(s.length).toBe(3);
    expect(s.every((x) => x.changed)).toBe(true);
  });
  it("no environment suggestion when the AI is unsure or it already matches", () => {
    expect(suggestionsFor(host(), prof("dev-pc", "unknown")).some((x) => x.field === "environment")).toBe(false);
    expect(suggestionsFor(host({ environment: "production" }), prof()).some((x) => x.field === "environment")).toBe(false);
  });
});
