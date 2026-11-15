import { describe, it, expect } from "vitest";
import { guessRole } from "./role.js";

describe("EDR-154 server / client PC", () => {
  it("uses agent-pack groups first", () => {
    expect(guessRole({ osName: "Microsoft Windows 11 Pro", groups: ["windows", "desktop"] })).toBe("client");
    expect(guessRole({ osName: "Microsoft Windows Server 2022 Standard", groups: ["windows", "desktop"] })).toBe("server"); // desktop = "not a laptop"
    expect(guessRole({ osName: "Microsoft Windows Server 2016", groups: ["windows", "laptop"] })).toBe("client");
    expect(guessRole({ osName: "Microsoft Windows 11 Pro", groups: ["linux-cloud"] })).toBe("server");
  });
  it("falls back to the OS name", () => {
    expect(guessRole({ osName: "Microsoft Windows 11 Pro" })).toBe("client");
    expect(guessRole({ osName: "Microsoft Windows Server 2016 Standard" })).toBe("server");
    expect(guessRole({ osName: "Ubuntu 26.04" })).toBe("server");
  });
  it("SSH-managed hosts and cloud instances are servers", () => {
    expect(guessRole({ osName: "Microsoft Windows 11 Pro", kind: "managed" })).toBe("server");
    expect(guessRole({ osName: "", cloud: true })).toBe("server");
  });
});
