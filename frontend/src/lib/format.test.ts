import { describe, expect, it } from "vitest";
import { fmtNumber, fmtRelative, humanize, pct } from "./format";

describe("format helpers", () => {
  it("formats numbers", () => {
    expect(fmtNumber(12345)).toBe("12,345");
    expect(fmtNumber(null)).toBe("—");
  });
  it("computes percentages safely", () => {
    expect(pct(1, 4)).toBe("25%");
    expect(pct(3, 0)).toBe("0%");
  });
  it("humanizes rule ids", () => {
    expect(humanize("BRUTE_FORCE_IP")).toBe("Brute Force Ip");
  });
  it("formats relative time", () => {
    const now = Date.parse("2026-01-01T12:00:00Z");
    expect(fmtRelative("2026-01-01T11:59:30Z", now)).toBe("30s ago");
    expect(fmtRelative("2026-01-01T10:00:00Z", now)).toBe("2h ago");
    expect(fmtRelative(null, now)).toBe("—");
  });
});
