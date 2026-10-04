import { describe, expect, it } from "vitest";
import { inIpv4Network, ipSortKey, ipv4ToNumber } from "./net";

describe("ipv4 helpers", () => {
  it("parses only valid IPv4 addresses", () => {
    expect(ipv4ToNumber("10.0.0.1")).toBe(167772161);
    expect(ipv4ToNumber("256.0.0.1")).toBeNull();
    expect(ipv4ToNumber("fe80::1")).toBeNull();
    expect(ipv4ToNumber("1.2.3")).toBeNull();
  });

  it("checks network membership", () => {
    expect(inIpv4Network("192.168.1.20", "192.168.1.0/24")).toBe(true);
    expect(inIpv4Network("192.168.2.20", "192.168.1.0/24")).toBe(false);
    expect(inIpv4Network("10.20.0.5", "10.20.0.4/30")).toBe(true);
    expect(inIpv4Network("10.20.0.8", "10.20.0.4/30")).toBe(false);
    expect(inIpv4Network("10.0.0.1", "10.0.0.1/32")).toBe(true);
    expect(inIpv4Network("fd00::1", "fd00::/120")).toBe(false); // IPv6: not handled here
    expect(inIpv4Network("10.0.0.1", "10.0.0.0/40")).toBe(false);
  });

  it("sorts addresses numerically", () => {
    const sorted = ["10.0.0.10", "10.0.0.2", "fe80::1", "9.255.0.1"].sort((a, b) =>
      ipSortKey(a).localeCompare(ipSortKey(b)),
    );
    expect(sorted).toEqual(["9.255.0.1", "10.0.0.2", "10.0.0.10", "fe80::1"]);
  });
});
