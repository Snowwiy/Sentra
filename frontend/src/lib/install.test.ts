import { describe, expect, it } from "vitest";
import {
  checkServerUrl,
  installSteps,
  isEnrollmentToken,
  lifetimeMinutes,
  shellQuote,
  timeLeft,
} from "./install";

// Test value only: the right shape, never issued by a server.
const TOKEN = "sentra_et_TEST-not-a-real-token_0123456789abcdef";

describe("checkServerUrl", () => {
  it("accepts LAN URLs and flags plain HTTP", () => {
    expect(checkServerUrl(" http://192.168.50.201:8000/ ")).toEqual({
      url: "http://192.168.50.201:8000",
      valid: true,
      insecure: true,
      loopback: false,
    });
    expect(checkServerUrl("https://sentra.lan").insecure).toBe(false);
    expect(checkServerUrl("http://[fd00::5]:8000").valid).toBe(true);
  });

  it("flags loopback addresses, which another machine cannot reach", () => {
    for (const url of ["http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"]) {
      expect(checkServerUrl(url).loopback).toBe(true);
    }
  });

  it("rejects anything that is not a plain http(s) URL", () => {
    for (const url of ["", "192.168.1.2:8000", "ftp://x", "http://x; rm -rf /", "http://a b", "http://x/$(id)"]) {
      expect(checkServerUrl(url).valid).toBe(false);
    }
  });
});

describe("installSteps", () => {
  const base = { serverUrl: "http://192.168.50.201:8000", token: TOKEN };

  it("recommended method never puts the token in a command", () => {
    const steps = installSteps({ ...base, method: "file", pkg: "tarball" });
    const text = steps.map((s) => s.command).join("\n");
    expect(text).not.toContain(TOKEN);
    expect(text).toContain("read -rsp");
    expect(text).toContain("umask 077");
    expect(text).toContain(
      "sudo ./install-sentra-agent.sh --server 'http://192.168.50.201:8000' --token-file ./enrollment.token",
    );
    expect(steps.some((s) => s.secret)).toBe(false);
    expect(steps.at(-1)?.command).toBe("systemctl status sentra-agent");
  });

  it("quick method passes the token quoted and marks the step as secret", () => {
    const steps = installSteps({ ...base, method: "inline", pkg: "tarball" });
    const install = steps.find((s) => s.secret);
    expect(install?.command).toBe(
      `sudo ./install-sentra-agent.sh --server 'http://192.168.50.201:8000' --token '${TOKEN}'`,
    );
  });

  it("uses sentra-agent-setup with the .deb", () => {
    const text = installSteps({ ...base, method: "file", pkg: "deb" }).map((s) => s.command).join("\n");
    expect(text).toContain("sudo apt install ./sentra-agent_*_amd64.deb");
    expect(text).toContain("sudo sentra-agent-setup --server");
  });

  it("refuses values that could break out of the shell command", () => {
    expect(() => installSteps({ ...base, token: "sentra_et_x'; rm -rf / #", method: "inline", pkg: "deb" })).toThrow();
    expect(() => installSteps({ ...base, serverUrl: "http://x'$(id)", method: "file", pkg: "deb" })).toThrow();
    expect(isEnrollmentToken(TOKEN)).toBe(true);
    expect(shellQuote("a'b")).toBe(`'a'\\''b'`);
  });
});

describe("token lifetime", () => {
  it("computes minutes and the countdown", () => {
    expect(lifetimeMinutes("2026-10-04T10:00:00Z", "2026-10-04T10:15:00Z")).toBe(15);
    const expires = "2026-10-04T10:15:00Z";
    expect(timeLeft(expires, Date.parse("2026-10-04T10:00:00Z"))).toBe("15:00");
    expect(timeLeft(expires, Date.parse("2026-10-04T10:14:55Z"))).toBe("0:05");
    expect(timeLeft(expires, Date.parse("2026-10-04T10:15:00Z"))).toBeNull();
  });
});
