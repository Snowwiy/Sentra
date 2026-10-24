// Vectores de prueba de FIPS 180-4 / NIST para la implementación propia de SHA-256, y
// comparación con Web Crypto sobre datos de varios tamaños (bordes de bloque de 64 bytes).
import { describe, expect, it } from "vitest";
import { sha256HexSync } from "./sha256";

const utf8 = (text: string) => new TextEncoder().encode(text);

describe("sha256HexSync", () => {
  it("coincide con los vectores de NIST", () => {
    expect(sha256HexSync(utf8(""))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256HexSync(utf8("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(sha256HexSync(utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
    expect(sha256HexSync(new Uint8Array(1_000_000).fill(0x61))).toBe(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
  });

  it("da lo mismo que Web Crypto en los bordes de bloque", async () => {
    for (const size of [1, 55, 56, 63, 64, 65, 119, 120, 128, 1000]) {
      const data = new Uint8Array(size).map((_, i) => (i * 31 + size) & 0xff);
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
      const expected = [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
      expect(sha256HexSync(data), `tamaño ${size}`).toBe(expected);
    }
  });
});
