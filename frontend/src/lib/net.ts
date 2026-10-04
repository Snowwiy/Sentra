/** IPv4 address as a number, or null for anything else (IPv6, invalid). */
export function ipv4ToNumber(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

/** True when `address` is inside the IPv4 network `cidr` ("192.168.1.0/24"). */
export function inIpv4Network(address: string, cidr: string): boolean {
  const [base, prefixText] = cidr.split("/");
  const ip = ipv4ToNumber(address);
  const network = ipv4ToNumber(base ?? "");
  const prefix = prefixText === undefined ? 32 : Number(prefixText);
  if (ip === null || network === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false;
  }
  const size = 2 ** (32 - prefix);
  return Math.floor(ip / size) === Math.floor(network / size);
}

/** Sort key that orders IPv4 addresses numerically (10.0.0.2 before 10.0.0.10). */
export function ipSortKey(address: string): string {
  const value = ipv4ToNumber(address);
  return value === null ? `z${address}` : value.toString().padStart(10, "0");
}
