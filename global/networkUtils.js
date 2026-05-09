/**
 * Returns true when `ip` is an IPv4 address in a private/reserved range:
 *   - Loopback:    127.0.0.0/8
 *   - Private:     10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
 *   - Link-local:  169.254.0.0/16
 *   - Unspecified: 0.0.0.0
 */
export function isPrivateIPv4(ip) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return false;
    const [a, b] = parts;
    return (
        a === 127 ||
        a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 169 && b === 254) ||
        (a === 0 && parts.every(p => p === 0))
    );
}
