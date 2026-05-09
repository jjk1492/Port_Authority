import { describe, it, expect } from "vitest";
import { isPrivateIPv4 } from "../global/networkUtils.js";

describe("isPrivateIPv4", () => {
    describe("loopback — 127.0.0.0/8", () => {
        it("blocks 127.0.0.1", () => expect(isPrivateIPv4("127.0.0.1")).toBe(true));
        it("blocks 127.0.0.0", () => expect(isPrivateIPv4("127.0.0.0")).toBe(true));
        it("blocks 127.255.255.255", () => expect(isPrivateIPv4("127.255.255.255")).toBe(true));
        it("blocks 127.1.2.3", () => expect(isPrivateIPv4("127.1.2.3")).toBe(true));
    });

    describe("Class A private — 10.0.0.0/8", () => {
        it("blocks 10.0.0.0", () => expect(isPrivateIPv4("10.0.0.0")).toBe(true));
        it("blocks 10.0.0.1", () => expect(isPrivateIPv4("10.0.0.1")).toBe(true));
        it("blocks 10.255.255.255", () => expect(isPrivateIPv4("10.255.255.255")).toBe(true));
        it("blocks 10.10.10.10", () => expect(isPrivateIPv4("10.10.10.10")).toBe(true));
    });

    describe("Class B private — 172.16.0.0/12", () => {
        it("blocks 172.16.0.0 (boundary start)", () => expect(isPrivateIPv4("172.16.0.0")).toBe(true));
        it("blocks 172.31.255.255 (boundary end)", () => expect(isPrivateIPv4("172.31.255.255")).toBe(true));
        it("blocks 172.20.5.1", () => expect(isPrivateIPv4("172.20.5.1")).toBe(true));
        it("does NOT block 172.15.255.255 (just below range)", () => expect(isPrivateIPv4("172.15.255.255")).toBe(false));
        it("does NOT block 172.32.0.0 (just above range)", () => expect(isPrivateIPv4("172.32.0.0")).toBe(false));
    });

    describe("Class C private — 192.168.0.0/16", () => {
        it("blocks 192.168.0.0", () => expect(isPrivateIPv4("192.168.0.0")).toBe(true));
        it("blocks 192.168.1.1", () => expect(isPrivateIPv4("192.168.1.1")).toBe(true));
        it("blocks 192.168.255.255", () => expect(isPrivateIPv4("192.168.255.255")).toBe(true));
        it("does NOT block 192.167.0.1", () => expect(isPrivateIPv4("192.167.0.1")).toBe(false));
        it("does NOT block 192.169.0.1", () => expect(isPrivateIPv4("192.169.0.1")).toBe(false));
    });

    describe("link-local — 169.254.0.0/16", () => {
        it("blocks 169.254.0.0", () => expect(isPrivateIPv4("169.254.0.0")).toBe(true));
        it("blocks 169.254.1.1", () => expect(isPrivateIPv4("169.254.1.1")).toBe(true));
        it("blocks 169.254.255.255", () => expect(isPrivateIPv4("169.254.255.255")).toBe(true));
        it("does NOT block 169.253.0.1", () => expect(isPrivateIPv4("169.253.0.1")).toBe(false));
        it("does NOT block 169.255.0.1", () => expect(isPrivateIPv4("169.255.0.1")).toBe(false));
    });

    describe("unspecified address — 0.0.0.0", () => {
        it("blocks 0.0.0.0", () => expect(isPrivateIPv4("0.0.0.0")).toBe(true));
        it("does NOT block 0.0.0.1 (not unspecified)", () => expect(isPrivateIPv4("0.0.0.1")).toBe(false));
    });

    describe("public addresses — must NOT be blocked", () => {
        it("allows 8.8.8.8", () => expect(isPrivateIPv4("8.8.8.8")).toBe(false));
        it("allows 1.1.1.1", () => expect(isPrivateIPv4("1.1.1.1")).toBe(false));
        it("allows 93.184.216.34 (example.com)", () => expect(isPrivateIPv4("93.184.216.34")).toBe(false));
        it("allows 172.15.0.1", () => expect(isPrivateIPv4("172.15.0.1")).toBe(false));
        it("allows 192.169.0.1", () => expect(isPrivateIPv4("192.169.0.1")).toBe(false));
        it("allows 11.0.0.1", () => expect(isPrivateIPv4("11.0.0.1")).toBe(false));
    });

    describe("invalid input — must return false, not throw", () => {
        it("returns false for empty string", () => expect(isPrivateIPv4("")).toBe(false));
        it("returns false for a hostname", () => expect(isPrivateIPv4("localhost")).toBe(false));
        it("returns false for an IPv6 address", () => expect(isPrivateIPv4("::1")).toBe(false));
        it("returns false for too few octets", () => expect(isPrivateIPv4("127.0.1")).toBe(false));
        it("returns false for too many octets", () => expect(isPrivateIPv4("127.0.0.1.0")).toBe(false));
        it("returns false for NaN in octet", () => expect(isPrivateIPv4("127.0.x.1")).toBe(false));
    });
});
