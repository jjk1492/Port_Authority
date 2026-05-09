import { vi, describe, it, expect, beforeEach } from "vitest";

// Mock the storage module so background.js can be imported without real browser.storage.
// These mocks are hoisted before the import below.
vi.mock("../global/BrowserStorageManager.js", () => ({
    getItemFromLocal: vi.fn(),
    setItemInLocal: vi.fn(),
    modifyItemInLocal: vi.fn(),
    addBlockedPortToHost: vi.fn(),
    addBlockedTrackingHost: vi.fn(),
    increaseBadge: vi.fn(),
}));

import { cancel } from "../background.js";
import {
    getItemFromLocal,
    increaseBadge,
    addBlockedPortToHost,
    addBlockedTrackingHost,
} from "../global/BrowserStorageManager.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRequest(overrides = {}) {
    return {
        thirdParty: true,
        originUrl: "https://evil.com/page",
        url: "http://target.com:8080/path",
        tabId: 1,
        ...overrides,
    };
}

function dnsResult(addresses = [], canonicalName = "") {
    return { addresses, canonicalName };
}

beforeEach(() => {
    vi.clearAllMocks();
    // Default: empty allowlist, DNS resolves to a public IP.
    getItemFromLocal.mockResolvedValue([]);
    browser.dns.resolve.mockResolvedValue(dnsResult(["93.184.216.34"], ""));
});

// ---------------------------------------------------------------------------
// Same-origin guard
// ---------------------------------------------------------------------------

describe("same-origin requests", () => {
    it("allows first-party requests without DNS lookup", async () => {
        const req = makeRequest({ thirdParty: false });
        const result = await cancel(req);

        expect(result).toEqual({ cancel: false });
        expect(browser.dns.resolve).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// Allowlist
// ---------------------------------------------------------------------------

describe("allowlisted origins", () => {
    it("allows requests from a whitelisted origin", async () => {
        getItemFromLocal.mockResolvedValue(["safe.example.com"]);
        const req = makeRequest({ originUrl: "https://safe.example.com/page" });

        const result = await cancel(req);

        expect(result).toEqual({ cancel: false });
        expect(browser.dns.resolve).not.toHaveBeenCalled();
    });

    it("does NOT allow a subdomain of a whitelisted domain (exact-match only)", async () => {
        getItemFromLocal.mockResolvedValue(["example.com"]);
        const req = makeRequest({ originUrl: "https://sub.example.com/page" });

        browser.dns.resolve.mockResolvedValue(dnsResult(["93.184.216.34"], ""));
        const result = await cancel(req);

        expect(result).toEqual({ cancel: false }); // passes — public IP, no ThreatMetrix
        expect(browser.dns.resolve).toHaveBeenCalled(); // allowlist check failed, so DNS ran
    });
});

// ---------------------------------------------------------------------------
// Literal-IP blocking (local_filter regex — pre-existing behaviour)
// ---------------------------------------------------------------------------

describe("literal local IP addresses in the URL", () => {
    const literalPrivateUrls = [
        "http://127.0.0.1:8080/",
        "http://10.0.0.1/",
        "http://192.168.1.1/admin",
        "http://172.16.0.1/",
        "http://169.254.1.1/",
        "http://0.0.0.0/",
        "https://127.0.0.1/",
        "wss://127.0.0.1:9229/",
    ];

    for (const url of literalPrivateUrls) {
        it(`blocks ${url}`, async () => {
            const result = await cancel(makeRequest({ url }));
            expect(result).toEqual({ cancel: true });
            expect(browser.dns.resolve).not.toHaveBeenCalled();
        });
    }
});

// ---------------------------------------------------------------------------
// DNS rebinding — the core fix from PR #73
// ---------------------------------------------------------------------------

describe("DNS rebinding: hostname resolves to a private IP", () => {
    const cases = [
        { label: "loopback 127.0.0.1", addresses: ["127.0.0.1"] },
        { label: "loopback 127.1.2.3", addresses: ["127.1.2.3"] },
        { label: "Class A private 10.0.0.1", addresses: ["10.0.0.1"] },
        { label: "Class B private 172.16.0.1", addresses: ["172.16.0.1"] },
        { label: "Class C private 192.168.1.100", addresses: ["192.168.1.100"] },
        { label: "link-local 169.254.1.1", addresses: ["169.254.1.1"] },
        { label: "unspecified 0.0.0.0", addresses: ["0.0.0.0"] },
        {
            label: "multiple addresses where one is private",
            addresses: ["93.184.216.34", "127.0.0.1"],
        },
    ];

    for (const { label, addresses } of cases) {
        it(`blocks when ${label}`, async () => {
            browser.dns.resolve.mockResolvedValue(dnsResult(addresses, ""));
            const req = makeRequest({ url: "http://rebinding.attacker.com/" });

            const result = await cancel(req);

            expect(result).toEqual({ cancel: true });
            expect(increaseBadge).toHaveBeenCalledWith(req, false);
            expect(addBlockedPortToHost).toHaveBeenCalled();
            expect(addBlockedTrackingHost).not.toHaveBeenCalled();
        });
    }

    it("allows a hostname that resolves only to public IPs", async () => {
        browser.dns.resolve.mockResolvedValue(dnsResult(["8.8.8.8", "8.8.4.4"], ""));
        const req = makeRequest({ url: "http://public.example.com/" });

        const result = await cancel(req);

        expect(result).toEqual({ cancel: false });
        expect(increaseBadge).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// DNS failure — fail-open behaviour
// ---------------------------------------------------------------------------

describe("DNS resolution failure", () => {
    it("allows the request when DNS throws (fail-open)", async () => {
        browser.dns.resolve.mockRejectedValue(new Error("NXDOMAIN"));
        const req = makeRequest({ url: "http://unknown.example.com/" });

        const result = await cancel(req);

        expect(result).toEqual({ cancel: false });
        expect(increaseBadge).not.toHaveBeenCalled();
    });

    it("allows the request on a network error", async () => {
        browser.dns.resolve.mockRejectedValue(new Error("NS_ERROR_NET_TIMEOUT"));
        const result = await cancel(makeRequest({ url: "http://timeout.example.com/" }));
        expect(result).toEqual({ cancel: false });
    });
});

// ---------------------------------------------------------------------------
// ThreatMetrix / online-metrix.net CNAME detection
// ---------------------------------------------------------------------------

describe("ThreatMetrix CNAME detection", () => {
    it("blocks a domain whose CNAME resolves to online-metrix.net", async () => {
        browser.dns.resolve.mockResolvedValue(
            dnsResult(["1.2.3.4"], "tracker.online-metrix.net")
        );
        const req = makeRequest({ url: "http://legit-looking.com/" });

        const result = await cancel(req);

        expect(result).toEqual({ cancel: true });
        expect(increaseBadge).toHaveBeenCalledWith(req, true);
        expect(addBlockedTrackingHost).toHaveBeenCalled();
        expect(addBlockedPortToHost).not.toHaveBeenCalled();
    });

    it("blocks a subdomain of online-metrix.net in the CNAME (case-insensitive)", async () => {
        browser.dns.resolve.mockResolvedValue(
            dnsResult(["1.2.3.4"], "h.ONLINE-METRIX.NET")
        );
        const result = await cancel(makeRequest({ url: "http://tracker.example.com/" }));
        expect(result).toEqual({ cancel: true });
    });

    it("allows a domain with an unrelated CNAME", async () => {
        browser.dns.resolve.mockResolvedValue(
            dnsResult(["93.184.216.34"], "cdn.example.com")
        );
        const result = await cancel(makeRequest({ url: "http://cdn-user.com/" }));
        expect(result).toEqual({ cancel: false });
    });

    it("does NOT flag a private-IP result as ThreatMetrix (private IP check takes priority)", async () => {
        browser.dns.resolve.mockResolvedValue(
            dnsResult(["127.0.0.1"], "some.online-metrix.net")
        );
        const req = makeRequest({ url: "http://weird.example.com/" });

        const result = await cancel(req);

        expect(result).toEqual({ cancel: true });
        // Blocked as port-scan, not as tracker
        expect(increaseBadge).toHaveBeenCalledWith(req, false);
        expect(addBlockedPortToHost).toHaveBeenCalled();
        expect(addBlockedTrackingHost).not.toHaveBeenCalled();
    });
});

// ---------------------------------------------------------------------------
// Addresses array is missing / empty (defensive: nullish coalescing)
// ---------------------------------------------------------------------------

describe("DNS result edge cases", () => {
    it("handles a result with no addresses array", async () => {
        browser.dns.resolve.mockResolvedValue({ canonicalName: "" }); // addresses undefined
        const result = await cancel(makeRequest({ url: "http://oddresolver.example.com/" }));
        expect(result).toEqual({ cancel: false });
    });

    it("handles an empty addresses array", async () => {
        browser.dns.resolve.mockResolvedValue(dnsResult([], ""));
        const result = await cancel(makeRequest({ url: "http://empty.example.com/" }));
        expect(result).toEqual({ cancel: false });
    });
});
