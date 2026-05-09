import { vi } from "vitest";

// Establish the browser extension global before any module loads.
// Test files can reference browser.dns.resolve etc. directly to control behaviour
// because these are vi.fn() instances and vi.clearAllMocks() resets them between tests.

globalThis.browser = {
    dns: {
        resolve: vi.fn(),
    },
    storage: {
        local: {
            get: vi.fn(),
            set: vi.fn(),
            clear: vi.fn(),
        },
    },
    webRequest: {
        onBeforeRequest: {
            addListener: vi.fn(),
            removeListener: vi.fn(),
            hasListener: vi.fn(() => false),
        },
    },
    tabs: {
        onUpdated: { addListener: vi.fn() },
    },
    runtime: {
        onMessage: { addListener: vi.fn() },
        getURL: vi.fn(() => "moz-extension://test-id/"),
    },
    browserAction: {
        setBadgeText: vi.fn(),
        setBadgeBackgroundColor: vi.fn(),
    },
    notifications: {
        create: vi.fn(),
    },
};

// navigator.locks.request(key, [opts,] fn) — just call fn synchronously.
// Node 22+ defines navigator as a read-only getter on globalThis, so we must
// use defineProperty instead of a plain assignment.
Object.defineProperty(globalThis, "navigator", {
    writable: true,
    configurable: true,
    value: {
        locks: {
            request: vi.fn((key, optsOrFn, fn) => {
                const cb = typeof optsOrFn === "function" ? optsOrFn : fn;
                return Promise.resolve(cb(null));
            }),
        },
    },
});
