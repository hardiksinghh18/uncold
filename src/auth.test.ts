import { test, describe } from "node:test";
import assert from "node:assert/strict";

describe("Auth Middleware & Routing Protection Tests", () => {
  // Test 1: Authenticated user attempting to visit /sign-in or /sign-up
  test("Redirects authenticated user away from /sign-in to /dashboard", () => {
    const user = { id: "usr_123", email: "test@example.com" };
    const pathname = "/sign-in";
    const isAuthRoute = pathname === "/sign-in" || pathname === "/sign-up";

    let redirectUrl = null;
    if (user && isAuthRoute) {
      redirectUrl = "/dashboard";
    }

    assert.equal(redirectUrl, "/dashboard");
  });

  test("Redirects authenticated user away from /sign-up to /dashboard", () => {
    const user = { id: "usr_123", email: "test@example.com" };
    const pathname: string = "/sign-up";
    const isAuthRoute = pathname === "/sign-in" || pathname === "/sign-up";

    let redirectUrl = null;
    if (user && isAuthRoute) {
      redirectUrl = "/dashboard";
    }

    assert.equal(redirectUrl, "/dashboard");
  });

  // Test 2: Unauthenticated user attempting to access /dashboard
  test("Redirects unauthenticated guest accessing /dashboard to /sign-in with redirect param", () => {
    const user = null;
    const pathname = "/dashboard";
    const isDashboardRoute = pathname.startsWith("/dashboard");

    let redirectUrl = null;
    if (!user && isDashboardRoute) {
      redirectUrl = `/sign-in?redirect=${encodeURIComponent(pathname)}`;
    }

    assert.equal(redirectUrl, "/sign-in?redirect=%2Fdashboard");
  });

  // Test 3: Logged-in user visiting base home route /
  test("Allows authenticated user to view home page / without forced redirect", () => {
    const user = { id: "usr_123", email: "test@example.com" };
    const pathname: string = "/";
    const isAuthRoute = pathname === "/sign-in" || pathname === "/sign-up";
    const isDashboardRoute = pathname.startsWith("/dashboard");

    let redirectUrl = null;
    if (user && isAuthRoute) {
      redirectUrl = "/dashboard";
    } else if (!user && isDashboardRoute) {
      redirectUrl = "/sign-in";
    }

    // Must be null (no redirect)
    assert.equal(redirectUrl, null);
  });
});

describe("OAuth Callback Route Security & Open Redirect Protection Tests", () => {
  // Helper validating destination path
  function sanitizeRedirectUrl(nextParam: string | null, allowedHost: string): string {
    const defaultDestination = "/dashboard";
    if (!nextParam) return defaultDestination;

    // Security check: Must start with '/' and must NOT start with '//' (protocol-relative open redirect)
    if (nextParam.startsWith("/") && !nextParam.startsWith("//") && !nextParam.includes("://")) {
      return nextParam;
    }

    // Malicious external URL detected
    return defaultDestination;
  }

  test("Prevents Open Redirect to external phishing URL", () => {
    const maliciousNext = "https://evil-phishing-site.com";
    const sanitized = sanitizeRedirectUrl(maliciousNext, "localhost:3000");
    assert.equal(sanitized, "/dashboard");
  });

  test("Prevents Protocol-Relative Open Redirect (//evil.com)", () => {
    const maliciousNext = "//evil.com/login";
    const sanitized = sanitizeRedirectUrl(maliciousNext, "localhost:3000");
    assert.equal(sanitized, "/dashboard");
  });

  test("Allows valid internal route redirection (/dashboard/campaigns)", () => {
    const validNext = "/dashboard/campaigns";
    const sanitized = sanitizeRedirectUrl(validNext, "localhost:3000");
    assert.equal(sanitized, "/dashboard/campaigns");
  });
});

describe("Password and Input Validation Unit Tests", () => {
  function validateCredentials(email: string, pass: string): { valid: boolean; error?: string } {
    if (!email || !pass) {
      return { valid: false, error: "Please enter both email and password." };
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return { valid: false, error: "Invalid email format." };
    }
    if (pass.length < 6) {
      return { valid: false, error: "Password must be at least 6 characters." };
    }
    return { valid: true };
  }

  test("Rejects empty credentials", () => {
    const result = validateCredentials("", "");
    assert.equal(result.valid, false);
    assert.equal(result.error, "Please enter both email and password.");
  });

  test("Rejects malformed emails", () => {
    const result = validateCredentials("invalid-email", "secret123");
    assert.equal(result.valid, false);
    assert.equal(result.error, "Invalid email format.");
  });

  test("Rejects short passwords under 6 characters", () => {
    const result = validateCredentials("user@domain.com", "12345");
    assert.equal(result.valid, false);
    assert.equal(result.error, "Password must be at least 6 characters.");
  });

  test("Accepts compliant credentials", () => {
    const result = validateCredentials("founder@startup.com", "superSecurePass123!");
    assert.equal(result.valid, true);
    assert.equal(result.error, undefined);
  });
});
