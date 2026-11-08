import crypto from "crypto";
import dns from "dns";
import type { Request, Response, NextFunction } from "express";

function getSecretKey(): Buffer {
  const raw =
    process.env.TOKEN_ENCRYPTION_KEY ||
    process.env.GOOGLE_CONSOLE_CLIENT_SECRET ||
    process.env.DB_PASSWORD ||
    "uncold-dev-fallback-secret-key-change-in-prod";
  return crypto.createHash("sha256").update(raw).digest();
}

/**
 * Encrypts sensitive OAuth tokens at rest using AES-256-GCM.
 */
export function encryptToken(plaintext: string | null | undefined): string | null {
  if (!plaintext) return null;
  if (plaintext.startsWith("enc:v1:")) return plaintext;

  const key = getSecretKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return `enc:v1:${iv.toString("base64url")}.${authTag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

/**
 * Decrypts AES-256-GCM encrypted tokens, transparently handling legacy plaintext values.
 */
export function decryptToken(stored: string | null | undefined): string | null {
  if (!stored) return null;
  if (!stored.startsWith("enc:v1:")) return stored; // Legacy plaintext fallback

  try {
    const payload = stored.slice("enc:v1:".length);
    const [ivB64, tagB64, dataB64] = payload.split(".");
    if (!ivB64 || !tagB64 || !dataB64) return null;

    const key = getSecretKey();
    const iv = Buffer.from(ivB64, "base64url");
    const authTag = Buffer.from(tagB64, "base64url");
    const encrypted = Buffer.from(dataB64, "base64url");

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString("utf8");
  } catch {
    return null;
  }
}

/**
 * Signs OAuth state payload with HMAC-SHA256 and a 10-minute expiration.
 */
export function signOAuthState(payload: { email: string; returnTo: string }): string {
  const data = {
    ...payload,
    nonce: crypto.randomBytes(16).toString("hex"),
    exp: Date.now() + 10 * 60 * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(data), "utf8").toString("base64url");
  const sig = crypto.createHmac("sha256", getSecretKey()).update(encoded).digest("base64url");
  return `${encoded}.${sig}`;
}

/**
 * Verifies HMAC-SHA256 signature and expiration of OAuth state.
 */
export function verifyOAuthState(stateStr: string): { email: string; returnTo: string } | null {
  if (!stateStr || !stateStr.includes(".")) return null;
  const [encoded, sig] = stateStr.split(".");
  if (!encoded || !sig) return null;

  const expectedSig = crypto.createHmac("sha256", getSecretKey()).update(encoded).digest("base64url");
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (!parsed?.email || typeof parsed.exp !== "number" || Date.now() > parsed.exp) {
      return null;
    }
    return {
      email: String(parsed.email),
      returnTo: typeof parsed.returnTo === "string" ? parsed.returnTo : "/dashboard",
    };
  } catch {
    return null;
  }
}

function isPrivateOrReservedIp(ip: string): boolean {
  // IPv4 checks
  const ipv4Parts = ip.split(".").map(Number);
  if (ipv4Parts.length === 4 && ipv4Parts.every((n) => !Number.isNaN(n) && n >= 0 && n <= 255)) {
    const [a, b] = ipv4Parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    return false;
  }

  // IPv6 checks
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::" || lower.startsWith("fe80:") || lower.startsWith("fc") || lower.startsWith("fd")) {
    return true;
  }
  if (lower.startsWith("::ffff:")) {
    return isPrivateOrReservedIp(lower.slice(7));
  }
  return false;
}

/**
 * Validates that a URL uses http/https and resolves only to public non-reserved IP addresses (SSRF guard).
 */
export async function isSafePublicUrl(rawUrl: string): Promise<boolean> {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    const hostname = parsed.hostname.toLowerCase();
    if (hostname === "localhost" || hostname.endsWith(".local") || hostname.endsWith(".internal")) {
      return false;
    }

    const records = await dns.promises.lookup(hostname, { all: true });
    if (!records || records.length === 0) return false;
    return records.every((rec) => !isPrivateOrReservedIp(rec.address));
  } catch {
    return false;
  }
}

/**
 * Strips CR, LF, and NUL characters to prevent RFC 2822 email header injection.
 */
export function sanitizeHeaderValue(value: string): string {
  return String(value || "").replace(/[\r\n\0]+/g, " ").trim();
}

/**
 * Simple in-memory sliding-window rate limiter middleware.
 */
export function createRateLimiter(windowMs: number, maxRequests: number) {
  const hits = new Map<string, number[]>();

  return (req: Request, res: Response, next: NextFunction): void => {
    const key = `${req.ip || "unknown"}:${(req as any).authUser?.email || ""}`;
    const now = Date.now();
    const recent = (hits.get(key) || []).filter((ts) => now - ts < windowMs);

    if (recent.length >= maxRequests) {
      res.status(429).json({
        error: "Too many requests. Please wait a moment before trying again.",
      });
      return;
    }

    recent.push(now);
    hits.set(key, recent);
    next();
  };
}
