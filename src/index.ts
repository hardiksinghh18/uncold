import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import dns from "dns";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { GoogleGenAI } from "@google/genai";
import { google } from "googleapis";
import { initDb, query } from "./db";
import { sendGmailMessage, checkThreadReplies } from "./gmail";
import { extractRichJdMetadata } from "./jdMetadata";
import {
  encryptToken,
  decryptToken,
  signOAuthState,
  verifyOAuthState,
  isSafePublicUrl,
  createRateLimiter,
} from "./security";

dotenv.config();

// Load Supabase public config from backend env or fallback to ../frontend/.env.local
function getSupabasePublicConfig(): { url: string; anonKey: string } {
  let url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || "";
  let anonKey = process.env.SUPABASE_ANON_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "";

  if (!url || !anonKey) {
    try {
      const feEnvPath = path.resolve(__dirname, "../../frontend/.env.local");
      if (fs.existsSync(feEnvPath)) {
        const lines = fs.readFileSync(feEnvPath, "utf8").split(/\r?\n/);
        for (const line of lines) {
          const idx = line.indexOf("=");
          if (idx === -1) continue;
          const k = line.slice(0, idx).trim();
          const v = line.slice(idx + 1).trim();
          if (k === "NEXT_PUBLIC_SUPABASE_URL" && !url) url = v;
          if (k === "NEXT_PUBLIC_SUPABASE_ANON_KEY" && !anonKey) anonKey = v;
        }
      }
    } catch {
      // Ignore fallback read errors
    }
  }
  return { url, anonKey };
}

const verifiedTokenCache = new Map<string, { id: string; email: string; expiresAt: number }>();

/**
 * Verifies the caller's Supabase JWT (Authorization: Bearer <token>) and attaches authUser.
 */
async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";

  if (!token) {
    res.status(401).json({ error: "Authentication required. Please sign in again." });
    return;
  }

  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  const cached = verifiedTokenCache.get(tokenHash);
  if (cached && Date.now() < cached.expiresAt) {
    (req as any).authUser = { id: cached.id, email: cached.email };
    next();
    return;
  }

  const { url, anonKey } = getSupabasePublicConfig();
  if (!url || !anonKey) {
    res.status(500).json({ error: "Supabase auth verification is not configured on backend." });
    return;
  }

  try {
    const resp = await fetch(`${url}/auth/v1/user`, {
      headers: {
        Authorization: `Bearer ${token}`,
        apikey: anonKey,
      },
    });
    if (!resp.ok) {
      res.status(401).json({ error: "Invalid or expired session. Please sign in again." });
      return;
    }
    const userObj: any = await resp.json();
    if (!userObj?.email) {
      res.status(401).json({ error: "Authenticated user has no verified email." });
      return;
    }

    verifiedTokenCache.set(tokenHash, {
      id: userObj.id,
      email: userObj.email,
      expiresAt: Date.now() + 60 * 1000,
    });
    (req as any).authUser = { id: userObj.id, email: userObj.email };
    next();
  } catch (err: any) {
    res.status(401).json({ error: "Failed to verify authentication session." });
  }
}

const aiRateLimiter = createRateLimiter(60 * 1000, 20);
const sendRateLimiter = createRateLimiter(60 * 1000, 15);

// Ensure fast IPv4 resolution for external APIs on Windows
dns.setDefaultResultOrder("ipv4first");

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = (process.env.FRONTEND_URL || "http://localhost:3000").replace(/\/+$/, "");

function getAllowedOrigins(): string[] {
  const configured = (process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || "")
    .split(",")
    .map((o) => o.trim().replace(/\/+$/, ""))
    .filter(Boolean);
  return Array.from(
    new Set([
      ...configured,
      FRONTEND_URL,
      "http://localhost:3000",
      "http://127.0.0.1:3000",
    ])
  );
}

function getBackendPublicOrigin(): string {
  if (process.env.BACKEND_PUBLIC_URL) {
    return process.env.BACKEND_PUBLIC_URL.replace(/\/+$/, "");
  }
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) {
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  }
  if (process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`;
  }
  return `http://localhost:${PORT}`;
}

let dbInitPromise: Promise<void> | null = null;
function ensureDbInitialized(): Promise<void> {
  if (!dbInitPromise) {
    dbInitPromise = initDb().catch((err) => {
      dbInitPromise = null;
      throw err;
    });
  }
  return dbInitPromise;
}

// Configure Multer for in-memory PDF uploads (max 10MB)
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype === "application/pdf" || file.originalname.toLowerCase().endsWith(".pdf")) {
      cb(null, true);
    } else {
      cb(new Error("Only PDF files are supported for resume upload."));
    }
  },
});

// Middleware
app.use(
  cors({
    origin: getAllowedOrigins(),
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(async (_req: Request, _res: Response, next: NextFunction) => {
  try {
    await ensureDbInitialized();
  } catch (err) {
    console.error("DB cold-start init error:", err);
  }
  next();
});

// Helper to extract text from PDF buffer (lazy-loaded to avoid serverless cold-start DOMMatrix issues)
async function extractTextFromPdf(buffer: Buffer): Promise<string> {
  const { PDFParse } = await import("pdf-parse");
  const parser = new PDFParse({ data: new Uint8Array(buffer) });
  try {
    const textResult = await parser.getText();
    return textResult.text || "";
  } finally {
    await parser.destroy().catch(() => {});
  }
}

// Root & Health Check
app.get("/", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "uncold-backend",
    health: "/api/health",
    timestamp: new Date().toISOString(),
  });
});

app.get("/api/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "uncold-backend",
    hasApiKey: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

// Helper: Ultra-fast multi-model generator with instant failover to bypass 503 high-demand retry loops
async function callFastGemini(
  ai: GoogleGenAI,
  prompt: string,
  options: { maxOutputTokens?: number; temperature?: number } = {}
): Promise<string> {
  const models = ["gemini-flash-lite-latest", "gemini-3-flash-preview", "gemini-3.1-flash-lite"];
  let lastError: any = null;

  for (const model of models) {
    try {
      const response = await ai.models.generateContent({
        model,
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          temperature: options.temperature ?? 0.2,
          maxOutputTokens: options.maxOutputTokens ?? 600,
          thinkingConfig: { thinkingBudget: 0 },
        },
      });
      if (response && response.text) return response.text;
    } catch (err: any) {
      lastError = err;
      console.warn(`[FastGemini] Model ${model} unavailable (${err.message?.slice(0, 70)}). Failing over immediately...`);
    }
  }

  throw lastError || new Error("All AI model endpoints are currently busy. Please try again shortly.");
}

interface CandidateLinks {
  portfolio?: string;
  github?: string;
  linkedin?: string;
  resume?: string;
}

function resolveCandidateLinks(profile: any): {
  links: CandidateLinks;
  availableLinksList: string[];
  linksPromptSummary: string;
} {
  const pLinks = (profile?.portfolio_links || {}) as Record<string, any>;
  const clean = (val: any): string => {
    if (!val || typeof val !== "string") return "";
    const trimmed = val.trim();
    if (
      !trimmed ||
      trimmed.toLowerCase() === "n/a" ||
      trimmed.toLowerCase() === "null" ||
      trimmed.toLowerCase() === "none"
    ) {
      return "";
    }
    return trimmed;
  };

  const portfolio = clean(pLinks.portfolio || profile?.portfolio);
  const github = clean(pLinks.github || profile?.github);
  const linkedin = clean(pLinks.linkedin || profile?.linkedin);
  const resume = clean(pLinks.resume_url || profile?.resume_url);

  const availableLinksList: string[] = [];
  if (portfolio) availableLinksList.push(`Portfolio: ${portfolio}`);
  if (github) availableLinksList.push(`GitHub: ${github}`);
  if (linkedin) availableLinksList.push(`LinkedIn: ${linkedin}`);
  if (resume) availableLinksList.push(`Resume: ${resume}`);

  const linksPromptSummary =
    availableLinksList.length > 0
      ? `Available Candidate Links (use ONLY these real URLs, NEVER invent placeholders):\n${availableLinksList.map((l) => `- ${l}`).join("\n")}`
      : "Available Candidate Links: None provided. (DO NOT attach any links or placeholder brackets).";

  return {
    links: { portfolio, github, linkedin, resume },
    availableLinksList,
    linksPromptSummary,
  };
}

function cleanBracketedPlaceholders(text: string, links: CandidateLinks): string {
  if (!text) return "";
  let cleaned = text;

  // 1. Replace bracketed link placeholders with actual URL if candidate has it, otherwise remove
  cleaned = cleaned.replace(
    /\[\s*(?:Portfolio\s*\/?\s*GitHub(?:\s*Link)?|Portfolio(?:\s*Link)?|GitHub(?:\s*Link)?|LinkedIn(?:\s*Link)?|Resume(?:\s*Link)?|Link|URL|Insert\s*Link|Link to Portfolio|Link to GitHub|Link to Resume)\s*\]/gi,
    (match) => {
      const lower = match.toLowerCase();
      if (lower.includes("github") && links.github) return links.github;
      if (lower.includes("portfolio") && links.portfolio) return links.portfolio;
      if (lower.includes("resume") && links.resume) return links.resume;
      if (lower.includes("linkedin") && links.linkedin) return links.linkedin;
      if (links.portfolio) return links.portfolio;
      if (links.github) return links.github;
      if (links.resume) return links.resume;
      return ""; // Remove placeholder if no URL available
    }
  );

  // 2. Strip any standalone bracketed placeholders like "[Your Name]", "[Company]", "[Link]"
  cleaned = cleaned.replace(/\[(?:Link|URL|Portfolio|GitHub|Resume)\]/gi, "");

  // 3. Remove orphaned link labels like "Portfolio & Resume: " or "GitHub: " or "Portfolio: " left without a URL
  cleaned = cleaned.replace(/(?:Portfolio\s*&\s*Resume|Portfolio|GitHub|LinkedIn|Resume|Links?)\s*:\s*(?:\r?\n|$)/gi, "");

  // 4. Normalize markdown bullets (* or -) to clean Unicode bullets (•) and strip bold asterisks
  cleaned = cleaned.replace(/^[ \t]*[\*\-][ \t]+/gm, "• ").replace(/\*\*(.*?)\*\*/g, "$1");

  // 5. Clean up any double spaces or triple newlines
  cleaned = cleaned.replace(/[ \t]{2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim();

  return cleaned;
}

// Helper: Fast (<1.2s) non-blocking company background lookup from JD URL or corporate email domain
async function fetchCompanyBackground(jd: string, recipientEmail: string): Promise<string> {
  try {
    let targetUrl = "";
    const urlMatch = jd.match(/https?:\/\/(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+/i);
    if (urlMatch && !/linkedin\.com|wellfound\.com|angel\.co|greenhouse\.io|lever\.co|ashbyhq\.com|workable\.com|github\.com|google\.com/i.test(urlMatch[0])) {
      targetUrl = urlMatch[0];
    } else if (recipientEmail && !/@(gmail|yahoo|outlook|hotmail|icloud|protonmail)\./i.test(recipientEmail)) {
      const domain = recipientEmail.split("@")[1]?.trim();
      if (domain) targetUrl = `https://${domain}`;
    }

    if (!targetUrl) return "";

    // SSRF Protection: ensure targetUrl resolves only to public non-reserved IPs
    const safeToFetch = await isSafePublicUrl(targetUrl);
    if (!safeToFetch) return "";

    const resp = await fetch(targetUrl, {
      signal: AbortSignal.timeout(1200),
      redirect: "error",
      headers: { "User-Agent": "Mozilla/5.0 (compatible; UncoldBot/1.0)" },
    });
    if (!resp.ok) return "";

    const html = (await resp.text()).slice(0, 30000);
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const descMatch =
      html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i) ||
      html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i) ||
      html.match(/<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']/i);

    const title = titleMatch?.[1]?.replace(/\s+/g, " ").trim() || "";
    const desc = descMatch?.[1]?.replace(/\s+/g, " ").trim() || "";

    if (!title && !desc) return "";
    return `${title}${desc ? ` — ${desc}` : ""}`.slice(0, 300);
  } catch {
    return "";
  }
}

// Helper: Derive a natural, modern greeting from JD / email / company name
function resolveGreetingHint(jd: string, recipientEmail: string, companyName: string): { greeting: string; recipientName: string } {
  const genericPrefixes = /^(careers|jobs|hr|hiring|info|hello|team|talent|recruiting|recruitment|support|contact|admin|noreply|no-reply|apply|founders|office)$/i;
  let recipientName = "";

  const nameMatch = jd.match(/(?:Contact|Reach out to|Hiring Manager|Recruiter|Attn)\s*[:\-]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/);
  if (nameMatch) {
    recipientName = nameMatch[1].trim();
  } else if (recipientEmail && recipientEmail.includes("@")) {
    const prefix = recipientEmail.split("@")[0].split(/[._+-]/)[0];
    if (prefix && prefix.length >= 2 && /^[a-zA-Z]+$/.test(prefix) && !genericPrefixes.test(prefix)) {
      recipientName = prefix.charAt(0).toUpperCase() + prefix.slice(1).toLowerCase();
    }
  }

  if (recipientName) {
    const firstName = recipientName.split(/\s+/)[0];
    return { greeting: `Hi ${firstName},`, recipientName };
  }
  if (companyName) {
    return { greeting: `Hi ${companyName} team,`, recipientName: "" };
  }
  return { greeting: "Hi there,", recipientName: "" };
}

// Main Generation Endpoint
app.post(
  "/api/generate",
  requireAuth,
  aiRateLimiter,
  upload.single("resume"),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey || apiKey === "your_gemini_api_key_here") {
        res.status(500).json({
          error:
            "GEMINI_API_KEY is not configured on the backend. Please add your Gemini API key to backend/.env",
        });
        return;
      }

      const jobDescription = req.body.jobDescription as string | undefined;
      const directResumeText = req.body.resumeText as string | undefined;
      const tone = (req.body.tone as string) || "confident";
      const targetRole = (req.body.targetRole as string) || "Hiring Manager";
      const outreachType = (req.body.outreachType as string) || "email";
      const resumeFile = req.file;

      if (!jobDescription || jobDescription.trim().length < 15) {
        res.status(400).json({
          error: "A detailed job description (minimum 15 characters) is required.",
        });
        return;
      }

      let parsedResumeText = "";

      const clientProfile = req.body.profile;
      let resolvedProfile = clientProfile;
      const emailParam = (req as any).authUser.email as string;

      if (!resolvedProfile && emailParam) {
        // Query user's actual saved profile from uncold.profiles
        const profileRes = await query(
          `SELECT full_name, headline, introduction, skills, projects_and_past_experience, education_details, portfolio_links, resume_url
           FROM uncold.profiles WHERE email = $1 LIMIT 1;`,
          [emailParam]
        );
        if (profileRes.rows.length > 0) {
          resolvedProfile = profileRes.rows[0];
        }
      }

      const linksInfo = resolveCandidateLinks(resolvedProfile);

      if (resumeFile && resumeFile.buffer) {
        try {
          parsedResumeText = await extractTextFromPdf(resumeFile.buffer);
        } catch (pdfErr: any) {
          console.error("PDF Parsing error:", pdfErr);
          res.status(400).json({
            error: "Failed to parse resume PDF. Please ensure the file is not password-protected or corrupt.",
          });
          return;
        }
      } else if (directResumeText && directResumeText.trim().length > 20) {
        parsedResumeText = directResumeText.trim();
      } else if (resolvedProfile && (resolvedProfile.full_name || resolvedProfile.skills)) {
        const topSkills = Array.isArray(resolvedProfile.skills) ? resolvedProfile.skills.slice(0, 15).join(", ") : "";
        const recentProjects = Array.isArray(resolvedProfile.projects_and_past_experience)
          ? resolvedProfile.projects_and_past_experience.slice(0, 2).map((p: any) => `${p.designation} at ${p.company_name}: ${(p.responsibilities_projects || "").slice(0, 150)}`).join("; ")
          : "";
        parsedResumeText = `
Candidate: ${resolvedProfile.full_name || "Applicant"} | ${resolvedProfile.headline || "Software Engineer"}
Summary: ${(resolvedProfile.introduction || "").slice(0, 200)}
Key Skills: ${topSkills}
Experience: ${recentProjects}
${linksInfo.linksPromptSummary}
        `.trim();
      }

      if (!parsedResumeText.trim()) {
        // Fallback concise profile
        parsedResumeText = `
Candidate: Hardik Singh | Associate Frontend Engineer
Key Skills: React, Next.js, TypeScript, Node.js, Express, PostgreSQL, Tailwind CSS, REST APIs, OAuth 2.0
Experience: Built responsive web applications and high-deliverability outreach engines.
${linksInfo.linksPromptSummary}
        `.trim();
      }

      // Fast deterministic regex extraction (<0.1ms) for emails and specified subject
      const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
      const detectedEmails = jobDescription.match(emailRegex) || [];
      const fastRecipientEmail = detectedEmails[0] || "";

      const subjectRegex = /(?:Subject|Apply with subject|Subject Line)\s*[:\-]\s*([^\r\n]+)/i;
      const subjectMatch = jobDescription.match(subjectRegex);
      const fastSpecifiedSubject = subjectMatch ? subjectMatch[1].replace(/^[“"']|[”"']$/g, "").trim() : "";

      const ai = new GoogleGenAI({ apiKey });

      const prompt = `You are Uncold, an elite cold outreach copywriter.

Target Job Description:
${jobDescription.slice(0, 4000)}

Candidate Summary:
${parsedResumeText.slice(0, 2500)}

Channel: ${outreachType === "dm" ? "LinkedIn / Twitter DM" : outreachType === "wellfound" ? "Wellfound Application Note" : "Direct Cold Email"}

Instructions:
${outreachType === "dm"
  ? `1. Subject Line: Leave empty or "[LinkedIn DM]".
2. Message Body: Write an ultra-concise, conversational direct message (under 70 words total, NO salutation like "Dear Hiring Team"). 1 casual hook, 1 proof point solving their specific need, frictionless CTA ("open to a quick chat this week?"), sign-off with first name${linksInfo.links.portfolio || linksInfo.links.github ? ` followed by their actual link URL (${linksInfo.links.portfolio || linksInfo.links.github})` : ""}.
3. CRITICAL RULE ON LINKS AND BRACKETS: NEVER use square brackets "[]" anywhere. NEVER output placeholder text like "[Link]", "[Portfolio Link]", "[GitHub Link]", or "[Portfolio/GitHub Link]". ${linksInfo.availableLinksList.length > 0 ? `Attach ONLY the candidate's actual URLs provided under Available Candidate Links.` : `No links are available, so DO NOT mention or attach any links at all.`}`
  : outreachType === "wellfound"
  ? `1. Subject Line: Leave empty or "[Wellfound Application]".
2. Message Body: Write a crisp Wellfound (AngelList) short cover letter (under 95 words). Direct hook on startup mission, 2 bullet points on relevant shipped features/stack match, polite close, sign-off.
3. CRITICAL RULE ON LINKS AND BRACKETS: NEVER use square brackets "[]" anywhere. NEVER output placeholder text like "[Link]", "[Portfolio]", or "[Resume]". ${linksInfo.availableLinksList.length > 0 ? `Include only the candidate's actual available links (${linksInfo.availableLinksList.join(", ")}). Write the exact URL directly, NEVER inside brackets.` : `No links are available, so DO NOT mention or attach any links at all.`} Every single word must be completely final and ready to send.`
  : `1. Subject Line: If an explicit subject line is specified in the JD (e.g. "${fastSpecifiedSubject || "Application for ..."}") or pre-detected, YOU MUST USE IT VERBATIM. Otherwise, craft a direct conversational subject line.
2. Email Body: Direct hook referencing company/role, 2 concise value points, low-friction CTA (10-min sync), professional sign-off. Under 150 words.
3. CRITICAL RULE ON LINKS AND BRACKETS: NEVER use square brackets "[]" anywhere. NEVER output placeholder text like "[Link]". ${linksInfo.availableLinksList.length > 0 ? `Only reference candidate links that are explicitly provided (${linksInfo.availableLinksList.join(", ")}). Write the exact URL directly, NEVER inside brackets.` : `No links are available, so DO NOT mention or attach any links at all.`}`}

Return ONLY a compact JSON object (no markdown, no code fences):
{
  "extractedInfo": {
    "recipientEmail": "${fastRecipientEmail}",
    "specifiedSubject": "${fastSpecifiedSubject}",
    "recipientName": "string",
    "companyName": "string",
    "jobTitle": "string"
  },
  "coldEmail": {
    "subject": "${outreachType === "dm" ? "[LinkedIn DM]" : outreachType === "wellfound" ? "[Wellfound Note]" : (fastSpecifiedSubject || "string")}",
    "body": "string"
  }
}`;

      // Call ultra-fast Gemini with zero thinking tokens and instant failover
      const responseText = await callFastGemini(ai, prompt, {
        temperature: 0.3,
        maxOutputTokens: 550,
      });

      if (!responseText) {
        throw new Error("Unable to generate outreach response. Please try again.");
      }

      let parsedPayload: any;
      try {
        parsedPayload = JSON.parse(responseText);
      } catch {
        const cleaned = responseText
          .replace(/```json/gi, "")
          .replace(/```/g, "")
          .trim();
        parsedPayload = JSON.parse(cleaned);
      }

      // Backward compatibility normalization and deterministic backfill
      if (!parsedPayload.extractedInfo) parsedPayload.extractedInfo = {};
      if (!parsedPayload.extractedInfo.recipientEmail && fastRecipientEmail) {
        parsedPayload.extractedInfo.recipientEmail = fastRecipientEmail;
      }
      if (!parsedPayload.extractedInfo.specifiedSubject && fastSpecifiedSubject) {
        parsedPayload.extractedInfo.specifiedSubject = fastSpecifiedSubject;
      }
      if (fastSpecifiedSubject) {
        if (!parsedPayload.coldEmail) parsedPayload.coldEmail = {};
        parsedPayload.coldEmail.subject = fastSpecifiedSubject;
        parsedPayload.subject = fastSpecifiedSubject;
      }

      if (parsedPayload.coldEmail && !parsedPayload.subject) {
        parsedPayload.subject = parsedPayload.coldEmail.subject;
        parsedPayload.body = parsedPayload.coldEmail.body;
      }

      // Sanitize unicode dashes/quotes in subject and text to standard ASCII characters
      if (parsedPayload.subject) {
        parsedPayload.subject = parsedPayload.subject
          .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015]/g, "-")
          .replace(/[\u2018\u2019]/g, "'")
          .replace(/[\u201C\u201D]/g, '"')
          .trim();
      }
      if (parsedPayload.coldEmail?.subject) {
        parsedPayload.coldEmail.subject = parsedPayload.coldEmail.subject
          .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015]/g, "-")
          .replace(/[\u2018\u2019]/g, "'")
          .replace(/[\u201C\u201D]/g, '"')
          .trim();
      }

      if (parsedPayload.coldEmail?.body) {
        parsedPayload.coldEmail.body = cleanBracketedPlaceholders(parsedPayload.coldEmail.body, linksInfo.links);
      }
      if (parsedPayload.body) {
        parsedPayload.body = cleanBracketedPlaceholders(parsedPayload.body, linksInfo.links);
      }

      res.json({
        success: true,
        data: parsedPayload,
      });
    } catch (error: any) {
      console.error("Backend generation error:", error);
      res.status(500).json({
        error: error.message || "An unexpected error occurred while generating outreach.",
      });
    }
  }
);

// 0b. Real-Time Streaming Generation Endpoint (SSE Chunk Streaming)
app.post("/api/generate-stream", requireAuth, aiRateLimiter, async (req: Request, res: Response): Promise<void> => {
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      res.status(500).json({ error: "GEMINI_API_KEY is not configured." });
      return;
    }

    const jobDescription = req.body.jobDescription as string | undefined;
    const clientProfile = req.body.profile;
    const emailParam = (req as any).authUser.email as string;
    const tone = (req.body.tone as string) || "confident";
    const outreachType = (req.body.outreachType as string) || "email";

    if (!jobDescription || jobDescription.trim().length < 15) {
      res.status(400).json({ error: "A detailed job description (minimum 15 characters) is required." });
      return;
    }

    // 1. Instant deterministic regex extraction (<0.1ms)
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const detectedEmails = jobDescription.match(emailRegex) || [];
    const fastRecipientEmail = detectedEmails[0] || "";

    const subjectRegex = /(?:Subject|Apply with subject|Subject Line)\s*[:\-]\s*([^\r\n]+)/i;
    const subjectMatch = jobDescription.match(subjectRegex);
    let fastSpecifiedSubject = subjectMatch ? subjectMatch[1].replace(/^[“"']|[”"']$/g, "").trim() : "";
    if (fastSpecifiedSubject) {
      fastSpecifiedSubject = fastSpecifiedSubject
        .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015]/g, "-")
        .replace(/[\u2018\u2019]/g, "'")
        .replace(/[\u201C\u201D]/g, '"')
        .trim();
    }

    // Extract Company Name & Job Title quickly for tracking & grouping
    let fastCompanyName = "";
    const companyExplicitMatch = jobDescription.match(/(?:Company|Organization|Startup)\s*[:\-]\s*([^\r\n,]+)/i);
    const companyAtMatch = jobDescription.match(/\b(?:at|with)\s+([A-Z][A-Za-z0-9.&-]*(?:\s+[A-Z][A-Za-z0-9.&-]*){0,2})(?=[.,\s\r\n]|$)/);
    if (companyExplicitMatch) {
      fastCompanyName = companyExplicitMatch[1].trim();
    } else if (companyAtMatch) {
      fastCompanyName = companyAtMatch[1].trim();
    } else if (fastRecipientEmail && !/@(gmail|yahoo|outlook|hotmail|icloud|protonmail)\./i.test(fastRecipientEmail)) {
      const domainPart = fastRecipientEmail.split("@")[1]?.split(".")[0] || "";
      if (domainPart) fastCompanyName = domainPart.charAt(0).toUpperCase() + domainPart.slice(1);
    }

    let fastJobTitle = "";
    const roleMatch = jobDescription.match(/(?:hiring\s+(?:a|an)\s+|looking for\s+(?:a|an)\s+|Role\s*[:\-]\s*|Position\s*[:\-]\s*)([A-Za-z0-9/+\- ]{3,50}?)(?=\s+(?:at|in|with|for)\b|[\r\n.,(]|$)/i);
    if (roleMatch) {
      fastJobTitle = roleMatch[1].trim();
    }

    const safeJd = jobDescription || "";
    const { greeting, recipientName: fastRecipientName } = resolveGreetingHint(
      safeJd,
      fastRecipientEmail,
      fastCompanyName
    );

    // 2. Profile resolution + fast parallel company website background lookup (<1.2s cap)
    const [resolvedProfileResult, companyBackground] = await Promise.all([
      (async () => {
        if (clientProfile) return clientProfile;
        if (!emailParam) return null;
        const profileRes = await query(
          `SELECT full_name, location, headline, introduction, skills, projects_and_past_experience, portfolio_links, resume_url FROM uncold.profiles WHERE email = $1 LIMIT 1;`,
          [emailParam]
        );
        return profileRes.rows[0] || null;
      })(),
      fetchCompanyBackground(safeJd, fastRecipientEmail),
    ]);

    const resolvedProfile = resolvedProfileResult;
    const linksInfo = resolveCandidateLinks(resolvedProfile);
    const rawCandidateName = (resolvedProfile?.full_name || "Hardik Singh").trim();
    const candidateName =
      rawCandidateName === rawCandidateName.toUpperCase()
        ? rawCandidateName.replace(/\b\w+/g, (w: string) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
        : rawCandidateName;
    const candidateLocation = resolvedProfile?.location ? `\nLocation: ${resolvedProfile.location}` : "";

    let parsedResumeText = "";
    let alignedSkillsList: string[] = [];
    if (resolvedProfile && (resolvedProfile.full_name || resolvedProfile.skills)) {
      const allSkills: string[] = Array.isArray(resolvedProfile.skills) ? resolvedProfile.skills : [];
      const jdLower = safeJd.toLowerCase();
      alignedSkillsList = allSkills.filter((sk) => {
        const s = sk.trim().toLowerCase();
        if (!s) return false;
        const base = s.replace(/\.js$/i, "");
        return jdLower.includes(s) || (base.length >= 2 && jdLower.includes(base));
      });
      const alignedText = alignedSkillsList.slice(0, 8).join(", ");
      const otherSkills = allSkills.filter((s) => !alignedSkillsList.includes(s)).slice(0, 10).join(", ");
      const introSummary = resolvedProfile.introduction ? `\nExperience Summary: ${resolvedProfile.introduction.slice(0, 220)}` : "";
      const recentProjects = Array.isArray(resolvedProfile.projects_and_past_experience)
        ? resolvedProfile.projects_and_past_experience
            .slice(0, 2)
            .map(
              (p: any) =>
                `${p.designation} at ${p.company_name}${p.from ? ` (${p.from}–${p.to || "Present"})` : ""}: ${(p.responsibilities_projects || "").slice(0, 160)}`
            )
            .join("; ")
        : "";
      parsedResumeText = `Candidate: ${candidateName} | ${resolvedProfile.headline || "Software Engineer"}${candidateLocation}${introSummary}${alignedText ? `\nJD-Aligned Skills: ${alignedText}` : ""}\nOther Core Skills: ${otherSkills}\nWork Experience: ${recentProjects}\n${linksInfo.linksPromptSummary}`;
    }

    if (!parsedResumeText.trim()) {
      parsedResumeText = `Candidate: ${candidateName} | Associate Frontend Engineer${candidateLocation}\nSkills: React, Next.js, TypeScript, Node.js, Express, REST APIs\nExperience: Built scalable web applications and high-deliverability outreach tools.\n${linksInfo.linksPromptSummary}`;
    }

    // Set up SSE headers
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    if (res.flushHeaders) res.flushHeaders();

    const smartDefaultSubject =
      fastJobTitle && fastCompanyName
        ? `${fastJobTitle} @ ${fastCompanyName} — Quick note`
        : fastCompanyName
        ? `Quick note re: ${fastCompanyName} engineering role`
        : fastJobTitle
        ? `Quick note re: ${fastJobTitle} opening`
        : "Quick note regarding your open role";

    const initialSubject = fastSpecifiedSubject || smartDefaultSubject;
    const candidateSkillsList: string[] = Array.isArray(resolvedProfile?.skills)
      ? resolvedProfile.skills
      : [];
    const jobMetadata = extractRichJdMetadata(
      jobDescription,
      fastCompanyName,
      fastJobTitle,
      candidateSkillsList
    );

    // Immediately push pre-detected metadata to client (Time to First Byte: ~10ms!)
    res.write(`data: ${JSON.stringify({
      type: "meta",
      recipientEmail: fastRecipientEmail,
      recipientName: fastRecipientName,
      subject: initialSubject,
      companyName: fastCompanyName,
      jobTitle: fastJobTitle,
      jobMetadata,
    })}\n\n`);

    const companyContextBlock = companyBackground
      ? `\nCompany Background (from website):\n${companyBackground}\n`
      : "";

    // 3. Prompt Construction based on Outreach Format (Email vs DM vs Wellfound Note)
    let prompt = "";
    if (outreachType === "dm") {
      prompt = `You are Uncold, crafting an ultra-concise, high-reply direct message (DM) for LinkedIn or Twitter.

Target Job Description:
${jobDescription.slice(0, 3000)}
${companyContextBlock}
Candidate Summary:
${parsedResumeText}

Tone: ${tone}

Strict Instructions:
- Start with a warm, natural greeting: "${greeting.replace("Hi ", "Hey ")}" (never "Dear Sir/Madam").
- Format: Plain text direct message (NO subject line, NO JSON, NO markdown asterisks * or **).
- Length: Under 65 words total (must read effortlessly in an InMail / DM preview).
- Opening: Crisp 1-sentence hook referencing what they're building or the specific role.
- Proof point: 1 punchy sentence showing concrete shipped work that solves their exact need.
- Low-friction CTA: "Open to a quick chat this week?"
- Sign-off: Just candidate's first name${linksInfo.links.portfolio || linksInfo.links.github ? ` followed by their actual link URL (${linksInfo.links.portfolio || linksInfo.links.github})` : ""}.
- CRITICAL RULE REGARDING LINKS AND BRACKETS:
  * NEVER use square brackets "[]" anywhere in your response.
  * NEVER output placeholder text like "[Link]", "[Portfolio Link]", "[GitHub Link]", or "[Portfolio/GitHub Link]".
  * ${linksInfo.availableLinksList.length > 0 ? `Attach ONLY the candidate's actual URLs provided under Available Candidate Links.` : `No links are available. DO NOT attach or mention any links at all.`}`;
    } else if (outreachType === "wellfound") {
      prompt = `You are Uncold, crafting a crisp, high-signal application cover note for Wellfound (AngelList) or startup job boards.

Target Job Description:
${jobDescription.slice(0, 3000)}
${companyContextBlock}
Candidate Summary:
${parsedResumeText}

Tone: ${tone}

Strict Instructions:
- Start with a natural greeting: "${greeting}" (never "Dear Sir/Madam").
- Format: Short application cover note (under 95 words total, NO subject line, NO JSON, NO markdown asterisks * or **).
- Hook: Direct statement connecting their product/mission to the candidate's relevant shipped work.
- Use 2 clean Unicode bullets ("• ") highlighting relevant shipped features and core stack match.
- Low-friction closing: "Would love to connect and share more if there's synergy."
- Sign-off: Best regards, ${candidateName}.
- CRITICAL RULE REGARDING LINKS AND BRACKETS:
  * NEVER use square brackets "[]" anywhere in your response.
  * NEVER output placeholder text like "[Link]", "[Portfolio]", or "[Resume]".
  * ${linksInfo.availableLinksList.length > 0 ? `Attach ONLY the candidate's actual available links (${linksInfo.availableLinksList.join(", ")}). Write the exact URL directly, NEVER inside brackets.` : `No links are available. DO NOT mention or attach any links at all.`}`;
    } else {
      prompt = `You are Uncold, an elite cold outreach copywriter optimizing for maximum reply rate from busy founders and hiring managers.

Target Job Description:
${jobDescription.slice(0, 3000)}
${companyContextBlock}
Candidate Summary:
${parsedResumeText}

Tone: ${tone}

Strict Instructions:
- Write ONLY the body of the cold email (NO subject line header, NO JSON, NO markdown code fences).
- Greeting: Start with "${greeting}" (NEVER use "Dear Sir/Madam" or "Dear Hiring Team").
- Eye-Catching Opening Paragraph (2 sentences):
  * Sentence 1: Skip clichés ("I hope this email finds you well", "I am writing to apply"). Immediately hook the reader by referencing their specific product, engineering challenge, or company mission.
  * Sentence 2: Weave in a crisp 1-line self-introduction highlighting the candidate's role, experience, and top JD-aligned skills${alignedSkillsList.length > 0 ? ` (specifically ${alignedSkillsList.slice(0, 4).join(", ")})` : ""} (e.g. "I'm a Full Stack Engineer with 2+ years of experience building scalable systems with ..."). Never use generic phrasing like "I've spent my career...".
- High-Signal Proof Points (Experience & Skills): Write exactly 2 crisp bullets using clean Unicode bullets ("• " — NEVER use markdown "*" or "**") highlighting concrete past work experience, measurable impact, and the top matching skills from the JD.
- Location/Availability & Resume Link:
  * If the JD mentions a specific city/onsite office and the candidate's location matches, mention it naturally (e.g., "Being based in ${resolvedProfile?.location || "Delhi"}, I am ready to work full-time at your onsite office.").
  * ${linksInfo.links.resume ? `Include ONLY the candidate's Resume link formatted cleanly on its own line right below (no Portfolio, GitHub, or LinkedIn links), like:\n  Resume: ${linksInfo.links.resume}` : `No resume link is available. Do NOT attach or mention any links (no Portfolio, GitHub, LinkedIn, or Resume links).`}
- Frictionless CTA: End with a low-pressure, specific ask (e.g., "Open to a quick 10-min chat this week to see if I can help ship this?").
- Sign-off:
  Best regards,
  ${candidateName}
- Length: Keep the entire email tight, scannable, and under 140 words.
- CRITICAL RULE REGARDING LINKS AND BRACKETS:
  * NEVER use square brackets "[]" anywhere in your response.
  * NEVER output placeholder text like "[Link]", "[Portfolio Link]", or "[Resume]".
  * ${linksInfo.links.resume ? `ONLY attach the Resume link (${linksInfo.links.resume}) as "Resume: ${linksInfo.links.resume}". Do NOT include Portfolio, GitHub, or LinkedIn links.` : `Do NOT include any links or placeholders at all.`}`;
    }

    const ai = new GoogleGenAI({ apiKey });

    // Stream directly using gemini-flash-lite-latest with fallback
    const models = ["gemini-flash-lite-latest", "gemini-3-flash-preview", "gemini-3.1-flash-lite"];
    let streamSuccess = false;

    for (const model of models) {
      try {
        const stream = await ai.models.generateContentStream({
          model,
          contents: prompt,
          config: {
            maxOutputTokens: 400,
            temperature: 0.3,
            thinkingConfig: { thinkingBudget: 0 },
          },
        });

        let bracketBuffer = "";

        for await (const chunk of stream) {
          if (!chunk.text) continue;
          let textToSend = chunk.text;

          // If a bracket is opened or we are buffering brackets, hold until closed
          if (bracketBuffer || textToSend.includes("[")) {
            bracketBuffer += textToSend;
            if (bracketBuffer.includes("]")) {
              const cleaned = cleanBracketedPlaceholders(bracketBuffer, linksInfo.links);
              bracketBuffer = "";
              if (cleaned) {
                res.write(`data: ${JSON.stringify({ type: "chunk", text: cleaned })}\n\n`);
              }
            }
          } else {
            res.write(`data: ${JSON.stringify({ type: "chunk", text: textToSend })}\n\n`);
          }
        }

        if (bracketBuffer) {
          const cleaned = cleanBracketedPlaceholders(bracketBuffer, linksInfo.links);
          if (cleaned) {
            res.write(`data: ${JSON.stringify({ type: "chunk", text: cleaned })}\n\n`);
          }
        }

        streamSuccess = true;
        break;
      } catch (streamErr: any) {
        console.warn(`Streaming failed on ${model} (${streamErr.message}). Trying fallback...`);
      }
    }

    if (!streamSuccess) {
      res.write(`data: ${JSON.stringify({ type: "error", error: "AI service temporarily busy. Please retry." })}\n\n`);
    } else {
      res.write(`data: ${JSON.stringify({ type: "done" })}\n\n`);
    }

    res.end();
  } catch (err: any) {
    console.error("Stream generation error:", err);
    if (!res.headersSent) {
      res.status(500).json({ error: err.message || "Streaming failed." });
    } else {
      res.write(`data: ${JSON.stringify({ type: "error", error: err.message })}\n\n`);
      res.end();
    }
  }
});

// Helper: Verify that a Google access token actually has gmail.send scope granted
async function hasGmailSendScope(accessToken: string): Promise<boolean> {
  if (!accessToken) return false;
  try {
    const resp = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(accessToken)}`
    );
    if (!resp.ok) return false;
    const info: any = await resp.json();
    const scopeStr = String(info?.scope || "");
    return scopeStr.includes("https://www.googleapis.com/auth/gmail.send");
  } catch {
    return false;
  }
}

// 1. Sync & persist user's Google tokens (encrypted at rest)
app.post("/api/auth/sync-google-token", requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const email = (req as any).authUser.email as string;
    const { providerToken, providerRefreshToken } = req.body;
    if (!providerToken) {
      res.status(400).json({ error: "Missing required field: providerToken." });
      return;
    }

    // Verify whether the user actually checked the gmail.send permission box
    const hasSendScope = await hasGmailSendScope(providerToken);

    if (hasSendScope) {
      await query(
        `
        INSERT INTO uncold.users (email, connected_gmail, google_access_token, google_refresh_token, gmail_scopes_verified, updated_at)
        VALUES ($1, $1, $2, $3, true, NOW())
        ON CONFLICT (email)
        DO UPDATE SET
          connected_gmail = COALESCE(uncold.users.connected_gmail, EXCLUDED.connected_gmail),
          google_access_token = EXCLUDED.google_access_token,
          google_refresh_token = COALESCE(EXCLUDED.google_refresh_token, uncold.users.google_refresh_token),
          gmail_scopes_verified = true,
          updated_at = NOW();
        `,
        [email, encryptToken(providerToken), encryptToken(providerRefreshToken)]
      );
    } else {
      // User signed in with Google but unchecked Gmail permissions
      await query(
        `
        INSERT INTO uncold.users (email, gmail_scopes_verified, updated_at)
        VALUES ($1, false, NOW())
        ON CONFLICT (email)
        DO UPDATE SET
          gmail_scopes_verified = false,
          google_access_token = NULL,
          google_refresh_token = NULL,
          updated_at = NOW();
        `,
        [email]
      );
    }

    res.json({
      success: true,
      gmailScopesGranted: hasSendScope,
      message: hasSendScope
        ? "Google tokens synchronized with Gmail permissions."
        : "Signed in without Gmail send permission.",
    });
  } catch (err: any) {
    console.error("Token sync error:", err);
    res.status(500).json({ error: err.message || "Failed to sync token." });
  }
});

// 2. Check user's Gmail connection status
app.get("/api/gmail/status", requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const email = (req as any).authUser.email as string;

    const result = await query(
      `SELECT google_access_token, google_refresh_token, connected_gmail, gmail_scopes_verified FROM uncold.users WHERE email = $1 LIMIT 1;`,
      [email]
    );

    const row = result.rows[0];
    const storedAccess = decryptToken(row?.google_access_token);
    const storedRefresh = decryptToken(row?.google_refresh_token);
    const hasTokens = Boolean(storedAccess || storedRefresh);
    let scopesVerified = Boolean(row?.gmail_scopes_verified);

    // If tokens exist but gmail_scopes_verified is false/null (e.g. legacy row), verify actual scope with Google
    if (hasTokens && !scopesVerified) {
      let tokenToCheck = storedAccess;
      if (
        storedRefresh &&
        process.env.GOOGLE_CONSOLE_CLIENT_ID &&
        process.env.GOOGLE_CONSOLE_CLIENT_SECRET
      ) {
        try {
          const oauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CONSOLE_CLIENT_ID,
            process.env.GOOGLE_CONSOLE_CLIENT_SECRET
          );
          oauth2Client.setCredentials({
            access_token: storedAccess || undefined,
            refresh_token: storedRefresh,
          });
          const refreshed = await oauth2Client.getAccessToken();
          if (refreshed?.token) tokenToCheck = refreshed.token;
        } catch {
          // Ignore refresh failure
        }
      }

      if (tokenToCheck) {
        scopesVerified = await hasGmailSendScope(tokenToCheck);
        await query(
          `UPDATE uncold.users SET gmail_scopes_verified = $1, google_access_token = COALESCE($2, google_access_token) WHERE email = $3;`,
          [scopesVerified, encryptToken(tokenToCheck), email]
        );
      }
    }

    const isConnected = hasTokens && scopesVerified;

    res.json({
      connected: isConnected,
      hasRefreshToken: Boolean(storedRefresh),
      connectedGmail: isConnected ? row?.connected_gmail || email : null,
    });
  } catch (err: any) {
    res.json({ connected: false, error: err.message });
  }
});

// 2b. Start dedicated Gmail OAuth flow (authenticated, HMAC-signed state)
app.get("/api/gmail/connect", requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const email = (req as any).authUser.email as string;
    const returnTo = (req.query.returnTo as string) || "/dashboard";

    const clientId = process.env.GOOGLE_CONSOLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CONSOLE_CLIENT_SECRET;
    if (!clientId || !clientSecret) {
      res.status(500).json({ error: "Google OAuth credentials are not configured on backend." });
      return;
    }

    const backendOrigin = getBackendPublicOrigin();
    const redirectUri = process.env.GOOGLE_GMAIL_REDIRECT_URI || `${backendOrigin}/api/gmail/callback`;

    const oauth2Client = new google.auth.OAuth2(clientId, clientSecret, redirectUri);

    const safeReturnTo =
      returnTo.startsWith("/") && !returnTo.startsWith("//") && !returnTo.includes("://")
        ? returnTo
        : "/dashboard";

    const state = signOAuthState({ email, returnTo: safeReturnTo });

    const authUrl = oauth2Client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      include_granted_scopes: true,
      login_hint: email,
      scope: [
        "https://www.googleapis.com/auth/gmail.send",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/userinfo.email",
      ],
      state,
    });

    if (req.query.format === "json") {
      res.json({ url: authUrl });
      return;
    }

    res.redirect(authUrl);
  } catch (err: any) {
    console.error("Gmail OAuth connect error:", err);
    res.status(500).json({ error: err.message || "Failed to initiate Gmail OAuth." });
  }
});

// 2c. Dedicated Gmail OAuth Callback (verifies HMAC-signed state & encrypts tokens)
app.get("/api/gmail/callback", async (req: Request, res: Response): Promise<void> => {
  let returnTo = "/dashboard";
  let accountEmail = "";

  try {
    const code = req.query.code as string | undefined;
    const stateParam = req.query.state as string | undefined;
    const oauthError = req.query.error as string | undefined;

    if (stateParam) {
      const verified = verifyOAuthState(stateParam);
      if (verified) {
        accountEmail = verified.email;
        if (
          verified.returnTo.startsWith("/") &&
          !verified.returnTo.startsWith("//") &&
          !verified.returnTo.includes("://")
        ) {
          returnTo = verified.returnTo;
        }
      }
    }

    if (oauthError || !code || !accountEmail) {
      const msg = encodeURIComponent(oauthError || "Invalid or expired OAuth state. Please try connecting Gmail again.");
      res.redirect(`${FRONTEND_URL}${returnTo}?gmail_error=${msg}`);
      return;
    }

    const clientId = process.env.GOOGLE_CONSOLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CONSOLE_CLIENT_SECRET;
    const backendOrigin = getBackendPublicOrigin();
    const redirectUri = process.env.GOOGLE_GMAIL_REDIRECT_URI || `${backendOrigin}/api/gmail/callback`;

    const oauth2Client = new google.auth.OAuth2(clientId, clientSecret, redirectUri);
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    // Verify that the user actually granted gmail.send permission
    const grantedScopeStr = String(tokens.scope || "");
    const hasSendScope =
      grantedScopeStr.includes("https://www.googleapis.com/auth/gmail.send") ||
      (tokens.access_token ? await hasGmailSendScope(tokens.access_token) : false);

    if (!hasSendScope) {
      const msg = encodeURIComponent(
        "Gmail send permission was not granted. Please check the permission box to allow sending emails."
      );
      res.redirect(`${FRONTEND_URL}${returnTo}?gmail_error=${msg}`);
      return;
    }

    // Fetch the actual Gmail address that was authorized
    let connectedGmail = accountEmail;
    try {
      const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
      const userInfo = await oauth2.userinfo.get();
      if (userInfo.data?.email) {
        connectedGmail = userInfo.data.email;
      }
    } catch {
      // Fallback to accountEmail if userinfo fails
    }

    await query(
      `
      INSERT INTO uncold.users (email, connected_gmail, google_access_token, google_refresh_token, gmail_scopes_verified, updated_at)
      VALUES ($1, $2, $3, $4, true, NOW())
      ON CONFLICT (email)
      DO UPDATE SET
        connected_gmail = EXCLUDED.connected_gmail,
        google_access_token = COALESCE(EXCLUDED.google_access_token, uncold.users.google_access_token),
        google_refresh_token = COALESCE(EXCLUDED.google_refresh_token, uncold.users.google_refresh_token),
        gmail_scopes_verified = true,
        updated_at = NOW();
      `,
      [accountEmail, connectedGmail, encryptToken(tokens.access_token), encryptToken(tokens.refresh_token)]
    );

    res.redirect(`${FRONTEND_URL}${returnTo}?gmail_connected=1&gmail=${encodeURIComponent(connectedGmail)}`);
  } catch (err: any) {
    console.error("Gmail OAuth callback error:", err);
    const msg = encodeURIComponent(err.message || "Failed to connect Gmail.");
    res.redirect(`${FRONTEND_URL}${returnTo}?gmail_error=${msg}`);
  }
});

// 3. Send email directly from user's Gmail mailbox (authenticated + rate limited)
app.post("/api/gmail/send", requireAuth, sendRateLimiter, async (req: Request, res: Response): Promise<void> => {
  let emailRecordId: string | undefined;
  try {
    const email = (req as any).authUser.email as string;
    const {
      to,
      subject,
      body,
      directAccessToken,
      senderName,
      campaignId,
      companyName,
      recipientName,
      jobTitle,
      jobMetadata,
    } = req.body;

    if (!to || !subject || !body) {
      res.status(400).json({ error: "Missing required fields: to, subject, or body." });
      return;
    }

    // Retrieve & decrypt tokens from DB
    let accessToken = directAccessToken;
    let refreshToken: string | null = null;
    let connectedGmail: string | null = null;

    if (!accessToken) {
      const result = await query(
        `SELECT google_access_token, google_refresh_token, connected_gmail FROM uncold.users WHERE email = $1 LIMIT 1;`,
        [email]
      );
      if (result.rows.length > 0) {
        accessToken = decryptToken(result.rows[0].google_access_token);
        refreshToken = decryptToken(result.rows[0].google_refresh_token);
        connectedGmail = result.rows[0].connected_gmail;
      }
    }

    if (!accessToken && !refreshToken) {
      res.status(401).json({
        error: "Gmail is not connected for this account. Please connect your Gmail first.",
      });
      return;
    }

    const serializedJobMetadata = JSON.stringify(
      jobMetadata && typeof jobMetadata === "object" ? jobMetadata : {}
    );

    // Pre-insert email record in DB to generate tracking ID
    const insertResult = await query(
      `
      INSERT INTO uncold.emails (campaign_id, sender_email, recipient_email, subject, body, channel, company_name, recipient_name, job_title, job_metadata, sent_at)
      VALUES ($1, $2, $3, $4, $5, 'email', $6, $7, $8, $9::jsonb, NOW())
      RETURNING id;
      `,
      [
        campaignId || null,
        email || null,
        to,
        subject,
        body,
        companyName || null,
        recipientName || null,
        jobTitle || null,
        serializedJobMetadata,
      ]
    );

    emailRecordId = insertResult.rows[0]?.id;
    const backendOrigin = getBackendPublicOrigin();
    const trackingPixelUrl = emailRecordId ? `${backendOrigin}/api/track/open/${emailRecordId}` : undefined;

    const sendResult = await sendGmailMessage({
      accessToken: accessToken || "",
      refreshToken,
      to,
      subject,
      body,
      fromEmail: connectedGmail || email,
      senderName,
      trackingPixelUrl,
    });

    // Update with Gmail Message & Thread IDs
    if (emailRecordId) {
      await query(
        `UPDATE uncold.emails SET gmail_message_id = $1, gmail_thread_id = $2 WHERE id = $3;`,
        [sendResult.messageId, sendResult.threadId, emailRecordId]
      );
    }

    res.json({
      success: true,
      emailId: emailRecordId,
      messageId: sendResult.messageId,
      threadId: sendResult.threadId,
    });
  } catch (err: any) {
    console.error("Gmail sending error:", err);

    // Clean up pre-inserted tracking row if Gmail dispatch failed
    if (emailRecordId) {
      await query(
        `DELETE FROM uncold.emails WHERE id = $1 AND gmail_message_id IS NULL;`,
        [emailRecordId]
      ).catch(() => {});
    }

    const errMsg = String(err?.message || "");
    const isInsufficientScope =
      err?.code === 403 ||
      err?.status === 403 ||
      /insufficient|permission|scope/i.test(errMsg);

    if (isInsufficientScope && req.body?.email) {
      await query(
        `UPDATE uncold.users SET gmail_scopes_verified = false WHERE email = $1;`,
        [req.body.email]
      ).catch(() => {});
      res.status(403).json({
        error:
          "Gmail send permission was not granted. Please click 'Connect Gmail' and check the permission boxes.",
      });
      return;
    }

    res.status(500).json({
      error:
        err.message ||
        "Failed to send email via Gmail API. Ensure Gmail API is enabled in Google Cloud Console.",
    });
  }
});

// 3b. Log Copied DM or Wellfound Short Note to History (authenticated)
app.post("/api/outreach/log-copy", requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const email = (req as any).authUser.email as string;
    const {
      channel,
      companyName,
      recipientName,
      recipientEmail,
      jobTitle,
      subject,
      body,
      jobMetadata,
    } = req.body;

    if (!body) {
      res.status(400).json({ error: "Missing required field: body." });
      return;
    }

    const safeChannel = channel === "dm" || channel === "wellfound" ? channel : "email";
    const fallbackSubject =
      subject ||
      (safeChannel === "dm"
        ? `[LinkedIn DM] ${companyName || jobTitle || "Direct Outreach"}`
        : `[Wellfound Note] ${companyName || jobTitle || "Application Note"}`);

    const serializedJobMetadata = JSON.stringify(
      jobMetadata && typeof jobMetadata === "object" ? jobMetadata : {}
    );

    const insertResult = await query(
      `
      INSERT INTO uncold.emails (
        sender_email,
        recipient_email,
        subject,
        body,
        channel,
        company_name,
        recipient_name,
        job_title,
        job_metadata,
        sent_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, NOW())
      RETURNING id, sent_at;
      `,
      [
        email,
        recipientEmail || (safeChannel === "dm" ? "LinkedIn / Twitter DM" : "Wellfound Application"),
        fallbackSubject,
        body,
        safeChannel,
        companyName || null,
        recipientName || null,
        jobTitle || null,
        serializedJobMetadata,
      ]
    );

    res.json({
      success: true,
      record: insertResult.rows[0],
    });
  } catch (err: any) {
    console.error("Failed to log copied outreach:", err);
    res.status(500).json({ error: err.message || "Failed to log outreach." });
  }
});

// 4. Tracking Pixel Endpoint (1x1 Transparent GIF)
// Base64 for 1x1 transparent GIF (43 bytes)
const TRANSPARENT_1X1_GIF = Buffer.from(
  "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
  "base64"
);

app.get("/api/track/open/:emailId", async (req: Request, res: Response): Promise<void> => {
  try {
    const { emailId } = req.params;

    if (emailId) {
      await query(
        `
        UPDATE uncold.emails
        SET opened_at = COALESCE(opened_at, NOW()),
            open_count = COALESCE(open_count, 0) + 1
        WHERE id = $1;
        `,
        [emailId]
      );
    }
  } catch (err) {
    console.warn("Tracking pixel record error:", err);
  } finally {
    // Return standard transparent 1x1 GIF with aggressive no-cache headers
    res.writeHead(200, {
      "Content-Type": "image/gif",
      "Content-Length": TRANSPARENT_1X1_GIF.length,
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
      Pragma: "no-cache",
      Expires: "0",
    });
    res.end(TRANSPARENT_1X1_GIF);
  }
});

// 5. Query sent emails and open tracking statistics (strictly scoped to authenticated user)
app.get("/api/emails/stats", requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const email = (req as any).authUser.email as string;
    const result = await query(
      `
      SELECT id, sender_email, recipient_email, subject, body, channel, company_name, recipient_name, job_title, job_metadata, gmail_message_id, gmail_thread_id, sent_at, opened_at, open_count, reply_detected_at
      FROM uncold.emails
      WHERE sender_email = $1
        AND (channel IS DISTINCT FROM 'email' OR gmail_message_id IS NOT NULL)
      ORDER BY sent_at DESC
      LIMIT 200;
      `,
      [email]
    );

    res.json({
      success: true,
      emails: result.rows,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || "Failed to fetch email statistics." });
  }
});

// 6. Sync incoming replies from Gmail threads (authenticated)
app.post("/api/emails/sync-replies", requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const email = (req as any).authUser.email as string;
    const { directAccessToken } = req.body;

    // Get & decrypt user's Google tokens
    let accessToken = directAccessToken;
    let refreshToken: string | null = null;
    let connectedGmail: string | null = null;

    if (!accessToken) {
      const userRes = await query(
        `SELECT google_access_token, google_refresh_token, connected_gmail FROM uncold.users WHERE email = $1 LIMIT 1;`,
        [email]
      );
      if (userRes.rows.length > 0) {
        accessToken = decryptToken(userRes.rows[0].google_access_token);
        refreshToken = decryptToken(userRes.rows[0].google_refresh_token);
        connectedGmail = userRes.rows[0].connected_gmail;
      }
    }

    if (!accessToken && !refreshToken) {
      res.json({ synced: 0, message: "No active token available for sync." });
      return;
    }

    // Get active emails sent by this user that don't yet have a detected reply
    const pendingEmails = await query(
      `
      SELECT id, gmail_thread_id, recipient_email
      FROM uncold.emails
      WHERE sender_email = $1 AND gmail_thread_id IS NOT NULL AND reply_detected_at IS NULL
      LIMIT 20;
      `,
      [email]
    );

    let repliesFound = 0;

    for (const row of pendingEmails.rows) {
      if (!row.gmail_thread_id) continue;

      const replyCheck = await checkThreadReplies({
        accessToken,
        refreshToken,
        threadId: row.gmail_thread_id,
        userEmail: email,
      });

      if (replyCheck.hasReply) {
        await query(
          `
          UPDATE uncold.emails
          SET reply_detected_at = $1
          WHERE id = $2;
          `,
          [replyCheck.replyDate || new Date(), row.id]
        );
        repliesFound++;
      }
    }

    res.json({ success: true, synced: pendingEmails.rows.length, repliesFound });
  } catch (err: any) {
    console.warn("Reply sync notice:", err.message);
    res.json({ success: false, error: err.message });
  }
});

// 7. Parse Resume In-Memory (No disk/S3 storage) and return structured candidate profile
app.post(
  "/api/profile/parse-resume",
  requireAuth,
  aiRateLimiter,
  upload.single("resume"),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        res.status(500).json({ error: "GEMINI_API_KEY is not configured." });
        return;
      }

      const file = req.file;
      let rawText = req.body.rawText as string | undefined;

      if (file && file.buffer) {
        try {
          rawText = await extractTextFromPdf(file.buffer);
        } catch (pdfErr: any) {
          res.status(400).json({
            error: "Failed to extract text from PDF. Ensure file is not password-protected or corrupt.",
          });
          return;
        }
      }

      if (!rawText || rawText.trim().length < 30) {
        res.status(400).json({
          error: "Could not read sufficient text from the resume. Please ensure it is a valid PDF.",
        });
        return;
      }

      // 1. Sanitize text and strip repetitive whitespace/blank lines
      const sanitizedText = rawText
        .replace(/\r\n/g, "\n")
        .replace(/[ \t]+/g, " ")
        .replace(/\n{3,}/g, "\n\n")
        .trim()
        .slice(0, 4500);

      // 2. Fast deterministic regex extraction (<0.1ms)
      const candidateEmail = sanitizedText.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/)?.[0] || "";
      const candidatePhone = sanitizedText.match(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/)?.[0] || "";
      const candidateGithub = sanitizedText.match(/https?:\/\/(?:www\.)?github\.com\/[A-Za-z0-9_-]+/i)?.[0] || "";
      const candidateLinkedin = sanitizedText.match(/https?:\/\/(?:www\.)?linkedin\.com\/in\/[A-Za-z0-9_-]+/i)?.[0] || "";

      const ai = new GoogleGenAI({ apiKey });

      const prompt = `Extract clean structured profile data from this resume text.

Pre-detected:
- Email: ${candidateEmail || "scan text"}
- Phone: ${candidatePhone || "scan text"}
- GitHub: ${candidateGithub || "scan text"}
- LinkedIn: ${candidateLinkedin || "scan text"}

Instructions:
- Keep skills deduplicated.
- For dates, use MM/YYYY (e.g. "06/2023") or Present.
- Keep responsibilities concise (concise bullet points or 2-3 sentences).
- Extract university, degree, and graduation year.

Return ONLY a valid JSON object with EXACTLY this structure (no markdown, no code fences):
{
  "full_name": "string",
  "email": "${candidateEmail}",
  "phone": "${candidatePhone}",
  "headline": "string (e.g. Associate Frontend Engineer | React & Next.js)",
  "location": "string or null",
  "introduction": "string (concise 2-3 sentence executive intro)",
  "skills": ["string"],
  "projects_and_past_experience": [
    {
      "company_name": "string",
      "designation": "string",
      "role_type": "Full-time",
      "from": "MM/YYYY",
      "to": "MM/YYYY or Present",
      "is_currently_working": true,
      "responsibilities_projects": "string"
    }
  ],
  "education_details": [
    {
      "university_text": "string",
      "degree_or_major_title": "string",
      "education_level_text": "Bachelor's Degree",
      "graduation_month_year": "MM/YYYY or null"
    }
  ],
  "portfolio_links": {
    "github": "${candidateGithub}",
    "linkedin": "${candidateLinkedin}",
    "portfolio": "url or null"
  }
}

Resume Text:
${sanitizedText}`;

      // Call ultra-fast Gemini with zero thinking tokens and instant failover
      const responseText = await callFastGemini(ai, prompt, {
        temperature: 0.1,
        maxOutputTokens: 950,
      });
      let parsedData: any = {};
      try {
        parsedData = JSON.parse(responseText);
      } catch {
        const cleaned = responseText.replace(/```json/gi, "").replace(/```/g, "").trim();
        parsedData = JSON.parse(cleaned);
      }

      // Backfill pre-detected fields if missing from AI output
      if (!parsedData.email && candidateEmail) parsedData.email = candidateEmail;
      if (!parsedData.phone && candidatePhone) parsedData.phone = candidatePhone;
      if (!parsedData.portfolio_links) parsedData.portfolio_links = {};
      if (!parsedData.portfolio_links.github && candidateGithub) parsedData.portfolio_links.github = candidateGithub;
      if (!parsedData.portfolio_links.linkedin && candidateLinkedin) parsedData.portfolio_links.linkedin = candidateLinkedin;

      res.json({
        success: true,
        data: parsedData,
      });
    } catch (err: any) {
      console.error("Resume parsing error:", err);
      res.status(500).json({ error: err.message || "Failed to parse resume via AI." });
    }
  }
);

// 8. Fetch user's saved profile (authenticated)
app.get("/api/profile", requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const email = (req as any).authUser.email as string;

    const result = await query(
      `
      SELECT id, user_id, email, full_name, phone, location, headline, introduction, skills,
             projects_and_past_experience, education_details, certification_details,
             portfolio_links, resume_url, updated_at
      FROM uncold.profiles
      WHERE email = $1
      ORDER BY updated_at DESC
      LIMIT 1;
      `,
      [email]
    );

    res.json({
      success: true,
      profile: result.rows[0] || null,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || "Failed to fetch profile." });
  }
});

// 9. Save or update user's profile (authenticated + strict URL protocol validation)
app.post("/api/profile", requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const email = (req as any).authUser.email as string;
    const {
      full_name,
      phone,
      location,
      headline,
      introduction,
      skills,
      projects_and_past_experience,
      education_details,
      certification_details,
      portfolio_links,
      raw_parsed_data,
    } = req.body;

    // Validate URL schemes on portfolio_links to block javascript:/data: URIs
    const sanitizeUrl = (val: any): string => {
      if (!val || typeof val !== "string") return "";
      const trimmed = val.trim();
      if (!trimmed) return "";
      const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
      try {
        const parsed = new URL(candidate);
        if (parsed.protocol === "http:" || parsed.protocol === "https:") {
          return candidate;
        }
      } catch {
        // Ignore invalid URL
      }
      return "";
    };

    const safeLinks = {
      github: sanitizeUrl(portfolio_links?.github),
      linkedin: sanitizeUrl(portfolio_links?.linkedin),
      portfolio: sanitizeUrl(portfolio_links?.portfolio),
      resume_url: sanitizeUrl(portfolio_links?.resume_url || req.body.resume_url),
    };

    // Get user id if exists in uncold.users
    const userRes = await query(`SELECT id FROM uncold.users WHERE email = $1 LIMIT 1;`, [email]);
    const userId = userRes.rows[0]?.id || null;

    // Check if profile exists for this email
    const existing = await query(`SELECT id FROM uncold.profiles WHERE email = $1 LIMIT 1;`, [email]);

    const resumeUrl = safeLinks.resume_url || null;

    let savedProfile;
    if (existing.rows.length > 0) {
      const updateRes = await query(
        `
        UPDATE uncold.profiles
        SET full_name = $1,
            phone = $2,
            location = $3,
            headline = $4,
            introduction = $5,
            skills = $6,
            projects_and_past_experience = $7,
            education_details = $8,
            certification_details = $9,
            portfolio_links = $10,
            raw_parsed_data = COALESCE($11, raw_parsed_data),
            user_id = COALESCE($12, user_id),
            resume_url = COALESCE($13, resume_url),
            updated_at = NOW()
        WHERE email = $14
        RETURNING *;
        `,
        [
          full_name || null,
          phone || null,
          location || null,
          headline || null,
          introduction || null,
          JSON.stringify(skills || []),
          JSON.stringify(projects_and_past_experience || []),
          JSON.stringify(education_details || []),
          JSON.stringify(certification_details || []),
          JSON.stringify(safeLinks),
          raw_parsed_data ? JSON.stringify(raw_parsed_data) : null,
          userId,
          resumeUrl,
          email,
        ]
      );
      savedProfile = updateRes.rows[0];
    } else {
      const insertRes = await query(
        `
        INSERT INTO uncold.profiles (
          user_id, email, full_name, phone, location, headline, introduction, skills,
          projects_and_past_experience, education_details, certification_details,
          portfolio_links, resume_url, raw_parsed_data, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
        RETURNING *;
        `,
        [
          userId,
          email,
          full_name || null,
          phone || null,
          location || null,
          headline || null,
          introduction || null,
          JSON.stringify(skills || []),
          JSON.stringify(projects_and_past_experience || []),
          JSON.stringify(education_details || []),
          JSON.stringify(certification_details || []),
          JSON.stringify(safeLinks),
          resumeUrl,
          raw_parsed_data ? JSON.stringify(raw_parsed_data) : null,
        ]
      );
      savedProfile = insertRes.rows[0];
    }

    res.json({
      success: true,
      message: "Profile saved successfully.",
      profile: savedProfile,
    });
  } catch (err: any) {
    console.error("Profile save error:", err);
    res.status(500).json({ error: err.message || "Failed to save profile." });
  }
});

if (!process.env.VERCEL) {
  app.listen(PORT, async () => {
    console.log(`🚀 Uncold Backend running at http://localhost:${PORT}`);
    console.log(`📡 CORS allowed for: ${FRONTEND_URL}`);
    await ensureDbInitialized();
  });
}

export default app;
