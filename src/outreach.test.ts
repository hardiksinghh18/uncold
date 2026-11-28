import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  encryptToken,
  decryptToken,
  signOAuthState,
  verifyOAuthState,
  isSafePublicUrl,
  sanitizeHeaderValue,
} from "./security";
import {
  extractFastCompanyName,
  extractRichJdMetadata,
  formatBestExperienceForJd,
} from "./jdMetadata";

// Mirror core backend pure functions to test all edge cases & security invariants

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
      return "";
    }
  );

  cleaned = cleaned.replace(/\[(?:Link|URL|Portfolio|GitHub|Resume)\]/gi, "");
  cleaned = cleaned.replace(/(?:Portfolio\s*&\s*Resume|Portfolio|GitHub|LinkedIn|Resume|Links?)\s*:\s*(?:\r?\n|$)/gi, "");
  cleaned = cleaned.replace(/^[ \t]*[\*\-][ \t]+/gm, "• ").replace(/\*\*(.*?)\*\*/g, "$1");
  cleaned = cleaned.replace(/[ \t]{2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim();

  return cleaned;
}

function resolveGreetingHint(
  jd: string,
  recipientEmail: string,
  companyName: string
): { greeting: string; recipientName: string } {
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

function formatHtmlBody(rawText: string): string {
  const escaped = rawText
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

  const lines = escaped.split(/\r?\n/);
  const out: string[] = [];
  let inList = false;

  for (const line of lines) {
    const bulletMatch = line.match(/^[ \t]*(?:•|\*|-)[ \t]+(.*)$/);
    if (bulletMatch) {
      if (!inList) {
        out.push('<ul style="margin: 8px 0 12px 0; padding-left: 20px;">');
        inList = true;
      }
      out.push(`<li style="margin-bottom: 6px;">${bulletMatch[1]}</li>`);
    } else {
      if (inList) {
        out.push("</ul>");
        inList = false;
      }
      if (line.trim() === "") {
        out.push("<br/>");
      } else {
        out.push(`${line}<br/>`);
      }
    }
  }
  if (inList) out.push("</ul>");
  return out.join("\n").replace(/(<\/ul>)\s*<br\/>/g, "$1");
}

describe("Candidate Links Resolution & Placeholder Sanitization", () => {
  test("Filters out N/A, null, none, and empty strings", () => {
    const res = resolveCandidateLinks({
      portfolio_links: { github: "N/A", linkedin: "  ", portfolio: "null", resume_url: "none" },
    });
    assert.equal(res.availableLinksList.length, 0);
    assert.match(res.linksPromptSummary, /None provided/);
  });

  test("Preserves valid resume and portfolio URLs", () => {
    const res = resolveCandidateLinks({
      portfolio_links: { resume_url: "https://drive.google.com/file/d/abc/view", github: "https://github.com/u" },
    });
    assert.equal(res.links.resume, "https://drive.google.com/file/d/abc/view");
    assert.equal(res.links.github, "https://github.com/u");
    assert.equal(res.availableLinksList.length, 2);
  });

  test("Strips bracketed placeholders and orphaned labels when no links exist", () => {
    const raw = "Hey!\n\nPortfolio & Resume: [Link]\nGitHub: [GitHub Link]\n\nBest,\nHardik";
    const cleaned = cleanBracketedPlaceholders(raw, {});
    assert.equal(cleaned.includes("["), false);
    assert.equal(cleaned.includes("Portfolio & Resume:"), false);
    assert.equal(cleaned.includes("GitHub:"), false);
  });

  test("Replaces bracketed placeholders with real URL when available", () => {
    const raw = "Check my work at [Portfolio Link] and resume [Resume Link]";
    const cleaned = cleanBracketedPlaceholders(raw, {
      portfolio: "https://hardiksingh.codes",
      resume: "https://drive.google.com/resume",
    });
    assert.equal(cleaned, "Check my work at https://hardiksingh.codes and resume https://drive.google.com/resume");
  });

  test("Normalizes markdown * bullets to Unicode • and strips **bold**", () => {
    const raw = "* **Built** pgvector search\n- Migrated 400+ APIs";
    const cleaned = cleanBracketedPlaceholders(raw, {});
    assert.equal(cleaned, "• Built pgvector search\n• Migrated 400+ APIs");
  });
});

describe("Greeting Hint Extraction", () => {
  test("Extracts first name from non-generic email prefix", () => {
    const res = resolveGreetingHint("Hiring Frontend Engineer", "alex.rivera@linear.app", "Linear");
    assert.equal(res.greeting, "Hi Alex,");
    assert.equal(res.recipientName, "Alex");
  });

  test("Ignores generic email prefixes like careers@ and falls back to company team", () => {
    const res = resolveGreetingHint("Hiring Frontend Engineer", "careers@linear.app", "Linear");
    assert.equal(res.greeting, "Hi Linear team,");
    assert.equal(res.recipientName, "");
  });

  test("Falls back to Hi there, when neither name nor company is available", () => {
    const res = resolveGreetingHint("Hiring Frontend Engineer", "", "");
    assert.equal(res.greeting, "Hi there,");
  });
});

describe("Email HTML Formatting & XSS Escaping", () => {
  test("Escapes raw HTML tags in email body to prevent HTML injection", () => {
    const html = formatHtmlBody("Hello <script>alert(1)</script>");
    assert.equal(html.includes("<script>"), false);
    assert.equal(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"), true);
  });

  test("Converts bullet lines into clean HTML <ul><li> lists", () => {
    const html = formatHtmlBody("Intro line\n\n• Point one\n* Point two\n\nThanks");
    assert.equal(html.includes("<ul"), true);
    assert.equal(html.includes("<li style=\"margin-bottom: 6px;\">Point one</li>"), true);
    assert.equal(html.includes("<li style=\"margin-bottom: 6px;\">Point two</li>"), true);
    assert.equal(html.includes("</ul>"), true);
  });
});

describe("Security Hardening Tests (Encryption, Signed State, SSRF, Header Injection)", () => {
  test("Encrypts and decrypts OAuth tokens with AES-256-GCM", () => {
    const raw = "ya29.a0AfH6SMBxSecretToken";
    const enc = encryptToken(raw);
    assert.ok(enc && enc.startsWith("enc:v1:"));
    assert.notEqual(enc, raw);
    assert.equal(decryptToken(enc), raw);
  });

  test("Transparently reads legacy plaintext tokens", () => {
    assert.equal(decryptToken("legacy-plain-token"), "legacy-plain-token");
  });

  test("Signs and verifies OAuth state, and rejects tampered state", () => {
    const state = signOAuthState({ email: "user@gmail.com", returnTo: "/dashboard" });
    const verified = verifyOAuthState(state);
    assert.deepEqual(verified, { email: "user@gmail.com", returnTo: "/dashboard" });

    const tampered = state.slice(0, -3) + "xxx";
    assert.equal(verifyOAuthState(tampered), null);
  });

  test("Blocks SSRF URLs targeting localhost, private IPs, and cloud metadata", async () => {
    assert.equal(await isSafePublicUrl("http://localhost:5000/secret"), false);
    assert.equal(await isSafePublicUrl("http://127.0.0.1:8080/admin"), false);
    assert.equal(await isSafePublicUrl("http://169.254.169.254/latest/meta-data/"), false);
    assert.equal(await isSafePublicUrl("http://10.0.0.1/internal"), false);
    assert.equal(await isSafePublicUrl("file:///etc/passwd"), false);
  });

  test("Sanitizes CR/LF characters to prevent email header injection", () => {
    const dirty = "Attacker\r\nBcc: victim@evil.com";
    const clean = sanitizeHeaderValue(dirty);
    assert.equal(clean.includes("\r"), false);
    assert.equal(clean.includes("\n"), false);
  });
});

describe("Rich JD Metadata Extraction", () => {
  test("Extracts location, compensation, remote status, experience, skills, and apply URL", () => {
    const jd = `
      Senior Full-Stack Engineer at Acme Corp
      Location: Gurugram, India (Hybrid)
      Compensation: 24 - 32 LPA
      Experience: 2-4 years of experience
      Employment: Full-time
      Required Skills: TypeScript, React, Next.js, Node.js, PostgreSQL, pgvector, Docker
      Apply here: https://acme.dev/careers/fullstack
    `;
    const meta = extractRichJdMetadata(jd, "Acme Corp", "Senior Full-Stack Engineer", [
      "TypeScript",
      "React",
      "PostgreSQL",
      "Go",
    ]);

    assert.equal(meta.companyName, "Acme Corp");
    assert.equal(meta.jobTitle, "Senior Full-Stack Engineer");
    assert.equal(meta.location, "Gurugram, India (Hybrid)");
    assert.equal(meta.workMode, "Hybrid");
    assert.equal(meta.isRemoteAllowed, true);
    assert.equal(meta.compensation, "24 - 32 LPA");
    assert.equal(meta.experienceRequired, "2-4 years of experience");
    assert.equal(meta.employmentType, "Full-time");
    assert.ok(meta.requiredSkills.includes("TypeScript"));
    assert.ok(meta.requiredSkills.includes("pgvector"));
    assert.deepEqual(meta.matchedSkills, ["TypeScript", "React", "PostgreSQL"]);
    assert.equal(meta.applicationUrl, "https://acme.dev/careers/fullstack");
  });

  test("Detects on-site only / no remote restriction accurately", () => {
    const jd = `
      Backend Engineer in Bengaluru, India
      This is an on-site only role (no remote).
      Salary: $120k - $150k/yr
      Must know Python, FastAPI, Redis, and Kubernetes.
    `;
    const meta = extractRichJdMetadata(jd, "StartupX", "Backend Engineer", ["Python"]);

    assert.equal(meta.location, "Bengaluru, India");
    assert.equal(meta.workMode, "On-site (No Remote)");
    assert.equal(meta.isRemoteAllowed, false);
    assert.equal(meta.compensation, "$120k - $150k/yr");
    assert.ok(meta.requiredSkills.includes("Python"));
    assert.ok(meta.requiredSkills.includes("FastAPI"));
    assert.deepEqual(meta.matchedSkills, ["Python"]);
  });

  test("Does not misclassify tech stack words like 'with PostgreSQL' as company name", () => {
    const jd = `
      We are building always-on AI coworkers.
      About Metaworkers
      Experience with PostgreSQL, Redis, LangGraph, and RBAC required.
      Hiring a Full Stack Engineer at Metaworkers.
    `;
    assert.equal(extractFastCompanyName(jd), "Metaworkers");

    const techOnlyJd = `Experience with PostgreSQL, Redis, and Docker.`;
    assert.equal(extractFastCompanyName(techOnlyJd), "");
  });

  test("Ranks and surfaces the best JD-matching experience bullet points across all roles", () => {
    const experiences = [
      {
        company_name: "RoleOne",
        designation: "Frontend Engineer",
        from: "01/2024",
        to: "Present",
        responsibilities_projects:
          "• Built marketing landing pages in HTML and CSS.\n• Migrated 400+ APIs to RTK Query, slashing LCP by 34%.\n• Led sprint planning meetings.",
      },
      {
        company_name: "RoleTwo",
        designation: "Full Stack Intern",
        from: "06/2023",
        to: "12/2023",
        responsibilities_projects:
          "• Implemented AI-powered visual matching using pgvector and PostgreSQL, reducing manual work by 65%.",
      },
    ];

    const jd = "Hiring an AI Full Stack Engineer with PostgreSQL, pgvector, and vector search experience.";
    const ranked = formatBestExperienceForJd(experiences, jd, 2);

    assert.ok(ranked.includes("pgvector and PostgreSQL"));
    assert.ok(!ranked.includes("sprint planning"));
  });
});
