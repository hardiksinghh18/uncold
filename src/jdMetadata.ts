export interface RichJdMetadata {
  companyName: string;
  jobTitle: string;
  location: string;
  workMode: string;
  isRemoteAllowed: boolean | null;
  compensation: string;
  experienceRequired: string;
  employmentType: string;
  requiredSkills: string[];
  matchedSkills: string[];
  applicationUrl: string;
}

const KNOWN_SKILLS: Array<{ label: string; pattern: RegExp }> = [
  { label: "TypeScript", pattern: /\btypescript\b|\bts\b/i },
  { label: "JavaScript", pattern: /\bjavascript\b|\bjs\b/i },
  { label: "React", pattern: /\breact(?:\.js|js)?\b/i },
  { label: "Next.js", pattern: /\bnext(?:\.js|js)\b/i },
  { label: "Node.js", pattern: /\bnode(?:\.js|js)\b/i },
  { label: "Python", pattern: /\bpython\b/i },
  { label: "Go", pattern: /\bgolang\b|\bgo\b/i },
  { label: "Rust", pattern: /\brust\b/i },
  { label: "Java", pattern: /\bjava\b(?!script)/i },
  { label: "C++", pattern: /(?:^|[\s,;/|(])c\+\+(?=$|[\s,;/|)])/i },
  { label: "C#", pattern: /(?:^|[\s,;/|(])c#(?=$|[\s,;/|)])/i },
  { label: ".NET", pattern: /(?:^|[\s,;/|(])\.net(?:\s+core)?\b/i },
  { label: "Kotlin", pattern: /\bkotlin\b/i },
  { label: "Swift", pattern: /\bswift\b/i },
  { label: "PostgreSQL", pattern: /\bpostgres(?:ql)?\b/i },
  { label: "pgvector", pattern: /\bpgvector\b/i },
  { label: "SQL", pattern: /\bsql\b/i },
  { label: "MongoDB", pattern: /\bmongodb\b|\bmongo\b/i },
  { label: "Redis", pattern: /\bredis\b/i },
  { label: "Kafka", pattern: /\bkafka\b/i },
  { label: "GraphQL", pattern: /\bgraphql\b/i },
  { label: "gRPC", pattern: /\bgrpc\b/i },
  { label: "REST APIs", pattern: /\brest(?:ful)?\s*(?:apis?)?\b/i },
  { label: "Docker", pattern: /\bdocker\b/i },
  { label: "Kubernetes", pattern: /\bkubernetes\b|\bk8s\b/i },
  { label: "AWS", pattern: /\baws\b|\bamazon web services\b/i },
  { label: "GCP", pattern: /\bgcp\b|\bgoogle cloud\b/i },
  { label: "Azure", pattern: /\bazure\b/i },
  { label: "Terraform", pattern: /\bterraform\b/i },
  { label: "Tailwind CSS", pattern: /\btailwind(?:\s*css)?\b/i },
  { label: "Redux / RTK Query", pattern: /\bredux\b|\brtk\s*query\b/i },
  { label: "Prisma", pattern: /\bprisma\b/i },
  { label: "Express", pattern: /\bexpress(?:\.js|js)?\b/i },
  { label: "FastAPI", pattern: /\bfastapi\b/i },
  { label: "Django", pattern: /\bdjango\b/i },
  { label: "Spring Boot", pattern: /\bspring\s*boot\b/i },
  { label: "Ruby on Rails", pattern: /\bruby on rails\b|\brails\b/i },
  { label: "Vue.js", pattern: /\bvue(?:\.js|js)?\b/i },
  { label: "Angular", pattern: /\bangular\b/i },
  { label: "Svelte", pattern: /\bsvelte\b/i },
  { label: "WebSockets", pattern: /\bwebsockets?\b/i },
  { label: "Microservices", pattern: /\bmicroservices?\b/i },
  { label: "System Design", pattern: /\bsystem design\b/i },
  { label: "CI/CD", pattern: /\bci\s*\/\s*cd\b/i },
  { label: "Linux", pattern: /\blinux\b/i },
  { label: "Git", pattern: /\bgit\b/i },
  { label: "LLMs / GenAI", pattern: /\bllms?\b|\bgenai\b|\bgenerative ai\b|\brag\b/i },
  { label: "PyTorch", pattern: /\bpytorch\b/i },
  { label: "TensorFlow", pattern: /\btensorflow\b/i },
  { label: "React Native", pattern: /\breact native\b/i },
  { label: "Flutter", pattern: /\bflutter\b/i },
  { label: "Elasticsearch", pattern: /\belasticsearch\b/i },
  { label: "RabbitMQ", pattern: /\brabbitmq\b/i },
  { label: "Supabase", pattern: /\bsupabase\b/i },
  { label: "Firebase", pattern: /\bfirebase\b/i },
  { label: "Vercel", pattern: /\bvercel\b/i },
  { label: "Figma", pattern: /\bfigma\b/i },
];

function cleanLineValue(val: string): string {
  return val.replace(/^[\s:–—-]+/, "").replace(/\s+/g, " ").trim();
}

const NON_COMPANY_WORDS = new Set([
  "postgresql", "postgres", "mysql", "mongodb", "redis", "sqlite", "prisma", "drizzle",
  "react", "reactjs", "nextjs", "next", "node", "nodejs", "typescript", "javascript",
  "python", "golang", "go", "rust", "java", "kotlin", "swift", "docker", "kubernetes",
  "aws", "gcp", "azure", "terraform", "graphql", "grpc", "rest", "kafka", "rabbitmq",
  "langgraph", "langchain", "pytorch", "tensorflow", "fastapi", "django", "flask",
  "express", "tailwind", "redux", "vercel", "supabase", "firebase", "figma", "git",
  "linux", "ci", "cd", "ai", "ml", "llm", "llms", "rag", "rbac", "api", "apis", "sdk",
  "english", "hindi", "india", "remote", "hybrid", "onsite", "full-time", "part-time",
  "our", "the", "a", "an", "your", "us", "you", "strong", "deep", "solid", "hands-on",
]);

function isLikelyCompanyName(candidate: string): boolean {
  const cleaned = candidate.trim();
  if (!cleaned || cleaned.length < 2 || cleaned.length > 50) return false;
  const words = cleaned.split(/\s+/);
  if (words.every((w) => NON_COMPANY_WORDS.has(w.toLowerCase().replace(/[.,!?]+$/, "")))) {
    return false;
  }
  return true;
}

/**
 * Extracts a clean company name from a Job Description without matching tech stack words
 * (e.g. avoids "experience with PostgreSQL" matching "PostgreSQL").
 */
export function extractFastCompanyName(jd: string, recipientEmail = ""): string {
  const text = jd || "";

  // 1. Explicit label: Company: Acme / Organization: Acme / Startup: Acme
  const explicitMatch = text.match(
    /(?:^|\n)\s*(?:company(?:\s+name)?|organization|startup|employer)\s*[:–—-]\s*([^\r\n,|•]{2,55})/i
  );
  if (explicitMatch?.[1] && isLikelyCompanyName(explicitMatch[1])) {
    return cleanLineValue(explicitMatch[1]);
  }

  // 2. "About <Company>" / "<Company> is hiring" / "Join <Company>"
  const aboutMatch = text.match(
    /(?:^|\n)\s*(?:about|join)\s+([A-Z][A-Za-z0-9.&-]*(?:\s+[A-Z][A-Za-z0-9.&-]*){0,2})(?=\s*[:\r\n,]|$)/m
  );
  if (aboutMatch?.[1]) {
    const val = aboutMatch[1].replace(/[.,;:!?]+$/, "").trim();
    if (isLikelyCompanyName(val)) return val;
  }

  const hiringMatch = text.match(
    /\b([A-Z][A-Za-z0-9.&-]*(?:\s+[A-Z][A-Za-z0-9.&-]*){0,2})\s+(?:is\s+hiring|is\s+looking\s+for|is\s+building)\b/
  );
  if (hiringMatch?.[1]) {
    const val = hiringMatch[1].replace(/[.,;:!?]+$/, "").trim();
    if (isLikelyCompanyName(val)) return val;
  }

  // 3. "... at <Company>" (avoid "with <TechSkill>" false positives)
  const atMatches = Array.from(
    text.matchAll(/\bat\s+([A-Z][A-Za-z0-9.&-]*(?:\s+[A-Z][A-Za-z0-9.&-]*){0,2})(?=[.,\s\r\n]|$)/g)
  );
  for (const m of atMatches) {
    if (m[1]) {
      const val = m[1].replace(/[.,;:!?]+$/, "").trim();
      if (isLikelyCompanyName(val)) return val;
    }
  }

  // 4. Non-generic email domain fallback
  if (
    recipientEmail &&
    !/@(gmail|yahoo|outlook|hotmail|icloud|protonmail|live|me)\./i.test(recipientEmail)
  ) {
    const domainPart = recipientEmail.split("@")[1]?.split(".")[0] || "";
    if (domainPart && isLikelyCompanyName(domainPart)) {
      return domainPart.charAt(0).toUpperCase() + domainPart.slice(1);
    }
  }

  return "";
}

/**
 * Deterministically extracts structured job intelligence from a raw Job Description
 * in <1ms without adding any AI latency.
 */
export function extractRichJdMetadata(
  jd: string,
  companyName: string,
  jobTitle: string,
  candidateSkills: string[] = []
): RichJdMetadata {
  const text = jd || "";

  // 1. Work Mode & Remote Allowed
  let workMode = "";
  let isRemoteAllowed: boolean | null = null;

  const noRemoteRegex = /\b(?:no\s+remote|not\s+remote|on-?site\s+only|in-?office\s+only|must\s+work\s+from\s+office)\b/i;
  const hybridRegex = /\bhybrid\b/i;
  const remoteRegex = /\b(?:remote(?:\s+(?:allowed|friendly|first|only|work|position|role|job))?|work\s+from\s+home|wfh|fully\s+distributed|work\s+from\s+anywhere)\b/i;
  const onsiteRegex = /\b(?:on-?site|in-?office|in-?person)\b/i;

  if (noRemoteRegex.test(text)) {
    workMode = "On-site (No Remote)";
    isRemoteAllowed = false;
  } else if (hybridRegex.test(text)) {
    workMode = "Hybrid";
    isRemoteAllowed = true;
  } else if (remoteRegex.test(text)) {
    workMode = onsiteRegex.test(text) ? "Remote / On-site Flexible" : "Remote";
    isRemoteAllowed = true;
  } else if (onsiteRegex.test(text)) {
    workMode = "On-site";
    isRemoteAllowed = false;
  }

  // 2. Location
  let location = "";
  const explicitLocMatch = text.match(
    /(?:^|\n)\s*(?:job\s+location|work\s+location|office\s+location|location|based\s+in|headquarters)\s*[:–—-]\s*([^\n|•]{2,70})/i
  );
  if (explicitLocMatch && explicitLocMatch[1]) {
    location = cleanLineValue(explicitLocMatch[1]);
  } else {
    const inlineCityMatch = text.match(
      /\b(?:Gurugram|Gurgaon|Bengaluru|Bangalore|Delhi\s*NCR|New\s*Delhi|Noida|Mumbai|Hyderabad|Pune|Chennai|Kolkata|San\s*Francisco(?:,\s*CA)?|New\s*York(?:,\s*NY)?|Seattle(?:,\s*WA)?|Austin(?:,\s*TX)?|Boston(?:,\s*MA)?|London(?:,\s*UK)?|Berlin|Toronto|Singapore|Dubai)\b(?:\s*,\s*(?:India|USA|US|UK|Canada|Germany))?/i
    );
    if (inlineCityMatch && inlineCityMatch[0]) {
      location = inlineCityMatch[0].trim();
    } else if (workMode === "Remote") {
      location = "Remote";
    }
  }

  // 3. Compensation / Package / Salary / Stipend
  let compensation = "";
  const explicitCompMatch = text.match(
    /(?:^|\n)\s*(?:salary|compensation|package|ctc|pay(?:\s+range)?|stipend|ote)\s*[:–—-]\s*([^\n]{2,80})/i
  );
  if (explicitCompMatch && explicitCompMatch[1]) {
    compensation = cleanLineValue(explicitCompMatch[1]);
  } else {
    const currencyMatch = text.match(
      /(?:[$€£₹]\s*\d{1,3}(?:,\d{3})*(?:\.\d+)?\s*[kKlLmM]?\s*(?:[-–to]+\s*[$€£₹]?\s*\d{1,3}(?:,\d{3})*(?:\.\d+)?\s*[kKlLmM]?)?(?:\s*(?:\/\s*(?:yr|year|annum|mo|month|hr|hour)|per\s+(?:year|annum|month)|LPA|CTC))?|\b\d{1,3}(?:\.\d+)?\s*(?:[-–to]+\s*\d{1,3}(?:\.\d+)?)?\s*(?:LPA|lakhs?\s*(?:per\s*annum)?|CTC)\b)/i
    );
    if (currencyMatch && currencyMatch[0]) {
      compensation = currencyMatch[0].trim();
    }
  }

  // 4. Experience Required
  let experienceRequired = "";
  const explicitExpMatch = text.match(
    /(?:^|\n)\s*(?:experience(?:\s+required)?|years\s+of\s+experience|yoe)\s*[:–—-]\s*([^\n]{2,60})/i
  );
  if (explicitExpMatch && explicitExpMatch[1]) {
    experienceRequired = cleanLineValue(explicitExpMatch[1]);
  } else {
    const expRangeMatch = text.match(
      /\b(\d{1,2}\s*(?:\+|[-–to]+\s*\d{1,2}\s*\+?)\s*years?(?:\s+of)?(?:\s+\w+){0,2}\s*experience|\d{1,2}\+\s*years?)\b/i
    );
    if (expRangeMatch && expRangeMatch[1]) {
      experienceRequired = expRangeMatch[1].trim();
    } else if (/\bfreshers?\b|\bentry[\s-]level\b|\bnew\s+grad\b/i.test(text)) {
      experienceRequired = "Entry-level / Fresher";
    }
  }

  // 5. Employment Type
  let employmentType = "";
  if (/\bfull[\s-]time\b/i.test(text)) {
    employmentType = "Full-time";
  } else if (/\bintern(?:ship)?\b/i.test(text)) {
    employmentType = "Internship";
  } else if (/\bcontract(?:or)?\b/i.test(text)) {
    employmentType = "Contract";
  } else if (/\bpart[\s-]time\b/i.test(text)) {
    employmentType = "Part-time";
  } else if (/\bfreelance\b/i.test(text)) {
    employmentType = "Freelance";
  }

  // 6. Required Skills (curated dictionary + matched candidate skills)
  const requiredSkills: string[] = [];
  for (const skill of KNOWN_SKILLS) {
    if (skill.pattern.test(text)) {
      requiredSkills.push(skill.label);
    }
  }

  // 7. Matched Skills against candidate profile
  const matchedSet = new Set<string>();
  const matchedSkills: string[] = [];
  const lowerRequired = requiredSkills.map((s) => s.toLowerCase());
  const lowerText = text.toLowerCase();

  for (const rawCandidateSkill of candidateSkills) {
    const trimmed = (rawCandidateSkill || "").trim();
    if (!trimmed) continue;
    const lowerCandidate = trimmed.toLowerCase();
    const inRequired = lowerRequired.some(
      (req) => req === lowerCandidate || req.includes(lowerCandidate) || lowerCandidate.includes(req)
    );
    const inRawJd =
      trimmed.length >= 2 &&
      (lowerText.includes(` ${lowerCandidate} `) ||
        lowerText.includes(`${lowerCandidate},`) ||
        lowerText.includes(`${lowerCandidate}.`) ||
        lowerText.includes(`/${lowerCandidate}`) ||
        lowerText.includes(`${lowerCandidate}/`));

    if ((inRequired || inRawJd) && !matchedSet.has(lowerCandidate)) {
      matchedSet.add(lowerCandidate);
      matchedSkills.push(trimmed);
    }
  }

  // 8. Application / Job Link URL
  let applicationUrl = "";
  const urlMatch = text.match(/https?:\/\/[^\s"'<>)\]]+/i);
  if (urlMatch && urlMatch[0]) {
    applicationUrl = urlMatch[0].replace(/[.,;!?]+$/, "");
  }

  return {
    companyName: companyName || "",
    jobTitle: jobTitle || "",
    location,
    workMode,
    isRemoteAllowed,
    compensation,
    experienceRequired,
    employmentType,
    requiredSkills: requiredSkills.slice(0, 18),
    matchedSkills: matchedSkills.slice(0, 12),
    applicationUrl,
  };
}

export interface ExperienceItem {
  company_name?: string;
  designation?: string;
  from?: string;
  to?: string;
  responsibilities_projects?: string | string[];
}

/**
 * Splits an experience's responsibilities into individual bullet points.
 */
export function splitExperiencePoints(raw?: string | string[]): string[] {
  if (!raw) return [];
  if (Array.isArray(raw)) {
    return raw.map((s) => String(s).replace(/^[•\-*\s]+/, "").trim()).filter((s) => s.length > 5);
  }
  const normalized = String(raw)
    .replace(/\r\n/g, "\n")
    .replace(/\s+[•]\s+/g, "\n• ")
    .trim();

  const lines = normalized
    .split(/\n+/)
    .map((line) => line.replace(/^[•\-*\d.)\s]+/, "").trim())
    .filter((line) => line.length > 5);

  return lines;
}

const JD_STOPWORDS = new Set([
  "with", "that", "this", "from", "have", "will", "your", "their", "about", "using",
  "experience", "work", "working", "team", "role", "build", "building", "strong",
  "years", "skills", "looking", "seeking", "engineer", "engineering", "developer",
]);

/**
 * Ranks all bullet points across all candidate experiences against the target JD
 * so the best-matching proof points are surfaced to the AI generator.
 */
export function formatBestExperienceForJd(
  experiences: ExperienceItem[] | undefined,
  jd: string,
  maxPoints = 6
): string {
  if (!Array.isArray(experiences) || experiences.length === 0) return "";

  const jdLower = (jd || "").toLowerCase();
  const jdKeywords = Array.from(
    new Set(
      (jdLower.match(/[a-z0-9.+#-]{3,}/g) || []).filter((w) => !JD_STOPWORDS.has(w))
    )
  );

  const scored: Array<{
    roleHeader: string;
    point: string;
    score: number;
    roleIdx: number;
  }> = [];

  experiences.forEach((exp, roleIdx) => {
    const roleHeader = `${exp.designation || "Engineer"} at ${exp.company_name || "Company"}${
      exp.from ? ` (${exp.from}–${exp.to || "Present"})` : ""
    }`;
    const points = splitExperiencePoints(exp.responsibilities_projects);

    for (const point of points) {
      const pointLower = point.toLowerCase();
      let score = 0;

      for (const skill of KNOWN_SKILLS) {
        if (skill.pattern.test(jd) && skill.pattern.test(point)) {
          score += 4;
        }
      }

      for (const kw of jdKeywords) {
        if (pointLower.includes(kw)) {
          score += 1.5;
        }
      }

      if (/\d+%|\d+x|\$\d+|\d+\+/i.test(point)) {
        score += 2;
      }

      // Slight recency preference so ties favor recent roles
      score += Math.max(0, 1 - roleIdx * 0.25);

      scored.push({ roleHeader, point, score, roleIdx });
    }
  });

  if (scored.length === 0) return "";

  const top = [...scored]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxPoints);

  return top
    .map((item) => `[${item.roleHeader}] • ${item.point}`)
    .join("\n");
}
