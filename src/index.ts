import express, { Request, Response } from "express";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import { GoogleGenAI } from "@google/genai";
import { PDFParse } from "pdf-parse";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

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
    origin: [FRONTEND_URL, "http://localhost:3000", "http://127.0.0.1:3000"],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Helper to extract text from PDF buffer
async function extractTextFromPdf(buffer: Buffer): Promise<string> {
  const parser = new PDFParse({ data: new Uint8Array(buffer) });
  try {
    const textResult = await parser.getText();
    return textResult.text || "";
  } finally {
    await parser.destroy().catch(() => {});
  }
}

// Health Check
app.get("/api/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "uncold-backend",
    hasApiKey: Boolean(process.env.GEMINI_API_KEY),
    timestamp: new Date().toISOString(),
  });
});

// Main Generation Endpoint
app.post(
  "/api/generate",
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
      const resumeFile = req.file;

      if (!jobDescription || jobDescription.trim().length < 15) {
        res.status(400).json({
          error: "A detailed job description (minimum 15 characters) is required.",
        });
        return;
      }

      let parsedResumeText = "";

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
      } else {
        res.status(400).json({
          error: "Either an uploaded PDF resume or resume text is required.",
        });
        return;
      }

      if (!parsedResumeText.trim()) {
        res.status(400).json({
          error: "Could not extract any readable text from the provided resume.",
        });
        return;
      }

      const ai = new GoogleGenAI({ apiKey });

      const prompt = `You are Uncold, a world-class executive career coach and elite outreach copywriter who has helped hundreds of professionals land top-tier roles.

Your task is to analyze the candidate's resume against the target job description and craft a high-converting, personalized cold email to the ${targetRole}.

Tone requested: ${tone} (Options: confident, direct & punchy, value-first, enthusiastic).

Strict Instructions:
1. Subject line: High open-rate, conversational, not generic, mentioning a specific hook or role.
2. Body:
   - Paragraph 1: An intriguing, non-generic opening hook that proves genuine research on the role or company.
   - Paragraph 2: 2-3 specific, high-impact achievements from the resume directly mapped to the JD's biggest pain points or requirements.
   - Paragraph 3: A low-friction call-to-action (e.g. asking for 10 minutes or sharing an idea).
   - Sign-off placeholder: [Your Name]
3. LinkedIn Message: A punchy, character-conscious version (under 280 characters) suitable for a direct LinkedIn message or InMail.
4. Key Matches: List 3 key alignment points between resume and JD.
5. Alternate Subjects: 2 alternative subject lines.

Return ONLY a valid JSON object with EXACTLY this structure (no markdown formatting, no code fences):
{
  "subject": "string",
  "body": "string",
  "hook": "string",
  "keyMatches": ["string", "string", "string"],
  "alternateSubjects": ["string", "string"],
  "linkedInMessage": "string"
}

Target Job Description:
${jobDescription}

Candidate Resume:
${parsedResumeText.slice(0, 8000)}`;

      const response = await ai.models.generateContent({
        model: "gemini-1.5-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          temperature: 0.7,
        },
      });

      const responseText = response.text;
      if (!responseText) {
        throw new Error("Empty response received from Gemini API.");
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

app.listen(PORT, () => {
  console.log(`🚀 Uncold Backend running at http://localhost:${PORT}`);
  console.log(`📡 CORS allowed for: ${FRONTEND_URL}`);
});
