# Uncold – Backend API Service 🔥

> Precision outreach API engine powered by Node.js, Express, TypeScript, and Google Gemini API.

This repository powers the backend intelligence for **Uncold**, handling resume parsing (PDF in-memory extraction via `pdf-parse`), semantic Job Description analysis, and personalized outreach generation via Gemini 1.5 Flash.

---

## 🚀 Quick Start

### 1. Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
PORT=5000
FRONTEND_URL=http://localhost:3000
GEMINI_API_KEY=your_gemini_api_key_here
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Start Development Server
```bash
npm run dev
```
Server runs at [http://localhost:5000](http://localhost:5000).

---

## 📡 API Endpoints

- **`GET /api/health`**: Returns service status, timestamp, and Gemini API key configuration check.
- **`POST /api/generate`**: Multipart form endpoint accepting:
  - `resume`: PDF file (up to 10MB) or `resumeText`
  - `jobDescription`: Target job requirements
  - `tone`: `confident`, `direct`, or `value`
  - `targetRole`: e.g. `VP of Engineering`, `Hiring Manager`

Returns structured JSON with subject line, email body, hook, key matches, and LinkedIn DM copy.
