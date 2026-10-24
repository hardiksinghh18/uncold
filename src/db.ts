import dns from "dns";
import { Pool, QueryResult, QueryResultRow } from "pg";
import dotenv from "dotenv";

dotenv.config();

// Ensure IPv4 DNS resolution for Supabase connection pooler on Windows
dns.setDefaultResultOrder("ipv4first");

const SCHEMA_NAME = process.env.DB_SCHEMA || "uncold";

export const pool = new Pool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || "6543", 10),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "postgres",
  ssl: {
    rejectUnauthorized: false,
  },
  connectionTimeoutMillis: 10000,
  max: 5,
  idleTimeoutMillis: 30000,
});

/**
 * Executes a SQL query within the isolated 'uncold' schema namespace.
 * This guarantees zero interference with other projects (like SkillSync in 'public').
 */
export async function query<T extends QueryResultRow = any>(
  text: string,
  params?: any[]
): Promise<QueryResult<T>> {
  const client = await pool.connect();
  try {
    // Set schema search_path so queries operate in the uncold namespace
    await client.query(`SET search_path TO ${SCHEMA_NAME}, public;`);
    return await client.query<T>(text, params);
  } finally {
    client.release();
  }
}

/**
 * Initializes the dedicated 'uncold' database schema and core tables.
 * Safely isolated so that other project tables in 'public' are never touched.
 */
export async function initDb(): Promise<void> {
  if (!process.env.DB_HOST || !process.env.DB_USER) {
    console.log("ℹ️ Database credentials not configured. Skipping DB initialization.");
    return;
  }

  try {
    const client = await pool.connect();
    try {
      console.log(`🔌 Initializing PostgreSQL in dedicated schema: [${SCHEMA_NAME}]...`);

      // 1. Create dedicated schema namespace to isolate Uncold from other projects
      await client.query(`CREATE SCHEMA IF NOT EXISTS ${SCHEMA_NAME};`);
      await client.query(`SET search_path TO ${SCHEMA_NAME}, public;`);

      // 2. Users table
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${SCHEMA_NAME}.users (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          email VARCHAR(255) UNIQUE NOT NULL,
          google_refresh_token TEXT,
          google_access_token TEXT,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
      `);

      // 3. Profiles table
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${SCHEMA_NAME}.profiles (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID REFERENCES ${SCHEMA_NAME}.users(id) ON DELETE CASCADE,
          resume_url TEXT,
          full_name VARCHAR(255),
          headline VARCHAR(255),
          parsed_skills JSONB DEFAULT '[]',
          key_achievements JSONB DEFAULT '[]',
          portfolio_links JSONB DEFAULT '{}',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
      `);

      // 4. Outreach Campaigns table
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${SCHEMA_NAME}.outreach_campaigns (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID REFERENCES ${SCHEMA_NAME}.users(id) ON DELETE CASCADE,
          target_company VARCHAR(255),
          job_title VARCHAR(255),
          job_description TEXT,
          recipient_name VARCHAR(255),
          recipient_email VARCHAR(255),
          recipient_linkedin VARCHAR(255),
          status VARCHAR(50) DEFAULT 'draft',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
      `);

      // 5. Emails table
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${SCHEMA_NAME}.emails (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          campaign_id UUID REFERENCES ${SCHEMA_NAME}.outreach_campaigns(id) ON DELETE CASCADE,
          gmail_message_id VARCHAR(255),
          gmail_thread_id VARCHAR(255),
          subject TEXT,
          body TEXT,
          sent_at TIMESTAMP WITH TIME ZONE,
          reply_detected_at TIMESTAMP WITH TIME ZONE
        );
      `);

      console.log(`✅ Dedicated PostgreSQL schema [${SCHEMA_NAME}] and tables verified!`);
    } finally {
      client.release();
    }
  } catch (err: any) {
    console.warn(
      `⚠️ PostgreSQL connection note: ${err.message}. If the Supabase project is paused/asleep, unpause it in the Supabase dashboard.`
    );
  }
}
