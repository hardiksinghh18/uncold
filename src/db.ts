import dns from "dns";
import { Pool } from "pg";
import type { QueryResult, QueryResultRow } from "pg";
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
  max: process.env.VERCEL ? 3 : 5,
  idleTimeoutMillis: process.env.VERCEL ? 10000 : 30000,
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
          connected_gmail VARCHAR(255),
          google_refresh_token TEXT,
          google_access_token TEXT,
          gmail_scopes_verified BOOLEAN DEFAULT false,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
      `);

      await client.query(`
        ALTER TABLE ${SCHEMA_NAME}.users ADD COLUMN IF NOT EXISTS connected_gmail VARCHAR(255);
        ALTER TABLE ${SCHEMA_NAME}.users ADD COLUMN IF NOT EXISTS gmail_scopes_verified BOOLEAN DEFAULT false;
      `);

      // 3. Profiles table
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${SCHEMA_NAME}.profiles (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID REFERENCES ${SCHEMA_NAME}.users(id) ON DELETE CASCADE,
          email VARCHAR(255),
          full_name VARCHAR(255),
          phone VARCHAR(100),
          headline VARCHAR(255),
          introduction TEXT,
          skills JSONB DEFAULT '[]',
          projects_and_past_experience JSONB DEFAULT '[]',
          education_details JSONB DEFAULT '[]',
          certification_details JSONB DEFAULT '[]',
          portfolio_links JSONB DEFAULT '{}',
          raw_parsed_data JSONB DEFAULT '{}',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
      `);

      // Ensure profile columns exist if table was already created
      await client.query(`
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS email VARCHAR(255);
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS phone VARCHAR(100);
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS location VARCHAR(255);
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS introduction TEXT;
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS skills JSONB DEFAULT '[]';
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS projects_and_past_experience JSONB DEFAULT '[]';
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS education_details JSONB DEFAULT '[]';
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS certification_details JSONB DEFAULT '[]';
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS raw_parsed_data JSONB DEFAULT '{}';
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS resume_url TEXT;
        ALTER TABLE ${SCHEMA_NAME}.profiles ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();
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
          sender_email VARCHAR(255),
          recipient_email VARCHAR(255),
          gmail_message_id VARCHAR(255),
          gmail_thread_id VARCHAR(255),
          subject TEXT,
          body TEXT,
          sent_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          opened_at TIMESTAMP WITH TIME ZONE,
          open_count INT DEFAULT 0,
          reply_detected_at TIMESTAMP WITH TIME ZONE
        );
      `);

      // Ensure new columns exist if table was already created
      await client.query(`
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS sender_email VARCHAR(255);
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS recipient_email VARCHAR(255);
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS opened_at TIMESTAMP WITH TIME ZONE;
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS open_count INT DEFAULT 0;
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS channel VARCHAR(30) DEFAULT 'email';
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS company_name VARCHAR(255);
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS recipient_name VARCHAR(255);
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS job_title VARCHAR(255);
        ALTER TABLE ${SCHEMA_NAME}.emails ADD COLUMN IF NOT EXISTS job_metadata JSONB DEFAULT '{}'::jsonb;
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
