import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import Redis from "ioredis";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export const redis = new Redis(process.env.REDIS_URL);