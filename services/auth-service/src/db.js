
import pg from "pg";
import Redis from "ioredis";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";


const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, "../.env") });

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

export const redis = new Redis(process.env.REDIS_URL);