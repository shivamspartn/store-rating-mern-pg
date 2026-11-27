import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { pool, redis } from "./db.js";
import {
  registerSchema,
  adminCreateUserSchema,
  changePasswordSchema,
} from "./validators.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const INTERNAL_KEY = process.env.INTERNAL_API_KEY;

// Middleware: verify internal gateway calls
function verifyInternal(req, res, next) {
  if (req.headers["x-internal-key"] !== INTERNAL_KEY) {
    return res.status(403).json({ message: "Forbidden internal access" });
  }
  next();
}

// Seed default System Administrator
async function seedAdmin() {
  const email = "admin@platform.com";
  const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash("Admin@1234", 10);
    await pool.query(
      `INSERT INTO users (name, email, password_hash, address, role)
       VALUES ($1, $2, $3, $4, 'ADMIN')`,
      [
        "Platform System Administrator",
        email,
        hash,
        "100 Admin Headquarters, Vadodara, Gujarat",
      ]
    );
    console.log("Seeded default Admin: admin@platform.com / Admin@1234");
  }
}

app.get("/health", (_req, res) => res.json({ status: "ok", service: "auth-service" }));

// Normal User Signup
app.post("/signup", async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten().fieldErrors });
  }
  const { name, email, address, password } = parsed.data;
  try {
    const exists = await pool.query("SELECT id FROM users WHERE email = $1", [email.toLowerCase()]);
    if (exists.rows.length > 0) {
      return res.status(409).json({ message: "Email already registered" });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, address, role)
       VALUES ($1, $2, $3, $4, 'USER')
       RETURNING id, name, email, address, role, created_at`,
      [name, email.toLowerCase(), passwordHash, address]
    );
    await redis.del("admin:dashboard:stats");
    return res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Single Login for All Roles
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: "1d" }
    );
    return res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, address: user.address, role: user.role },
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Update Password (Authenticated User)
app.patch("/password", verifyInternal, async (req, res) => {
  const userId = Number(req.headers["x-user-id"]);
  const parsed = changePasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten().fieldErrors });
  }
  try {
    const result = await pool.query("SELECT password_hash FROM users WHERE id = $1", [userId]);
    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });

    const match = await bcrypt.compare(parsed.data.currentPassword, result.rows[0].password_hash);
    if (!match) return res.status(400).json({ message: "Current password is incorrect" });

    const newHash = await bcrypt.hash(parsed.data.newPassword, 10);
    await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [newHash, userId]);
    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Admin: Create User (ADMIN, USER, or STORE_OWNER)
app.post("/admin/users", verifyInternal, async (req, res) => {
  const parsed = adminCreateUserSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten().fieldErrors });
  }
  const { name, email, address, password, role } = parsed.data;
  try {
    const exists = await pool.query("SELECT id FROM users WHERE email = $1", [email.toLowerCase()]);
    if (exists.rows.length > 0) return res.status(409).json({ message: "Email already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, address, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, name, email, address, role, created_at`,
      [name, email.toLowerCase(), passwordHash, address, role]
    );
    await redis.del("admin:dashboard:stats");
    return res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Admin: List Users with Filters & Sorting
app.get("/admin/users", verifyInternal, async (req, res) => {
  const { name = "", email = "", address = "", role = "", sortBy = "name", order = "asc" } = req.query;

  const allowedSort = { name: "name", email: "email", address: "address", role: "role", created_at: "created_at" };
  const sortColumn = allowedSort[sortBy] || "name";
  const sortDirection = String(order).toLowerCase() === "desc" ? "DESC" : "ASC";

  const conditions = [];
  const values = [];

  if (name) {
    values.push(`%${name}%`);
    conditions.push(`name ILIKE $${values.length}`);
  }
  if (email) {
    values.push(`%${email}%`);
    conditions.push(`email ILIKE $${values.length}`);
  }
  if (address) {
    values.push(`%${address}%`);
    conditions.push(`address ILIKE $${values.length}`);
  }
  if (role) {
    values.push(role.toUpperCase());
    conditions.push(`role = $${values.length}`);
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

  try {
    const query = `
      SELECT id, name, email, address, role, created_at
      FROM users
      ${whereClause}
      ORDER BY ${sortColumn} ${sortDirection}
    `;
    const result = await pool.query(query, values);
    return res.json({ users: result.rows });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Admin: Get Single User Details
app.get("/admin/users/:id", verifyInternal, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, name, email, address, role, created_at FROM users WHERE id = $1",
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });
    return res.json({ user: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Internal: Total User Count for Admin Dashboard
app.get("/admin/stats/users", verifyInternal, async (_req, res) => {
  try {
    const result = await pool.query("SELECT COUNT(*)::int AS total_users FROM users");
    return res.json(result.rows[0]);
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

const PORT = process.env.PORT || 4001;
seedAdmin().then(() => {
  app.listen(PORT, () => console.log(`auth-service running on port ${PORT}`));
});