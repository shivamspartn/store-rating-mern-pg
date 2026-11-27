import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import Redis from "ioredis";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const AUTH_URL = process.env.AUTH_SERVICE_URL;
const STORE_URL = process.env.STORE_SERVICE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const INTERNAL_KEY = process.env.INTERNAL_API_KEY;
const redis = new Redis(process.env.REDIS_URL);

// Optional JWT decode (allows guest store browsing while attaching user if logged in)
function attachOptionalUser(req, _res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch {
      req.user = null;
    }
  }
  next();
}

// Required JWT verification
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Missing or invalid Authorization token" });
  }
  const token = authHeader.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// Role-based access guard
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "Forbidden: insufficient role permissions" });
    }
    next();
  };
}

// Forward request helper
async function forwardRequest(targetUrl, req, res) {
  const queryString = req.originalUrl.includes("?")
    ? req.originalUrl.slice(req.originalUrl.indexOf("?"))
    : "";

  const headers = {
    "Content-Type": "application/json",
    "x-internal-key": INTERNAL_KEY,
  };
  if (req.user) {
    headers["x-user-id"] = String(req.user.userId);
    headers["x-user-role"] = String(req.user.role);
  }

  const options = {
    method: req.method,
    headers,
  };
  if (!["GET", "HEAD"].includes(req.method) && req.body && Object.keys(req.body).length > 0) {
    options.body = JSON.stringify(req.body);
  }

  try {
    const response = await fetch(`${targetUrl}${queryString}`, options);
    const data = await response.json();
    return res.status(response.status).json(data);
  } catch (err) {
    return res.status(502).json({ message: "Upstream service unavailable", error: err.message });
  }
}

app.get("/health", (_req, res) => res.json({ status: "ok", service: "api-gateway" }));

// Public Auth Routes
app.post("/api/auth/signup", (req, res) => forwardRequest(`${AUTH_URL}/signup`, req, res));
app.post("/api/auth/login", (req, res) => forwardRequest(`${AUTH_URL}/login`, req, res));

// Authenticated Password Update
app.patch("/api/auth/password", requireAuth, (req, res) =>
  forwardRequest(`${AUTH_URL}/password`, req, res)
);

// Public / Authenticated Store Listing
app.get("/api/stores", attachOptionalUser, (req, res) =>
  forwardRequest(`${STORE_URL}/stores`, req, res)
);

// Normal User: Submit / Update Rating
app.post("/api/stores/:id/ratings", requireAuth, requireRole("USER"), (req, res) =>
  forwardRequest(`${STORE_URL}/stores/${req.params.id}/ratings`, req, res)
);

// Store Owner: Dashboard
app.get("/api/owner/dashboard", requireAuth, requireRole("STORE_OWNER"), (req, res) =>
  forwardRequest(`${STORE_URL}/owner/dashboard`, req, res)
);

// Admin: Cached Dashboard Stats
app.get("/api/admin/dashboard", requireAuth, requireRole("ADMIN"), async (_req, res) => {
  const cacheKey = "admin:dashboard:stats";
  try {
    const cached = await redis.get(cacheKey);
    if (cached) {
      return res.json({ ...JSON.parse(cached), cached: true });
    }

    const [usersRes, storesRes] = await Promise.all([
      fetch(`${AUTH_URL}/admin/stats/users`, { headers: { "x-internal-key": INTERNAL_KEY } }),
      fetch(`${STORE_URL}/admin/stats/stores`, { headers: { "x-internal-key": INTERNAL_KEY } }),
    ]);

    const usersData = await usersRes.json();
    const storesData = await storesRes.json();

    const stats = {
      total_users: usersData.total_users ?? 0,
      total_stores: storesData.total_stores ?? 0,
      total_ratings: storesData.total_ratings ?? 0,
    };

    await redis.set(cacheKey, JSON.stringify(stats), "EX", 30);
    return res.json({ ...stats, cached: false });
  } catch (err) {
    return res.status(500).json({ message: "Failed to load admin stats", error: err.message });
  }
});

// Admin: User Management
app.post("/api/admin/users", requireAuth, requireRole("ADMIN"), (req, res) =>
  forwardRequest(`${AUTH_URL}/admin/users`, req, res)
);
app.get("/api/admin/users", requireAuth, requireRole("ADMIN"), (req, res) =>
  forwardRequest(`${AUTH_URL}/admin/users`, req, res)
);
app.get("/api/admin/users/:id", requireAuth, requireRole("ADMIN"), (req, res) =>
  forwardRequest(`${AUTH_URL}/admin/users/${req.params.id}`, req, res)
);

// Admin: Store Creation
app.post("/api/admin/stores", requireAuth, requireRole("ADMIN"), (req, res) =>
  forwardRequest(`${STORE_URL}/admin/stores`, req, res)
);

app.listen(PORT, () => console.log(`api-gateway running on port ${PORT}`));