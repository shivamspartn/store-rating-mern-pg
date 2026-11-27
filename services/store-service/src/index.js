import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { pool, redis } from "./db.js";
import { createStoreSchema, submitRatingSchema } from "./validators.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const app = express();
app.use(cors());
app.use(express.json());

const INTERNAL_KEY = process.env.INTERNAL_API_KEY;

function verifyInternal(req, res, next) {
  if (req.headers["x-internal-key"] !== INTERNAL_KEY) {
    return res.status(403).json({ message: "Forbidden internal access" });
  }
  next();
}

async function invalidateStoreCaches(storeId) {
  const keys = await redis.keys("stores:*");
  if (keys.length > 0) {
    await redis.del(...keys);
  }
  await redis.del("admin:dashboard:stats", `owner:dashboard:${storeId}`);
}

app.get("/health", (_req, res) => res.json({ status: "ok", service: "store-service" }));

// Admin: Create Store
app.post("/admin/stores", verifyInternal, async (req, res) => {
  const parsed = createStoreSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten().fieldErrors });
  }

  const { name, email, address, ownerId } = parsed.data;
  try {
    const ownerCheck = await pool.query(
      "SELECT id, role FROM users WHERE id = $1",
      [ownerId]
    );
    if (ownerCheck.rows.length === 0) {
      return res.status(404).json({ message: "Store owner user not found" });
    }

    const result = await pool.query(
      `INSERT INTO stores (owner_id, name, email, address)
       VALUES ($1, $2, $3, $4)
       RETURNING id, owner_id, name, email, address, average_rating, total_ratings, created_at`,
      [ownerId, name, email.toLowerCase(), address]
    );

    await invalidateStoreCaches(result.rows[0].id);
    return res.status(201).json({ store: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ message: "Store email already exists" });
    }
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// List / Search / Sort Stores (with Redis caching + optional userRating)
app.get("/stores", verifyInternal, async (req, res) => {
  const { name = "", address = "", sortBy = "name", order = "asc" } = req.query;
  const userId = req.headers["x-user-id"] ? Number(req.headers["x-user-id"]) : null;

  const allowedSort = {
    name: "s.name",
    address: "s.address",
    average_rating: "s.average_rating",
    created_at: "s.created_at",
  };
  const sortColumn = allowedSort[sortBy] || "s.name";
  const sortDirection = String(order).toLowerCase() === "desc" ? "DESC" : "ASC";

  const cacheKey = `stores:list:n=${name}:a=${address}:s=${sortColumn}:o=${sortDirection}:u=${userId || "anon"}`;

  try {
    const cached = await redis.get(cacheKey);
    if (cached) {
      return res.json({ ...JSON.parse(cached), cached: true });
    }

    const conditions = [];
    const values = [];

    if (name) {
      values.push(`%${name}%`);
      conditions.push(`s.name ILIKE $${values.length}`);
    }
    if (address) {
      values.push(`%${address}%`);
      conditions.push(`s.address ILIKE $${values.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    let userRatingSelect = "NULL::smallint AS user_rating";
    let userRatingJoin = "";
    if (userId) {
      values.push(userId);
      userRatingSelect = "r.rating AS user_rating";
      userRatingJoin = `LEFT JOIN ratings r ON r.store_id = s.id AND r.user_id = $${values.length}`;
    }

    const query = `
      SELECT
        s.id,
        s.owner_id,
        s.name,
        s.email,
        s.address,
        s.average_rating,
        s.total_ratings,
        s.created_at,
        ${userRatingSelect}
      FROM stores s
      ${userRatingJoin}
      ${whereClause}
      ORDER BY ${sortColumn} ${sortDirection}
    `;

    const result = await pool.query(query, values);
    const payload = { stores: result.rows };
    await redis.set(cacheKey, JSON.stringify(payload), "EX", 60);

    return res.json({ ...payload, cached: false });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Submit or Update Rating (1-5) inside a Transaction
app.post("/stores/:id/ratings", verifyInternal, async (req, res) => {
  const storeId = Number(req.params.id);
  const userId = Number(req.headers["x-user-id"]);

  if (!Number.isInteger(storeId) || storeId <= 0) {
    return res.status(400).json({ message: "Invalid store ID" });
  }
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.status(401).json({ message: "Authenticated user required" });
  }

  const parsed = submitRatingSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ message: "Validation failed", errors: parsed.error.flatten().fieldErrors });
  }

  const { rating } = parsed.data;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const storeExists = await client.query("SELECT id FROM stores WHERE id = $1", [storeId]);
    if (storeExists.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Store not found" });
    }

    const ratingRow = await client.query(
      `INSERT INTO ratings (user_id, store_id, rating, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (user_id, store_id)
       DO UPDATE SET rating = EXCLUDED.rating, updated_at = NOW()
       RETURNING id, user_id, store_id, rating, updated_at`,
      [userId, storeId, rating]
    );

    const agg = await client.query(
      `SELECT
         COALESCE(ROUND(AVG(rating)::numeric, 1), 0.0) AS average_rating,
         COUNT(*)::int AS total_ratings
       FROM ratings
       WHERE store_id = $1`,
      [storeId]
    );

    const updatedStore = await client.query(
      `UPDATE stores
       SET average_rating = $1, total_ratings = $2
       WHERE id = $3
       RETURNING id, name, address, average_rating, total_ratings`,
      [agg.rows[0].average_rating, agg.rows[0].total_ratings, storeId]
    );

    await client.query("COMMIT");
    await invalidateStoreCaches(storeId);

    return res.status(200).json({
      rating: ratingRow.rows[0],
      store: updatedStore.rows[0],
    });
  } catch (err) {
    await client.query("ROLLBACK");
    return res.status(500).json({ message: "Transaction failed", error: err.message });
  } finally {
    client.release();
  }
});

// Store Owner Dashboard: Stores Owned + Ratings Received
app.get("/owner/dashboard", verifyInternal, async (req, res) => {
  const ownerId = Number(req.headers["x-user-id"]);
  if (!Number.isInteger(ownerId) || ownerId <= 0) {
    return res.status(401).json({ message: "Authenticated store owner required" });
  }

  try {
    const storesRes = await pool.query(
      `SELECT id, name, email, address, average_rating, total_ratings
       FROM stores
       WHERE owner_id = $1
       ORDER BY id ASC`,
      [ownerId]
    );

    const storeIds = storesRes.rows.map((s) => s.id);
    if (storeIds.length === 0) {
      return res.json({ stores: [], ratings: [] });
    }

    const ratingsRes = await pool.query(
      `SELECT
         r.id,
         r.store_id,
         s.name AS store_name,
         r.rating,
         r.updated_at,
         u.id AS user_id,
         u.name AS user_name,
         u.email AS user_email
       FROM ratings r
       JOIN users u ON u.id = r.user_id
       JOIN stores s ON s.id = r.store_id
       WHERE r.store_id = ANY($1::int[])
       ORDER BY r.updated_at DESC`,
      [storeIds]
    );

    return res.json({
      stores: storesRes.rows,
      ratings: ratingsRes.rows,
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Internal: Store & Rating Totals for Admin Dashboard
app.get("/admin/stats/stores", verifyInternal, async (_req, res) => {
  try {
    const storesCount = await pool.query("SELECT COUNT(*)::int AS total_stores FROM stores");
    const ratingsCount = await pool.query("SELECT COUNT(*)::int AS total_ratings FROM ratings");
    return res.json({
      total_stores: storesCount.rows[0].total_stores,
      total_ratings: ratingsCount.rows[0].total_ratings,
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

const PORT = process.env.PORT || 4002;
app.listen(PORT, () => console.log(`store-service running on port ${PORT}`));