// Stringing Intake — Express + Postgres server for Railway.
// Env: DATABASE_URL, STAFF_PIN, OWNER_PIN, SESSION_SECRET (any long random string), PORT (Railway sets it).
"use strict";
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const { Pool } = require("pg");

const { DATABASE_URL, STAFF_PIN, OWNER_PIN, SESSION_SECRET } = process.env;
const PORT = process.env.PORT || 3000;
for (const [k, v] of Object.entries({ DATABASE_URL, STAFF_PIN, OWNER_PIN, SESSION_SECRET })) {
  if (!v) { console.error(`Missing environment variable ${k}`); process.exit(1); }
}
if (STAFF_PIN === OWNER_PIN) { console.error("STAFF_PIN and OWNER_PIN must be different"); process.exit(1); }

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1|\.railway\.internal/.test(DATABASE_URL) ? false : { rejectUnauthorized: false },
});
const TABLES = new Set(["clients", "jobs"]);

async function migrate() {
  for (const t of TABLES) {
    await pool.query(`CREATE TABLE IF NOT EXISTS ${t} (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
  }
}

// ---------- sessions: HMAC-signed cookie ----------
const COOKIE = "si_session";
const MAX_AGE_MS = 30 * 24 * 3600 * 1000;
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return `${body}.${mac}`;
}
function verify(token) {
  if (!token || !token.includes(".")) return null;
  const [body, mac] = token.split(".");
  const want = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  if (mac.length !== want.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    if (!p.exp || p.exp < Date.now()) return null;
    // A session stops working when the PIN it was issued for changes.
    if (p.k !== pinKey(p.role)) return null;
    return p;
  } catch { return null; }
}
function pinKey(role) {
  const pin = role === "owner" ? OWNER_PIN : STAFF_PIN;
  return crypto.createHmac("sha256", SESSION_SECRET).update(role + ":" + pin).digest("base64url").slice(0, 16);
}
function readCookie(req) {
  const m = (req.headers.cookie || "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  return m ? decodeURIComponent(m[1]) : null;
}
function setCookie(res, value, maxAgeMs) {
  const secure = process.env.NODE_ENV === "production" || process.env.RAILWAY_ENVIRONMENT ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(maxAgeMs / 1000)}${secure}`);
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// ---------- login throttling ----------
const attempts = new Map(); // ip -> {n, until}
function throttled(ip) { const a = attempts.get(ip); return a && a.n >= 8 && a.until > Date.now(); }
function fail(ip) {
  const a = attempts.get(ip) || { n: 0, until: 0 };
  if (a.until < Date.now()) { a.n = 0; }
  a.n += 1; a.until = Date.now() + 15 * 60 * 1000;
  attempts.set(ip, a);
}

// ---------- app ----------
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "2mb" }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  next();
});

function auth(req, res, next) {
  const s = verify(readCookie(req));
  if (!s) return res.status(401).json({ error: "Please enter the PIN." });
  req.role = s.role;
  next();
}
function ownerOnly(req, res, next) {
  if (req.role !== "owner") return res.status(403).json({ error: "Only the owner PIN can do that." });
  next();
}
function checkTarget(req, res) {
  const { table, id } = req.params;
  if (!TABLES.has(table)) { res.status(404).json({ error: "Unknown table." }); return false; }
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) { res.status(400).json({ error: "Bad id." }); return false; }
  return true;
}
function cleanData(d) {
  if (!d || typeof d !== "object" || Array.isArray(d)) return null;
  const out = {};
  for (const [k, v] of Object.entries(d)) {
    if (k === "id" || !/^[A-Za-z0-9_]{1,40}$/.test(k)) continue;
    if (v === null || typeof v === "boolean" || typeof v === "number") out[k] = v;
    else if (typeof v === "string") out[k] = v.slice(0, 5000);
  }
  return out;
}

app.post("/api/login", (req, res) => {
  const ip = req.ip;
  if (throttled(ip)) return res.status(429).json({ error: "Too many wrong PINs. Try again in 15 minutes." });
  const pin = String((req.body && req.body.pin) || "").trim();
  const role = safeEqual(pin, OWNER_PIN) ? "owner" : safeEqual(pin, STAFF_PIN) ? "staff" : null;
  if (!role) { fail(ip); return res.status(401).json({ error: "That PIN isn't right." }); }
  attempts.delete(ip);
  setCookie(res, sign({ role, k: pinKey(role), exp: Date.now() + MAX_AGE_MS }), MAX_AGE_MS);
  res.json({ role });
});
app.post("/api/logout", (req, res) => { setCookie(res, "", 0); res.json({ ok: true }); });
app.get("/api/me", auth, (req, res) => res.json({ role: req.role }));

app.get("/api/data", auth, async (req, res, next) => {
  try {
    const [c, j] = await Promise.all([
      pool.query("SELECT id, data FROM clients"),
      pool.query("SELECT id, data FROM jobs"),
    ]);
    res.json({ role: req.role, clients: c.rows.map((r) => ({ ...r.data, id: r.id })), jobs: j.rows.map((r) => ({ ...r.data, id: r.id })) });
  } catch (e) { next(e); }
});

// Replace a record (create if missing)
app.put("/api/:table/:id", auth, async (req, res, next) => {
  if (!checkTarget(req, res)) return;
  const data = cleanData(req.body && req.body.data);
  if (!data) return res.status(400).json({ error: "Missing data." });
  try {
    await pool.query(
      `INSERT INTO ${req.params.table} (id, data, updated_at) VALUES ($1, $2, now())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [req.params.id, data]);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// Merge fields into an existing record
app.patch("/api/:table/:id", auth, async (req, res, next) => {
  if (!checkTarget(req, res)) return;
  const data = cleanData(req.body && req.body.data);
  if (!data) return res.status(400).json({ error: "Missing data." });
  try {
    const r = await pool.query(`UPDATE ${req.params.table} SET data = data || $2::jsonb, updated_at = now() WHERE id = $1`, [req.params.id, data]);
    if (!r.rowCount) return res.status(404).json({ error: "That record no longer exists." });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.delete("/api/:table/:id", auth, ownerOnly, async (req, res, next) => {
  if (!checkTarget(req, res)) return;
  try { await pool.query(`DELETE FROM ${req.params.table} WHERE id = $1`, [req.params.id]); res.json({ ok: true }); }
  catch (e) { next(e); }
});

// Owner-only bulk import: { clients: [{id,...}], jobs: [{id,...}] }. Existing ids are overwritten.
app.post("/api/import", auth, ownerOnly, async (req, res, next) => {
  const body = req.body || {};
  const client = await pool.connect();
  let count = 0;
  try {
    await client.query("BEGIN");
    for (const t of TABLES) {
      for (const rec of Array.isArray(body[t]) ? body[t] : []) {
        const id = String(rec && rec.id || "");
        const data = cleanData(rec);
        if (!/^[A-Za-z0-9_-]{1,64}$/.test(id) || !data) continue;
        await client.query(
          `INSERT INTO ${t} (id, data, updated_at) VALUES ($1, $2, now())
           ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, [id, data]);
        count++;
      }
    }
    await client.query("COMMIT");
    res.json({ imported: count });
  } catch (e) { await client.query("ROLLBACK").catch(() => {}); next(e); }
  finally { client.release(); }
});

app.get("/healthz", (req, res) => res.send("ok"));
app.use(express.static(path.join(__dirname, "public"), { index: "index.html", maxAge: 0 }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "Something went wrong saving. Try again." });
});

migrate()
  .then(() => app.listen(PORT, () => console.log(`Stringing Intake listening on ${PORT}`)))
  .catch((e) => { console.error("Database setup failed:", e.message); process.exit(1); });
