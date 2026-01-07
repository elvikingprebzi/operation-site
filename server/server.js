import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const PORT = process.env.PORT || 3001;

// Set these later in hosting (and locally when you run it)
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "change-this";

const PASSWORD_FILE = path.join(__dirname, "passwords.json");

app.use(helmet());
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 180
  })
);

function readPasswords() {
  const raw = fs.readFileSync(PASSWORD_FILE, "utf8");
  return JSON.parse(raw);
}

function writePasswords(data) {
  fs.writeFileSync(PASSWORD_FILE, JSON.stringify(data, null, 2), "utf8");
}

function isValidFieldId(fieldId) {
  return /^f([1-9]|1[0-2])$/.test(fieldId);
}

function requireBasicAuth(req, res, next) {
  const hdr = req.headers.authorization || "";
  if (!hdr.startsWith("Basic ")) {
    return res.status(401).set("WWW-Authenticate", "Basic").end();
  }

  const decoded = Buffer.from(hdr.slice(6), "base64").toString("utf8");
  const [user, pass] = decoded.split(":");

  if (user === ADMIN_USER && pass === ADMIN_PASS) return next();
  return res.status(401).set("WWW-Authenticate", "Basic").end();
}

// Serve frontend from /public
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir));

app.get("/api/health", (req, res) => res.json({ ok: true }));

// Verify a field entry (main page)
app.post("/api/verify", async (req, res) => {
  try {
    const { fieldId, value } = req.body ?? {};
    if (!isValidFieldId(fieldId) || typeof value !== "string") {
      return res.status(400).json({ ok: false, error: "Bad request" });
    }

    const store = readPasswords();
    const hash = store.fields[fieldId];
    if (!hash) return res.json({ ok: false });

    const ok = await bcrypt.compare(value, hash);
    return res.json({ ok });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Admin: view status
app.get("/api/admin/status", requireBasicAuth, (req, res) => {
  const store = readPasswords();
  const status = {};
  for (const [k, v] of Object.entries(store.fields)) status[k] = Boolean(v);
  res.json({ ok: true, status });
});

// Admin: set/change password
app.post("/api/admin/set", requireBasicAuth, async (req, res) => {
  try {
    const { fieldId, password } = req.body ?? {};
    if (!isValidFieldId(fieldId) || typeof password !== "string" || password.length < 1) {
      return res.status(400).json({ ok: false, error: "Bad request" });
    }

    const store = readPasswords();
    store.fields[fieldId] = await bcrypt.hash(password, 12);
    writePasswords(store);

    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Admin: clear a field password
app.post("/api/admin/clear", requireBasicAuth, (req, res) => {
  const { fieldId } = req.body ?? {};
  if (!isValidFieldId(fieldId)) return res.status(400).json({ ok: false });

  const store = readPasswords();
  store.fields[fieldId] = null;
  writePasswords(store);

  res.json({ ok: true });
});

// Admin: test a password
app.post("/api/admin/test", requireBasicAuth, async (req, res) => {
  try {
    const { fieldId, password } = req.body ?? {};
    if (!isValidFieldId(fieldId) || typeof password !== "string") {
      return res.status(400).json({ ok: false, error: "Bad request" });
    }

    const store = readPasswords();
    const hash = store.fields[fieldId];
    if (!hash) return res.json({ ok: false });

    const ok = await bcrypt.compare(password, hash);
    return res.json({ ok });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Admin: clear ALL (optional)
app.post("/api/admin/clearAll", requireBasicAuth, (req, res) => {
  const store = readPasswords();
  for (const k of Object.keys(store.fields)) store.fields[k] = null;
  writePasswords(store);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});