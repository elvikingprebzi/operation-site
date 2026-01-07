import express from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------
// Config
// ---------------------------
const PORT = process.env.PORT || 3001;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "change-this";

// Where we store passwords + unlocked state
const PASSWORDS_FILE = path.join(__dirname, "passwords.json");

// Fields we support
const FIELD_IDS = Array.from({ length: 12 }, (_, i) => `f${i + 1}`);

// ---------------------------
// Helpers: load/save
// ---------------------------
function ensureFileExists() {
  if (!fs.existsSync(PASSWORDS_FILE)) {
    const initial = {};
    for (const id of FIELD_IDS) {
      initial[id] = { hash: "", unlocked: false };
    }
    fs.writeFileSync(PASSWORDS_FILE, JSON.stringify(initial, null, 2), "utf-8");
  }
}

// Backward compatible:
// - If value is a string => treat as { hash: string, unlocked: false }
// - If object => ensure { hash, unlocked }
function normalizePasswords(data) {
  const out = {};
  const obj = data && typeof data === "object" ? data : {};

  for (const id of FIELD_IDS) {
    const v = obj[id];

    if (typeof v === "string") {
      out[id] = { hash: v, unlocked: false };
    } else if (v && typeof v === "object") {
      out[id] = { hash: v.hash || "", unlocked: !!v.unlocked };
    } else {
      out[id] = { hash: "", unlocked: false };
    }
  }
  return out;
}

function loadPasswords() {
  ensureFileExists();
  const raw = fs.readFileSync(PASSWORDS_FILE, "utf-8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = {};
  }
  return normalizePasswords(parsed);
}

// Atomic-ish write to reduce corruption risk
function savePasswords(passwords) {
  const tmp = `${PASSWORDS_FILE}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(passwords, null, 2), "utf-8");
  fs.renameSync(tmp, PASSWORDS_FILE);
}

// Keep in memory; write whenever changed
let passwords = loadPasswords();

// ---------------------------
// Admin auth (Basic Auth)
// ---------------------------
function parseBasicAuth(header) {
  // header like: "Basic base64(user:pass)"
  if (!header || !header.startsWith("Basic ")) return null;
  const b64 = header.slice("Basic ".length).trim();
  let decoded = "";
  try {
    decoded = Buffer.from(b64, "base64").toString("utf-8");
  } catch {
    return null;
  }
  const idx = decoded.indexOf(":");
  if (idx < 0) return null;
  return { user: decoded.slice(0, idx), pass: decoded.slice(idx + 1) };
}

function requireAdmin(req, res, next) {
  const creds = parseBasicAuth(req.headers.authorization);
  if (!creds || creds.user !== ADMIN_USER || creds.pass !== ADMIN_PASS) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Admin"');
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// ---------------------------
// App setup
// ---------------------------
const app = express();

app.use(
  helmet({
    contentSecurityPolicy: false, // keep simple; you can tighten later
  })
);

app.use(express.json({ limit: "64kb" }));

// Basic rate limiting
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// Serve the frontend from /public (one folder up from server/)
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir));

// ---------------------------
// API: public
// ---------------------------

// Return which fields are unlocked so frontend can show green on load
app.get("/api/status", (req, res) => {
  // Reload from disk to be safe if multiple instances ever happen
  passwords = loadPasswords();

  const status = {};
  for (const id of FIELD_IDS) {
    status[id] = !!passwords[id]?.unlocked;
  }

  res.json({ ok: true, status });
});

// Verify a password for a field.
// If correct: mark unlocked=true and persist to passwords.json
app.post("/api/verify", async (req, res) => {
  const { fieldId, password } = req.body || {};

  if (!FIELD_IDS.includes(fieldId)) {
    return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  }
  if (typeof password !== "string") {
    return res.status(400).json({ ok: false, error: "Invalid password" });
  }

  // Always reload in case admin changed things
  passwords = loadPasswords();

  const entry = passwords[fieldId];
  if (!entry || !entry.hash) {
    return res.json({ ok: false });
  }

  try {
    const match = await bcrypt.compare(password, entry.hash);
    if (!match) return res.json({ ok: false });

    // Persist unlock
    passwords[fieldId].unlocked = true;
    savePasswords(passwords);

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// ---------------------------
// API: admin (protected)
// ---------------------------

// List current state (hash present? unlocked?)
app.get("/api/admin/state", requireAdmin, (req, res) => {
  passwords = loadPasswords();

  const state = {};
  for (const id of FIELD_IDS) {
    state[id] = {
      hasPassword: !!passwords[id]?.hash,
      unlocked: !!passwords[id]?.unlocked,
    };
  }
  res.json({ ok: true, state });
});

// Set/replace a password for a field.
// NOTE: also locks it (unlocked=false) by default when password is changed.
app.post("/api/admin/set", requireAdmin, async (req, res) => {
  const { fieldId, password } = req.body || {};

  if (!FIELD_IDS.includes(fieldId)) {
    return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  }
  if (typeof password !== "string" || password.length < 1) {
    return res.status(400).json({ ok: false, error: "Password required" });
  }

  passwords = loadPasswords();

  try {
    const hash = await bcrypt.hash(password, 10);
    passwords[fieldId] = { hash, unlocked: false }; // lock on change
    savePasswords(passwords);

    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Reset (lock) one field OR all fields
app.post("/api/admin/reset", requireAdmin, (req, res) => {
  const { fieldId } = req.body || {};

  passwords = loadPasswords();

  if (fieldId === "all") {
    for (const id of FIELD_IDS) {
      if (!passwords[id]) passwords[id] = { hash: "", unlocked: false };
      passwords[id].unlocked = false;
    }
    savePasswords(passwords);
    return res.json({ ok: true });
  }

  if (!FIELD_IDS.includes(fieldId)) {
    return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  }

  if (!passwords[fieldId]) passwords[fieldId] = { hash: "", unlocked: false };
  passwords[fieldId].unlocked = false;
  savePasswords(passwords);

  res.json({ ok: true });
});

// Optional: clear a password entirely (also locks it)
app.post("/api/admin/clear", requireAdmin, (req, res) => {
  const { fieldId } = req.body || {};

  if (!FIELD_IDS.includes(fieldId)) {
    return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  }

  passwords = loadPasswords();
  passwords[fieldId] = { hash: "", unlocked: false };
  savePasswords(passwords);

  res.json({ ok: true });
});

// ---------------------------
// Fallback route
// ---------------------------
app.get("*", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

// ---------------------------
// Start
// ---------------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});