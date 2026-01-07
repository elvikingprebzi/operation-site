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

const PORT = process.env.PORT || 3001;
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "change-this";

const PASSWORDS_FILE = path.join(__dirname, "passwords.json");
const AUDIT_LOG_FILE = path.join(__dirname, "audit.log");
const FIELD_IDS = Array.from({ length: 12 }, (_, i) => `f${i + 1}`);

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);

app.use(express.json({ limit: "64kb" }));

app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 240,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

// -----------------------------
// Helpers: audit log (append-only)
// -----------------------------
function appendAudit(event, details = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    event,
    ...details,
  });
  fs.appendFileSync(AUDIT_LOG_FILE, line + "\n", "utf-8");
}

// -----------------------------
// Helpers: password storage
// -----------------------------
function ensurePasswordsFileExists() {
  if (!fs.existsSync(PASSWORDS_FILE)) {
    const initial = {};
    for (const id of FIELD_IDS) initial[id] = { hash: "", unlocked: false };
    fs.writeFileSync(PASSWORDS_FILE, JSON.stringify(initial, null, 2), "utf-8");
  }
}

function normalizePasswords(data) {
  const obj = data && typeof data === "object" ? data : {};
  const out = {};
  for (const id of FIELD_IDS) {
    const v = obj[id];
    if (typeof v === "string") out[id] = { hash: v, unlocked: false };
    else if (v && typeof v === "object")
      out[id] = { hash: v.hash || "", unlocked: !!v.unlocked };
    else out[id] = { hash: "", unlocked: false };
  }
  return out;
}

function loadPasswords() {
  ensurePasswordsFileExists();
  const raw = fs.readFileSync(PASSWORDS_FILE, "utf-8");
  let parsed = {};
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = {};
  }
  return normalizePasswords(parsed);
}

function savePasswords(passwords) {
  const tmp = `${PASSWORDS_FILE}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(passwords, null, 2), "utf-8");
  fs.renameSync(tmp, PASSWORDS_FILE);
}

let passwords = loadPasswords();

// -----------------------------
// Admin auth (HTTP Basic Auth)
// -----------------------------
function parseBasicAuth(header) {
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
    res.setHeader("WWW-Authenticate", 'Basic realm="System Login"');
    // For API calls return JSON; for pages return text.
    if (req.path.startsWith("/api/")) return res.status(401).json({ ok: false, error: "Unauthorized" });
    return res.status(401).send("Unauthorized");
  }
  next();
}

// -----------------------------
// Serve public frontend
// -----------------------------
const publicDir = path.join(__dirname, "..", "public");
app.use(express.static(publicDir));

// -----------------------------
// Admin UI routes (protected)
// NOTE: We do NOT serve admin.html via static. These routes require login first.
// -----------------------------
app.get("/admin", requireAdmin, (req, res) => {
  res.sendFile(path.join(publicDir, "admin.html"));
});
app.get("/admin.js", requireAdmin, (req, res) => {
  res.sendFile(path.join(publicDir, "admin.js"));
});

// -----------------------------
// Public API
// -----------------------------
app.get("/api/status", (req, res) => {
  passwords = loadPasswords();
  const status = {};
  for (const id of FIELD_IDS) status[id] = !!passwords[id]?.unlocked;
  res.json({ ok: true, status });
});

app.post("/api/verify", async (req, res) => {
  const { fieldId, password } = req.body || {};

  if (!FIELD_IDS.includes(fieldId)) return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  if (typeof password !== "string") return res.status(400).json({ ok: false, error: "Invalid password" });

  passwords = loadPasswords();
  const entry = passwords[fieldId];
  if (!entry || !entry.hash) return res.json({ ok: false });

  try {
    const match = await bcrypt.compare(password, entry.hash);
    if (!match) return res.json({ ok: false });

    // Persist unlock
    if (!passwords[fieldId].unlocked) {
      passwords[fieldId].unlocked = true;
      savePasswords(passwords);
      appendAudit("VERIFY_UNLOCK", { fieldId, ip: req.ip });
    }

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// -----------------------------
// Admin API (protected)
// -----------------------------
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

app.post("/api/admin/set", requireAdmin, async (req, res) => {
  const { fieldId, password } = req.body || {};

  if (!FIELD_IDS.includes(fieldId)) return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  if (typeof password !== "string" || password.length < 1)
    return res.status(400).json({ ok: false, error: "Password required" });

  passwords = loadPasswords();

  try {
    const hash = await bcrypt.hash(password, 10);

    // Changing password locks field again (as a sensible default)
    passwords[fieldId] = { hash, unlocked: false };
    savePasswords(passwords);

    appendAudit("ADMIN_SET_PASSWORD", { fieldId, ip: req.ip });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/api/admin/reset", requireAdmin, (req, res) => {
  const { fieldId } = req.body || {};
  passwords = loadPasswords();

  if (fieldId === "all") {
    for (const id of FIELD_IDS) {
      if (!passwords[id]) passwords[id] = { hash: "", unlocked: false };
      passwords[id].unlocked = false;
    }
    savePasswords(passwords);
    appendAudit("ADMIN_RESET_ALL", { ip: req.ip });
    return res.json({ ok: true });
  }

  if (!FIELD_IDS.includes(fieldId)) return res.status(400).json({ ok: false, error: "Invalid fieldId" });

  if (!passwords[fieldId]) passwords[fieldId] = { hash: "", unlocked: false };
  passwords[fieldId].unlocked = false;
  savePasswords(passwords);

  appendAudit("ADMIN_RESET_ONE", { fieldId, ip: req.ip });

  res.json({ ok: true });
});

// Append-only log viewer (latest N lines)
app.get("/api/admin/log", requireAdmin, (req, res) => {
  const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 200)));

  if (!fs.existsSync(AUDIT_LOG_FILE)) {
    return res.json({ ok: true, lines: [] });
  }

  const raw = fs.readFileSync(AUDIT_LOG_FILE, "utf-8");
  const lines = raw.trim().split("\n");
  const tail = lines.slice(Math.max(0, lines.length - limit));
  res.json({ ok: true, lines: tail });
});

// Fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});