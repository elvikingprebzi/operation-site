import express from "express";
import path from "path";
import fs from "fs";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3001;

// Set these in Render Environment
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "change-this";

const PASSWORDS_FILE = path.join(__dirname, "passwords.json");
const AUDIT_LOG_FILE = path.join(__dirname, "audit.log");
const FIELD_IDS = Array.from({ length: 12 }, (_, i) => `f${i + 1}`);

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "64kb" }));

// ---------- Helpers ----------
function appendAudit(event, details = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    event,
    ...details,
  });
  fs.appendFileSync(AUDIT_LOG_FILE, line + "\n", "utf-8");
}

function ensurePasswordsFile() {
  if (!fs.existsSync(PASSWORDS_FILE)) {
    const initial = {};
    for (const id of FIELD_IDS) initial[id] = { hash: "", unlocked: false };
    fs.writeFileSync(PASSWORDS_FILE, JSON.stringify(initial, null, 2), "utf-8");
  }
}

function loadPasswords() {
  ensurePasswordsFile();
  let parsed = {};
  try {
    parsed = JSON.parse(fs.readFileSync(PASSWORDS_FILE, "utf-8"));
  } catch {
    parsed = {};
  }

  // Backward compatible if older format stored strings
  const out = {};
  for (const id of FIELD_IDS) {
    const v = parsed[id];
    if (typeof v === "string") out[id] = { hash: v, unlocked: false };
    else if (v && typeof v === "object") out[id] = { hash: v.hash || "", unlocked: !!v.unlocked };
    else out[id] = { hash: "", unlocked: false };
  }
  return out;
}

function savePasswords(passwords) {
  fs.writeFileSync(PASSWORDS_FILE, JSON.stringify(passwords, null, 2), "utf-8");
}

// ---------- Basic Auth ----------
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
    return res.status(401).send("Unauthorized");
  }
  next();
}

// ---------- Public static ----------
const publicDir = path.join(__dirname, "public");

// IMPORTANT: protect admin page/routes BEFORE static
app.get("/admin", requireAdmin, (req, res) => res.sendFile(path.join(publicDir, "admin.html")));
app.get("/admin.js", requireAdmin, (req, res) => res.sendFile(path.join(publicDir, "admin.js")));
app.get("/admin.html", requireAdmin, (req, res) => res.sendFile(path.join(publicDir, "admin.html")));

app.use(express.static(publicDir));

app.get("/", (req, res) => {
  res.sendFile(path.join(publicDir, "index.html"));
});

// ---------- Public API ----------
app.get("/api/status", (req, res) => {
  const passwords = loadPasswords();
  const status = {};
  for (const id of FIELD_IDS) status[id] = !!passwords[id].unlocked;
  res.json({ ok: true, status });
});

app.post("/api/verify", async (req, res) => {
  const { fieldId, password } = req.body || {};
  if (!FIELD_IDS.includes(fieldId)) return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  if (typeof password !== "string") return res.status(400).json({ ok: false, error: "Invalid password" });

  const passwordsDb = loadPasswords();
  const entry = passwordsDb[fieldId];
  if (!entry.hash) return res.json({ ok: false });

  const match = await bcrypt.compare(password, entry.hash);
  if (!match) return res.json({ ok: false });

  // Persist unlocked across sessions until admin resets
  if (!passwordsDb[fieldId].unlocked) {
    passwordsDb[fieldId].unlocked = true;
    savePasswords(passwordsDb);
    appendAudit("VERIFY_UNLOCK", { fieldId, ip: req.ip });
  }

  res.json({ ok: true });
});

// ---------- Admin API (JSON, protected) ----------
app.get("/api/admin/state", requireAdmin, (req, res) => {
  const passwords = loadPasswords();
  const state = {};
  for (const id of FIELD_IDS) {
    state[id] = { hasPassword: !!passwords[id].hash, unlocked: !!passwords[id].unlocked };
  }
  res.json({ ok: true, state });
});

app.post("/api/admin/set", requireAdmin, async (req, res) => {
  const { fieldId, password } = req.body || {};
  if (!FIELD_IDS.includes(fieldId)) return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  if (typeof password !== "string" || !password.trim())
    return res.status(400).json({ ok: false, error: "Password required" });

  const passwordsDb = loadPasswords();
  const hash = await bcrypt.hash(password, 10);

  // Setting a password locks the field again (makes sense for new password)
  passwordsDb[fieldId] = { hash, unlocked: false };
  savePasswords(passwordsDb);

  appendAudit("ADMIN_SET_PASSWORD", { fieldId, ip: req.ip });
  res.json({ ok: true });
});

app.post("/api/admin/reset", requireAdmin, (req, res) => {
  const { fieldId } = req.body || {};
  const passwordsDb = loadPasswords();

  if (fieldId === "all") {
    for (const id of FIELD_IDS) passwordsDb[id].unlocked = false;
    savePasswords(passwordsDb);
    appendAudit("ADMIN_RESET_ALL", { ip: req.ip });
    return res.json({ ok: true });
  }

  if (!FIELD_IDS.includes(fieldId)) return res.status(400).json({ ok: false, error: "Invalid fieldId" });
  passwordsDb[fieldId].unlocked = false;
  savePasswords(passwordsDb);

  appendAudit("ADMIN_RESET_ONE", { fieldId, ip: req.ip });
  res.json({ ok: true });
});

app.get("/api/admin/log", requireAdmin, (req, res) => {
  const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 200)));
  if (!fs.existsSync(AUDIT_LOG_FILE)) return res.json({ ok: true, lines: [] });

  const raw = fs.readFileSync(AUDIT_LOG_FILE, "utf-8").trim();
  const lines = raw ? raw.split("\n") : [];
  res.json({ ok: true, lines: lines.slice(Math.max(0, lines.length - limit)) });
});

// Fallback to index
app.get("*", (req, res) => res.sendFile(path.join(publicDir, "index.html")));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));