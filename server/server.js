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

// Admin auth (unchanged)
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "change-this";

const PASSWORD_FILE = path.join(__dirname, "passwords.json");

/* ============================================================================
   CHANGE 1: Cross-device "solved state" storage (NOT passwords)
   - Adds solved.json support so a correct entry stays solved across devices.
   - If you want to remove this feature later:
     - Delete SOLVED_FILE + readSolved/writeSolved functions
     - Delete GET /api/solved route
     - Delete the "if (ok) { ... }" block in POST /api/verify
     - Delete the solved-clearing lines in admin clear routes (CHANGE 3)
============================================================================ */
const SOLVED_FILE = path.join(__dirname, "solved.json");

function readSolved() {
  try {
    return JSON.parse(fs.readFileSync(SOLVED_FILE, "utf8"));
  } catch {
    return {};
  }
}

function writeSolved(data) {
  fs.writeFileSync(SOLVED_FILE, JSON.stringify(data, null, 2), "utf8");
}
// ============================================================================

/* ============================================================================
   CHANGE 4: Log ALL password entry attempts (success + fail) to attemps.log
   - Writes one JSON line per attempt (JSONL) into attemps.log (same folder as server.js)
   - Note: On Render, file storage resets on redeploy unless you attach a Disk.
============================================================================ */
const ATTEMPTS_FILE = "/data/attemps.log";

function getClientIp(req) {
  // Works behind proxies like Render
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress || null;
}

function logAttempt({ fieldId, value, ok, req }) {
  const entry = {
    time: new Date().toISOString(),
    fieldId,
    ok,
    valueEntered: value,
    ip: getClientIp(req),
    userAgent: req.headers["user-agent"] || null
  };

  fs.appendFileSync(ATTEMPTS_FILE, JSON.stringify(entry) + "\n", "utf8");
}
// ============================================================================

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

/* ============================================================================
   CHANGE 2: Endpoint for cross-device solved status
   - Frontend calls this on load to mark fields as already solved.
============================================================================ */
app.get("/api/solved", (req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.set("Pragma", "no-cache");
  res.set("Expires", "0");
  res.json(readSolved());
});
// ============================================================================

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

    // CHANGE 4: Log ALL attempts (successful + failed)
    logAttempt({ fieldId, value, ok, req });

    /* ============================================================================
       CHANGE 2 (continued): When correct, mark field as solved in solved.json
       - This is what makes "correct entries stick" across devices.
    ============================================================================ */
    if (ok) {
      const solved = readSolved();
      solved[fieldId] = true;
      writeSolved(solved);
    }
    // ============================================================================

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

  /* ============================================================================
     CHANGE 3: Keep solved.json consistent with admin changes
     - If an admin clears a field password, also mark that field as NOT solved.
  ============================================================================ */
  const solved = readSolved();
  delete solved[fieldId];
  writeSolved(solved);
  // ============================================================================

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

  /* ============================================================================
     CHANGE 3 (continued): If admin clears all passwords, clear solved.json too
  ============================================================================ */
  writeSolved({});
  // ============================================================================

  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});