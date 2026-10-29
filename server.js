import express from "express";
import crypto from "node:crypto";
import { HoodPrivate, HoodPrivateAPIError } from "@hoodprivate/sdk";

const { HOODPRIVATE_API_KEY, APP_PASSWORD, SESSION_SECRET } = process.env;
if (!HOODPRIVATE_API_KEY || !APP_PASSWORD || !SESSION_SECRET)
  throw new Error("Set HOODPRIVATE_API_KEY, APP_PASSWORD and SESSION_SECRET in .env");
const hc = new HoodPrivate({ apiKey: HOODPRIVATE_API_KEY });
const app = express();
app.set("trust proxy", 1);

// ---------- webhook (raw body, registered BEFORE express.json) ----------
const events = []; // in-memory; use a database in production
app.post("/webhooks/hoodprivate", express.raw({ type: "*/*", limit: "100kb" }), async (req, res) => {
  try {
    const valid = await hc.webhooks.verifySignature({
      payload: req.body.toString("utf8"),
      signature: req.headers["x-hoodprivate-signature"],
      secret: process.env.HOODPRIVATE_WEBHOOK_SECRET,
    });
    if (!valid) return res.sendStatus(401);
    const e = JSON.parse(req.body.toString("utf8"));
    events.unshift({ at: Date.now(), type: e.type, id: e.data?.id, status: e.data?.status, txHash: e.data?.txHash });
    events.length = Math.min(events.length, 200);
    res.sendStatus(200);
  } catch { res.sendStatus(400); }
});

app.use(express.json({ limit: "2kb" }));
app.use(express.static("public"));

// ---------- rate limit ----------
const hits = new Map();
app.use("/api", (req, res, next) => {
  const now = Date.now();
  const r = (hits.get(req.ip) || []).filter((t) => now - t < 60_000);
  if (r.length >= 20) return res.status(429).json({ error: "Too many requests" });
  hits.set(req.ip, [...r, now]);
  next();
});

// ---------- auth: single operator password + signed cookie ----------
const sign = (v) => crypto.createHmac("sha256", SESSION_SECRET).update(v).digest("hex");
const eq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const cookie = (req, n) => (req.headers.cookie || "").split("; ").find((c) => c.startsWith(n + "="))?.slice(n.length + 1);
const authed = (req) => { const c = cookie(req, "s"); if (!c) return false; const [exp, mac] = c.split("."); return Number(exp) > Date.now() && mac && eq(mac, sign(exp)); };
const requireAuth = (req, res, next) => (authed(req) ? next() : res.status(401).json({ error: "Login required" }));

app.post("/api/login", (req, res) => {
  const pw = String(req.body?.password ?? "");
  if (!eq(sign(pw), sign(APP_PASSWORD))) return res.status(401).json({ error: "Wrong password" });
  const exp = String(Date.now() + 8 * 3600_000);
  res.setHeader("Set-Cookie", `s=${exp}.${sign(exp)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.NODE_ENV === "production" ? "; Secure" : ""}`);
  res.json({ ok: true });
});
app.get("/api/me", (req, res) => res.json({ authed: authed(req) }));

// ---------- transfers ----------
const TO = /^(@[a-z0-9_.-]{1,32}|0x[a-fA-F0-9]{40})$/;
const AMOUNT = /^\d{1,9}(\.\d{1,6})?$/;

app.post("/api/transfer", requireAuth, async (req, res) => {
  const { to, amount } = req.body ?? {};
  if (!TO.test(to ?? "")) return res.status(400).json({ error: "Invalid recipient" });
  if (!AMOUNT.test(amount ?? "") || Number(amount) <= 0) return res.status(400).json({ error: "Invalid amount" });
  try {
    const t = await hc.transfers.create({ to, amount });
    res.json({ status: t.status, txHash: t.txHash });
  } catch (e) {
    if (e instanceof HoodPrivateAPIError) return res.status(502).json({ error: "Transfer rejected by provider" });
    console.error(e); res.status(500).json({ error: "Server error" });
  }
});

// Status view: provider's transfer list + latest webhook events
app.get("/api/transfers", requireAuth, async (_req, res) => {
  try { res.json({ transfers: await hc.transfers.list(), events: events.slice(0, 20) }); }
  catch { res.json({ transfers: null, events: events.slice(0, 20) }); }
});

app.listen(process.env.PORT || 3000, () => console.log("http://localhost:3000"));
