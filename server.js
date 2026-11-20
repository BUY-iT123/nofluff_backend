const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const { OAuth2Client } = require("google-auth-library");
require("dotenv").config();

const app = express();
const port = Number(process.env.PORT) || 3000;
const mongoUri = process.env.MONGODB_URI;
const databaseName = process.env.MONGODB_DATABASE || "nofluff";
const model = process.env.GROQ_MODEL || "openai/gpt-oss-120b";
const maxWords = 500;
const perPersonLimit = 5;
const totalDailyLimit = 100;
const systemPrompt = fs.readFileSync(path.join(__dirname, "prompt.txt"), "utf8");

if (!mongoUri) {
  console.error("MONGODB_URI is missing. Add it to .env.");
  process.exit(1);
}

const allowedOrigins = (process.env.FRONTEND_URL || "http://localhost:5173")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json({ limit: "100kb" }));

const client = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 10000 });
const googleVerifier = new OAuth2Client();
let usageCollection;
let usersCollection;

function readSession(req) {
  const cookie = req.headers.cookie?.split(";").map((part) => part.trim()).find((part) => part.startsWith("nofluff_session="));
  return cookie ? decodeURIComponent(cookie.slice("nofluff_session=".length)) : "";
}

function signSession(userId) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error("SESSION_SECRET is not configured");
  const payload = Buffer.from(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 14 })).toString("base64url");
  const signature = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function verifySession(token) {
  const [payload, signature] = token.split(".");
  if (!payload || !signature || !process.env.SESSION_SECRET) return null;
  const expected = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(payload).digest();
  let supplied;
  try { supplied = Buffer.from(signature, "base64url"); } catch { return null; }
  if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return claims.sub && claims.exp > Math.floor(Date.now() / 1000) ? claims : null;
  } catch { return null; }
}

async function attachOptionalUser(req, _res, next) {
  const claims = verifySession(readSession(req));
  req.user = claims ? { id: claims.sub } : null;
  next();
}

function sessionCookieOptions() {
  return { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 14 * 24 * 60 * 60 * 1000 };
}

function currentDayKey() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Lagos",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date());
}

function personKey(req) {
  return `user_${req.user.id}`;
}

async function readUsage(day, key) {
  const record = await usageCollection.findOne({ _id: day });
  const usedByPerson = record?.people?.[key] || 0;
  const totalUsed = record?.total || 0;
  return {
    usedByPerson,
    totalUsed,
    remaining: Math.max(0, perPersonLimit - usedByPerson),
    totalRemaining: Math.max(0, totalDailyLimit - totalUsed),
  };
}

async function reserveUsage(day, key) {
  try {
    await usageCollection.updateOne(
      { _id: day },
      { $setOnInsert: { total: 0, people: {} } },
      { upsert: true },
    );
  } catch (error) {
    if (error.code !== 11000) throw error;
  }

  const personPath = `people.${key}`;
  const result = await usageCollection.updateOne(
    {
      _id: day,
      total: { $lt: totalDailyLimit },
      $or: [
        { [personPath]: { $exists: false } },
        { [personPath]: { $lt: perPersonLimit } },
      ],
    },
    { $inc: { total: 1, [personPath]: 1 } },
  );
  if (result.matchedCount === 0) return null;
  return readUsage(day, key);
}

async function releaseUsage(day, key) {
  const personPath = `people.${key}`;
  await usageCollection.updateOne(
    { _id: day, [personPath]: { $gt: 0 }, total: { $gt: 0 } },
    { $inc: { total: -1, [personPath]: -1 } },
  );
}

function parseModelOutput(raw) {
  const lines = raw.trim().split(/\r?\n/);
  const isCheckMarker = (line) => /^\s*[`*_~]*\s*-{2,}\s*CHECK\s*-{2,}\s*[`*_~]*\s*$/i.test(line);
  const marker = lines.findIndex(isCheckMarker);
  let rewriteLines = lines;
  let checkLines = [];

  if (marker >= 0) {
    rewriteLines = lines.slice(0, marker);
    checkLines = lines.slice(marker + 1);
  } else {
    const inlineMarker = /-{2,}\s*CHECK\s*-{2,}/i.exec(raw);
    if (inlineMarker) {
      rewriteLines = raw.slice(0, inlineMarker.index).split(/\r?\n/);
      checkLines = raw.slice(inlineMarker.index + inlineMarker[0].length).split(/\r?\n/);
    }
  }

  const rewrite = rewriteLines.join("\n").trim().replace(/\s*—\s*/g, ", ");
  const checks = checkLines.map((line) => line.trim()).filter(Boolean);
  return { rewrite, checks };
}

app.get("/", (_req, res) => {
  res.json({ name: "NoFluff API", status: "running", database: "connected" });
});

app.post("/api/auth/google", async (req, res) => {
  const credential = typeof req.body?.credential === "string" ? req.body.credential : "";
  const googleClientId = process.env.GOOGLE_CLIENT_ID;
  if (!googleClientId || !process.env.SESSION_SECRET) {
    return res.status(503).json({ error: "Google sign-in is not configured yet. Add GOOGLE_CLIENT_ID and SESSION_SECRET to the backend .env file." });
  }
  if (!credential) return res.status(400).json({ error: "Google sign-in did not return a credential. Please try again." });

  try {
    let identity;
    try {
      const ticket = await googleVerifier.verifyIdToken({ idToken: credential, audience: googleClientId });
      identity = ticket.getPayload();
    } catch {
      return res.status(401).json({ error: "Google could not verify this sign-in. Please try again." });
    }
    if (!identity || identity.email_verified !== true || !identity.sub || !identity.email) {
      return res.status(401).json({ error: "Google could not verify this sign-in. Please try again." });
    }

    const now = new Date();
    const user = await usersCollection.findOneAndUpdate(
      { googleId: identity.sub },
      {
        $set: { email: identity.email, name: identity.name || identity.email.split("@")[0], picture: identity.picture || "", updatedAt: now },
        $setOnInsert: { googleId: identity.sub, createdAt: now },
      },
      { upsert: true, returnDocument: "after", includeResultMetadata: false },
    );
    const session = signSession(user._id.toString());
    res.cookie("nofluff_session", session, sessionCookieOptions());
    return res.json({ user: { id: user._id.toString(), email: user.email, name: user.name, picture: user.picture } });
  } catch (error) {
    console.error("Google sign-in failed:", error.name, error.code || "");
    return res.status(502).json({ error: "Google sign-in could not be completed. Please try again." });
  }
});

app.use(attachOptionalUser);

app.get("/api/auth/me", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "You are not signed in." });
  try {
    const user = await usersCollection.findOne({ _id: new ObjectId(req.user.id) }, { projection: { email: 1, name: 1, picture: 1 } });
    if (!user) return res.status(401).json({ error: "Your sign-in has expired. Please sign in again." });
    return res.json({ user: { id: user._id.toString(), email: user.email, name: user.name, picture: user.picture } });
  } catch (error) {
    console.error("Could not read signed-in user:", error.name);
    return res.status(503).json({ error: "NoFluff is temporarily unavailable. Please try again." });
  }
});

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie("nofluff_session", sessionCookieOptions());
  res.json({ ok: true });
});

app.get("/api/usage", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Sign in with Google to use your daily rewrite requests." });
  try {
    const usage = await readUsage(currentDayKey(), personKey(req));
    res.json(usage);
  } catch (error) {
    console.error("Could not read usage counters:", error.name);
    res.status(503).json({ error: "NoFluff is temporarily unavailable. Please try again." });
  }
});

app.post("/api/rewrite", async (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Sign in with Google to use your daily rewrite requests." });
  const text = typeof req.body?.text === "string" ? req.body.text.trim() : "";
  if (!text) return res.status(400).json({ error: "Please paste some text first." });

  const wordCount = text.split(/\s+/u).filter(Boolean).length;
  if (wordCount > maxWords) {
    return res.status(400).json({ error: `Please keep it to ${maxWords} words or fewer.` });
  }
  if (!process.env.GROQ_API_KEY) {
    return res.status(503).json({ error: "Groq is not configured yet. Add GROQ_API_KEY to .env." });
  }

  const day = currentDayKey();
  const key = personKey(req);
  let reserved = false;
  try {
    const usage = await reserveUsage(day, key);
    if (!usage) {
      const current = await readUsage(day, key);
      if (current.totalUsed >= totalDailyLimit) {
        return res.status(429).json({ error: "NoFluff has reached today's total limit. Please try again tomorrow." });
      }
      return res.status(429).json({ error: "You've used today's 5 requests. They reset tomorrow." });
    }
    reserved = true;

    const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
      },
      body: JSON.stringify({
        model,
        temperature: 0.3,
        max_completion_tokens: 1600,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: text },
        ],
      }),
      signal: AbortSignal.timeout(45000),
    });

    if (!response.ok) {
      console.error("Groq request failed with HTTP status:", response.status);
      await releaseUsage(day, key);
      reserved = false;
      const status = response.status === 429 ? 429 : response.status === 401 ? 503 : 502;
      const error = response.status === 429
        ? "Groq is busy or its current limit was reached. Please try again shortly."
        : response.status === 401
          ? "NoFluff's Groq API key was rejected. Check GROQ_API_KEY in the backend .env file."
          : "NoFluff couldn't finish that rewrite. Please try again.";
      return res.status(status).json({ error });
    }

    const data = await response.json();
    const tokenUsage = {
      promptTokens: data.usage?.prompt_tokens ?? 0,
      completionTokens: data.usage?.completion_tokens ?? 0,
      totalTokens: data.usage?.total_tokens ?? 0,
    };
    console.log("Groq token usage:", JSON.stringify({ model, ...tokenUsage }));

    const raw = data.choices?.[0]?.message?.content;
    if (typeof raw !== "string" || !raw.trim()) {
      return res.status(502).json({ error: "No rewrite came back. Please try again." });
    }

    const parsed = parseModelOutput(raw);
    if (!parsed.rewrite) {
      return res.status(502).json({ error: "No rewrite came back. Please try again." });
    }

    const latestUsage = await readUsage(day, key);
    return res.json({ result: parsed.rewrite, checks: parsed.checks, ...tokenUsage, remaining: latestUsage.remaining, totalRemaining: latestUsage.totalRemaining });
  } catch (error) {
    if (reserved) await releaseUsage(day, key).catch(() => {});
    console.error("Rewrite request failed:", error.name, error.code || "");
    return res.status(502).json({ error: "NoFluff couldn't finish that rewrite. Please try again." });
  }
});

async function start() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  usageCollection = client.db(databaseName).collection("daily_usage");
  usersCollection = client.db(databaseName).collection("users");
  await usersCollection.createIndex({ googleId: 1 }, { unique: true, partialFilterExpression: { googleId: { $type: "string" } } });
  app.listen(port, "0.0.0.0", () => {
    console.log(`NoFluff local API listening on http://127.0.0.1:${port}; MongoDB connected.`);
  });
}

async function shutdown() {
  await client.close();
  process.exit(0);
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

start().catch(async (error) => {
  console.error("Could not connect to MongoDB. Check the URI, database user, and Atlas network access.");
  console.error(error.name, error.code || "");
  await client.close().catch(() => {});
  process.exit(1);
});



