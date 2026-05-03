/**
 * Location Tracking App — Main Server
 * Auth: OpenID Connect (Authorization Code + PKCE), validated against own OIDC Provider.
 */

const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");
const { Kafka, Partitioners } = require("kafkajs");

const PORT = process.env.PORT || 3000;
const KAFKA_BROKER = process.env.KAFKA_BROKER || "localhost:9092";

// ─── OIDC Config ──────────────────────────────────────────────────────────────

const OIDC_ISSUER = process.env.OIDC_ISSUER || "http://localhost:4000";
const OIDC_CLIENT_ID = process.env.OIDC_CLIENT_ID || "location-app";
const OIDC_CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET || "location-app-secret";
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${APP_BASE_URL}/callback`;

// In-memory PKCE state store: state → { codeVerifier, nonce }
const pendingAuth = new Map();

// Cached OIDC discovery + JWKS
let oidcDiscovery = null;
let jwksCache = null;

async function fetchDiscovery() {
  if (oidcDiscovery) return oidcDiscovery;
  const res = await fetch(`${OIDC_ISSUER}/.well-known/openid-configuration`);
  oidcDiscovery = await res.json();
  return oidcDiscovery;
}

async function fetchJWKS() {
  if (jwksCache) return jwksCache;
  const disc = await fetchDiscovery();
  const res = await fetch(disc.jwks_uri);
  jwksCache = await res.json();
  return jwksCache;
}

function jwkToPem(jwk) {
  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  return key.export({ type: "spki", format: "pem" });
}

async function verifyToken(token) {
  const jwks = await fetchJWKS();
  const header = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("No matching JWK for kid: " + header.kid);
  const pem = jwkToPem(jwk);
  return jwt.verify(token, pem, {
    algorithms: ["RS256"],
    issuer: OIDC_ISSUER,
    audience: OIDC_CLIENT_ID,
  });
}

// ─── Express + Socket.IO ──────────────────────────────────────────────────────

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.json());
app.use(express.static(path.join(__dirname, "../client")));

// ─── OIDC Routes ──────────────────────────────────────────────────────────────

app.get("/login", async (req, res) => {
  try {
    const disc = await fetchDiscovery();
    const codeVerifier = crypto.randomBytes(48).toString("base64url");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    const state = crypto.randomBytes(16).toString("base64url");
    const nonce = crypto.randomBytes(16).toString("base64url");

    pendingAuth.set(state, { codeVerifier, nonce });

    const authUrl = new URL(disc.authorization_endpoint);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", OIDC_CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
    authUrl.searchParams.set("scope", "openid profile email");
    authUrl.searchParams.set("state", state);
    authUrl.searchParams.set("nonce", nonce);
    authUrl.searchParams.set("code_challenge", codeChallenge);
    authUrl.searchParams.set("code_challenge_method", "S256");

    res.redirect(authUrl.toString());
  } catch (err) {
    console.error("Login redirect error:", err);
    res.status(500).send("OIDC provider unavailable. Is oidc-provider running on port 4000?");
  }
});

app.get("/callback", async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.status(400).send("OIDC Error: " + error);

  const pending = pendingAuth.get(state);
  if (!pending) return res.status(400).send("Invalid or expired state.");
  pendingAuth.delete(state);

  try {
    const disc = await fetchDiscovery();
    const tokenRes = await fetch(disc.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: OIDC_CLIENT_ID,
        client_secret: OIDC_CLIENT_SECRET,
        code_verifier: pending.codeVerifier,
      }),
    });

    const tokens = await tokenRes.json();
    if (tokens.error) return res.status(400).send("Token error: " + tokens.error);

    const claims = await verifyToken(tokens.id_token);

    res.send(`<!DOCTYPE html>
<html><head><title>Authenticated</title></head><body>
<script>
  localStorage.setItem("access_token", ${JSON.stringify(tokens.access_token)});
  localStorage.setItem("id_token", ${JSON.stringify(tokens.id_token)});
  localStorage.setItem("user", JSON.stringify({
    sub: ${JSON.stringify(claims.sub)},
    name: ${JSON.stringify(claims.name)},
    email: ${JSON.stringify(claims.email)}
  }));
  window.location.href = "/app.html";
</script>
</body></html>`);
  } catch (err) {
    console.error("Callback error:", err);
    res.status(500).send("Authentication failed: " + err.message);
  }
});

app.get("/logout", async (req, res) => {
  try {
    const disc = await fetchDiscovery();
    const logoutUrl = new URL(disc.end_session_endpoint);
    logoutUrl.searchParams.set("post_logout_redirect_uri", `${APP_BASE_URL}/`);

    // Serve a page that clears localStorage FIRST, then redirects to OIDC logout
    res.send(`<!DOCTYPE html>
<html><head><title>Logging out...</title></head><body>
<script>
  localStorage.removeItem("access_token");
  localStorage.removeItem("id_token");
  localStorage.removeItem("user");
  window.location.href = ${JSON.stringify(logoutUrl.toString())};
</script>
</body></html>`);
  } catch {
    res.send(`<!DOCTYPE html>
<html><head><title>Logging out...</title></head><body>
<script>
  localStorage.clear();
  window.location.href = "/";
</script>
</body></html>`);
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../client/index.html"));
});

// ─── Socket.IO — verify OIDC access token ────────────────────────────────────

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("No token provided"));
    const claims = await verifyToken(token);
    socket.user = { id: claims.sub, name: claims.name, email: claims.email };
    next();
  } catch (err) {
    next(new Error("Authentication failed: " + err.message));
  }
});

io.on("connection", (socket) => {
  console.log(`✅ Connected: ${socket.user.name} (${socket.user.id})`);

  socket.on("location:update", async (data) => {
    const event = {
      userId: socket.user.id,
      username: socket.user.name,
      lat: data.lat,
      lng: data.lng,
      timestamp: Date.now(),
    };
    console.log("📍 Kafka send:", event);
    await producer.send({
      topic: "location-updates",
      messages: [{ value: JSON.stringify(event) }],
    });
  });

  socket.on("disconnect", () => {
    console.log(`❌ Disconnected: ${socket.user.name}`);
  });
});

// ─── Kafka ────────────────────────────────────────────────────────────────────

const kafka = new Kafka({ clientId: "location-app", brokers: [KAFKA_BROKER] });
const producer = kafka.producer({ createPartitioner: Partitioners.LegacyPartitioner });
const consumer = kafka.consumer({ groupId: "socket-group" });

const startKafka = async () => {
  await producer.connect();
  await consumer.connect();
  const admin = kafka.admin();
  await admin.connect();
  await admin.createTopics({ topics: [{ topic: "location-updates", numPartitions: 1 }] });
  await admin.disconnect();
  await consumer.subscribe({ topic: "location-updates", fromBeginning: true });
  await consumer.run({
    eachMessage: async ({ message }) => {
      const event = JSON.parse(message.value.toString());
      console.log("📡 Broadcast:", event);
      io.emit("location:broadcast", event);
    },
  });
};

server.listen(PORT, async () => {
  console.log(`🚀 App running at ${APP_BASE_URL}`);
  await startKafka();
});

