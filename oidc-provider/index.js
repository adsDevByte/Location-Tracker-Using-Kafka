/**
 * Own OIDC Provider
 * Implements core OpenID Connect / OAuth2 Authorization Code Flow.
 * Supports user registration (sign-up) in addition to login.
 */

const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.OIDC_PORT || 4000;
const ISSUER = process.env.OIDC_ISSUER || `http://localhost:${PORT}`;

// RSA key pair for signing ID tokens
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const pubKeyObj = crypto.createPublicKey(publicKey);
const jwkPublic = pubKeyObj.export({ format: "jwk" });
const KEY_ID = crypto.randomBytes(8).toString("hex");

// ─── Stores ───────────────────────────────────────────────────────────────────

const CLIENTS = {
  "location-app": {
    clientSecret: process.env.OIDC_CLIENT_SECRET || "location-app-secret",
    redirectUris: ["http://localhost:3000/callback", "http://127.0.0.1:3000/callback"],
    name: "Live Tracker",
  },
};

function hashPassword(plain) {
  return crypto.createHash("sha256").update(plain).digest("hex");
}

// Users stored as { username -> { passwordHash, name, email, createdAt } }
const USERS = {
  adarsh: { passwordHash: hashPassword("pass123"), name: "Adarsh", email: "adarsh@example.com", createdAt: new Date().toISOString() },
  demo:   { passwordHash: hashPassword("demo123"), name: "Demo User", email: "demo@example.com", createdAt: new Date().toISOString() },
};

const authCodes    = new Map();
const refreshTokens = new Map();

// ─── Helpers ──────────────────────────────────────────────────────────────────

const generateCode  = () => crypto.randomBytes(32).toString("base64url");
const generateToken = () => crypto.randomBytes(40).toString("base64url");
const signIdToken   = (p) => jwt.sign(p, privateKey, { algorithm: "RS256", keyid: KEY_ID });
const signAccessToken = (p) => jwt.sign(p, privateKey, { algorithm: "RS256", keyid: KEY_ID, expiresIn: "1h" });
const verifyAccessToken = (t) => jwt.verify(t, publicKey, { algorithms: ["RS256"] });

function verifyPKCE(codeVerifier, codeChallenge, method) {
  if (method === "S256") {
    return crypto.createHash("sha256").update(codeVerifier).digest("base64url") === codeChallenge;
  }
  return codeVerifier === codeChallenge;
}

// ─── Shared page template ─────────────────────────────────────────────────────

function renderPage({ clientName, loginError, regError, registered, hiddenFields, prefillUsername }) {
  const showReg = !!(regError || registered);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Sign In — ${clientName}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);min-height:100vh;display:flex;align-items:center;justify-content:center}
    .card{background:rgba(255,255,255,.05);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,.1);border-radius:20px;padding:44px 38px;width:100%;max-width:420px;box-shadow:0 25px 50px rgba(0,0,0,.4)}
    .badge{text-align:center;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:rgba(255,255,255,.4);margin-bottom:6px}
    .appname{text-align:center;font-size:22px;font-weight:700;color:#fff;margin-bottom:4px}
    .subtitle{text-align:center;color:rgba(255,255,255,.45);font-size:14px;margin-bottom:24px}
    .tabs{display:flex;background:rgba(255,255,255,.06);border-radius:10px;padding:4px;gap:4px;margin-bottom:24px}
    .tab{flex:1;padding:9px;border:none;border-radius:7px;background:transparent;color:rgba(255,255,255,.5);font-size:14px;font-weight:500;cursor:pointer;transition:.2s}
    .tab.active{background:rgba(79,142,247,.25);color:#fff}
    .section{display:none}.section.on{display:block}
    label{display:block;color:rgba(255,255,255,.7);font-size:13px;font-weight:500;margin-bottom:5px}
    input{width:100%;padding:11px 15px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);border-radius:10px;color:#fff;font-size:15px;margin-bottom:16px;outline:none;transition:border-color .2s}
    input:focus{border-color:#4f8ef7}
    input::placeholder{color:rgba(255,255,255,.3)}
    .err{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:#fca5a5;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:16px}
    .ok{background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);color:#86efac;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:16px}
    button[type=submit]{width:100%;padding:13px;background:linear-gradient(135deg,#4f8ef7,#7c3aed);border:none;border-radius:10px;color:#fff;font-size:16px;font-weight:600;cursor:pointer;transition:opacity .2s}
    button[type=submit]:hover{opacity:.88}
    .hint{text-align:center;color:rgba(255,255,255,.28);font-size:12px;margin-top:16px}
  </style>
</head>
<body>
<div class="card">
  <div class="badge">Your OIDC Provider</div>
  <div class="appname">🚀 ${clientName}</div>
  <p class="subtitle">Sign in or create an account</p>

  <div class="tabs">
    <button class="tab ${!showReg ? "active" : ""}" data-t="login">Sign In</button>
    <button class="tab ${showReg ? "active" : ""}"  data-t="reg">Create Account</button>
  </div>

  <!-- LOGIN -->
  <div id="login" class="section ${!showReg ? "on" : ""}">
    ${loginError ? `<div class="err">⚠️ ${loginError}</div>` : ""}
    <form method="POST" action="/authorize/submit">
      ${hiddenFields}
      <label>Username</label>
      <input type="text" name="username" placeholder="e.g. adarsh" value="${prefillUsername || ""}" autocomplete="username" required/>
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" autocomplete="current-password" required/>
      <button type="submit">Sign In →</button>
    </form>
    <p class="hint">Don't have an account? Switch to Create Account above.</p>
  </div>

  <!-- REGISTER -->
  <div id="reg" class="section ${showReg ? "on" : ""}">
    ${regError  ? `<div class="err">⚠️ ${regError}</div>` : ""}
    ${registered ? `<div class="ok">✅ Account created! Switch to Sign In.</div>` : ""}
    <form method="POST" action="/authorize/register">
      ${hiddenFields}
      <label>Full Name</label>
      <input type="text" name="name" placeholder="Jane Smith" autocomplete="name" required/>
      <label>Email</label>
      <input type="email" name="email" placeholder="jane@example.com" autocomplete="email" required/>
      <label>Username</label>
      <input type="text" name="username" placeholder="janesmith" autocomplete="username" required/>
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" autocomplete="new-password" required/>
      <label>Confirm Password</label>
      <input type="password" name="confirm_password" placeholder="••••••••" autocomplete="new-password" required/>
      <button type="submit">Create Account →</button>
    </form>
  </div>
</div>
<script>
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.dataset.t;
      document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b === btn));
      document.querySelectorAll('.section').forEach(s => s.classList.toggle('on', s.id === t));
    });
  });
</script>
</body>
</html>`;
}

// ─── Discovery ────────────────────────────────────────────────────────────────

app.get("/.well-known/openid-configuration", (_req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    jwks_uri: `${ISSUER}/jwks`,
    end_session_endpoint: `${ISSUER}/logout`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "name", "email"],
    code_challenge_methods_supported: ["S256", "plain"],
    grant_types_supported: ["authorization_code", "refresh_token"],
  });
});

app.get("/jwks", (_req, res) => {
  res.json({ keys: [{ kty: jwkPublic.kty, use: "sig", alg: "RS256", kid: KEY_ID, n: jwkPublic.n, e: jwkPublic.e }] });
});

// ─── Authorize ────────────────────────────────────────────────────────────────

app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, nonce,
          code_challenge, code_challenge_method,
          error, reg_error, registered, prefill_username } = req.query;

  const client = CLIENTS[client_id];
  if (!client) return res.status(400).send("Unknown client_id");
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).send("Invalid redirect_uri");
  if (response_type !== "code") return res.redirect(`${redirect_uri}?error=unsupported_response_type&state=${state}`);

  const hiddenFields = `
    <input type="hidden" name="client_id"             value="${client_id}"/>
    <input type="hidden" name="redirect_uri"          value="${redirect_uri}"/>
    <input type="hidden" name="scope"                 value="${scope || "openid profile email"}"/>
    <input type="hidden" name="state"                 value="${state || ""}"/>
    <input type="hidden" name="nonce"                 value="${nonce || ""}"/>
    <input type="hidden" name="code_challenge"        value="${code_challenge || ""}"/>
    <input type="hidden" name="code_challenge_method" value="${code_challenge_method || ""}"/>
  `;

  const loginError = error === "invalid_credentials" ? "Invalid username or password."
                   : error ? error : "";

  const regErrorMap = {
    username_taken: "That username is already taken.",
    password_mismatch: "Passwords do not match.",
    missing_fields: "All fields are required.",
    username_invalid: "Username: 3–32 chars, letters/numbers/_ only.",
  };
  const regErrorMsg = regErrorMap[reg_error] || reg_error || "";

  res.send(renderPage({
    clientName: client.name,
    loginError,
    regError: regErrorMsg,
    registered: !!registered,
    hiddenFields,
    prefillUsername: prefill_username || "",
  }));
  console.log("Authorize request:", req.query); 
});

// ─── Login submit ─────────────────────────────────────────────────────────────

app.post("/authorize/submit", (req, res) => {
  const { client_id, redirect_uri, scope, state, nonce,
          code_challenge, code_challenge_method, username, password } = req.body;

  const client = CLIENTS[client_id];
  if (!client || !client.redirectUris.includes(redirect_uri)) return res.status(400).send("Invalid request");

  const user = USERS[username];
  if (!user || user.passwordHash !== hashPassword(password)) {
    const p = new URLSearchParams({ client_id, redirect_uri, scope: scope||"", state: state||"",
      nonce: nonce||"", code_challenge: code_challenge||"", response_type: "code",code_challenge_method: code_challenge_method||"",
      error: "invalid_credentials", prefill_username: username || "" });
    return res.redirect(`/authorize?${p}`);
  }

  const code = generateCode();
  authCodes.set(code, {
    clientId: client_id, userId: username, redirectUri: redirect_uri,
    nonce, scope: scope || "openid profile email",
    expiresAt: Date.now() + 60_000,
    codeChallenge: code_challenge || null, codeChallengeMethod: code_challenge_method || "S256",
  });

  const url = new URL(redirect_uri);
  url.searchParams.set("code", code);
  if (state) url.searchParams.set("state", state);
  res.redirect(url.toString());
});

// ─── Register submit ──────────────────────────────────────────────────────────

app.post("/authorize/register", (req, res) => {
  const { client_id, redirect_uri, scope, state, nonce,
          code_challenge, code_challenge_method,
          name, email, username, password, confirm_password } = req.body;

  const client = CLIENTS[client_id];
  if (!client || !client.redirectUris.includes(redirect_uri)) return res.status(400).send("Invalid request");

  const base = { client_id, redirect_uri, scope: scope||"", state: state||"",
                 nonce: nonce||"", code_challenge: code_challenge||"", code_challenge_method: code_challenge_method||"" , response_type: "code"};
  const redir = (reg_error) => res.redirect(`/authorize?${new URLSearchParams({ ...base, reg_error })}`);

  if (!name || !email || !username || !password || !confirm_password) return redir("missing_fields");
  if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) return redir("username_invalid");
  if (USERS[username]) return redir("username_taken");
  if (password !== confirm_password) return redir("password_mismatch");

  USERS[username] = {
    passwordHash: hashPassword(password),
    name: name.trim(),
    email: email.trim().toLowerCase(),
    createdAt: new Date().toISOString(),
  };
  console.log(`🆕 Registered: ${username} <${email}>`);

  res.redirect(`/authorize?${new URLSearchParams({ ...base, registered: "1" })}`);
});

// ─── Token endpoint ───────────────────────────────────────────────────────────

app.post("/token", (req, res) => {
  let clientId, clientSecret;
  const auth = req.headers.authorization;
  if (auth?.startsWith("Basic ")) {
    [clientId, clientSecret] = Buffer.from(auth.slice(6), "base64").toString().split(":");
  } else {
    clientId = req.body.client_id; clientSecret = req.body.client_secret;
  }

  const client = CLIENTS[clientId];
  if (!client || client.clientSecret !== clientSecret) return res.status(401).json({ error: "invalid_client" });

  const { grant_type, code, redirect_uri, code_verifier, refresh_token } = req.body;

  if (grant_type === "authorization_code") {
    const stored = authCodes.get(code);
    if (!stored) return res.status(400).json({ error: "invalid_grant" });
    if (stored.expiresAt < Date.now()) { authCodes.delete(code); return res.status(400).json({ error: "invalid_grant", error_description: "Code expired" }); }
    if (stored.clientId !== clientId || stored.redirectUri !== redirect_uri) return res.status(400).json({ error: "invalid_grant" });
    if (stored.codeChallenge) {
      if (!code_verifier) return res.status(400).json({ error: "invalid_grant", error_description: "code_verifier required" });
      if (!verifyPKCE(code_verifier, stored.codeChallenge, stored.codeChallengeMethod)) return res.status(400).json({ error: "invalid_grant", error_description: "PKCE failed" });
    }
    authCodes.delete(code);

    const user = USERS[stored.userId];
    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken({ iss: ISSUER, sub: stored.userId, aud: clientId, exp: now+3600, iat: now, nonce: stored.nonce||undefined, name: user.name, email: user.email });
    const accessToken = signAccessToken({ iss: ISSUER, sub: stored.userId, aud: clientId, scope: stored.scope });
    const rt = generateToken();
    refreshTokens.set(rt, { clientId, userId: stored.userId, scope: stored.scope });
    return res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, id_token: idToken, refresh_token: rt, scope: stored.scope });
  }

  if (grant_type === "refresh_token") {
    const stored = refreshTokens.get(refresh_token);
    if (!stored || stored.clientId !== clientId) return res.status(400).json({ error: "invalid_grant" });
    const user = USERS[stored.userId];
    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken({ iss: ISSUER, sub: stored.userId, aud: clientId, exp: now+3600, iat: now, name: user.name, email: user.email });
    const accessToken = signAccessToken({ iss: ISSUER, sub: stored.userId, aud: clientId, scope: stored.scope });
    return res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600, id_token: idToken, scope: stored.scope });
  }

  return res.status(400).json({ error: "unsupported_grant_type" });
});

// ─── UserInfo ─────────────────────────────────────────────────────────────────

app.get("/userinfo", (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "unauthorized" });
  try {
    const payload = verifyAccessToken(auth.slice(7));
    const user = USERS[payload.sub];
    if (!user) return res.status(404).json({ error: "user_not_found" });
    res.json({ sub: payload.sub, name: user.name, email: user.email });
  } catch { res.status(401).json({ error: "invalid_token" }); }
});

// ─── Logout ───────────────────────────────────────────────────────────────────

app.get("/logout", (req, res) => {
  const { post_logout_redirect_uri, state } = req.query;
  if (post_logout_redirect_uri) {
    const url = new URL(post_logout_redirect_uri);
    if (state) url.searchParams.set("state", state);
    return res.redirect(url.toString());
  }
  res.send("Logged out.");
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`🔐 OIDC Provider running at ${ISSUER}`);
  console.log(`   Discovery: ${ISSUER}/.well-known/openid-configuration`);
  console.log(`   Seeded users: adarsh (pass123), demo (demo123)`);
});
