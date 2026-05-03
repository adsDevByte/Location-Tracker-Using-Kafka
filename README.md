
# 🚀 Live Location Tracker

A real-time multi-user location tracking application built with Node.js, Socket.IO, and Kafka — secured with a fully self-hosted OpenID Connect (OIDC) provider implementing the Authorization Code + PKCE flow.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Tech Stack](#tech-stack)
- [Setup Steps](#setup-steps)
- [Environment Variables](#environment-variables)
- [OIDC Auth Setup](#oidc-auth-setup)
- [Socket Event Flow](#socket-event-flow)
- [Kafka Event Flow](#kafka-event-flow)
- [Assumptions and Limitations](#assumptions-and-limitations)

---

## Project Overview

Live Location Tracker lets multiple authenticated users share their GPS coordinates on a shared map in real time. Each user's browser emits location updates via Socket.IO; the server publishes these to a Kafka topic; a consumer broadcasts them back to all connected clients, rendering live-updating markers on a Leaflet map.

Authentication is handled entirely by a self-hosted OIDC provider (also included in this repo) rather than a third-party service like Auth0 or Google. The provider issues RS256-signed JWTs that the main app verifies using the provider's public JWKS endpoint — no shared secret required between the two servers.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 18+ |
| Web framework | Express 4 |
| Real-time transport | Socket.IO 4 |
| Message broker | Apache Kafka (KRaft mode, no Zookeeper) |
| Auth protocol | OpenID Connect 1.0 — Authorization Code + PKCE |
| Token format | JWT (RS256, verified via JWKS) |
| Map rendering | Leaflet + OpenStreetMap tiles |
| Containerisation | Docker (Kafka only) |

---

## Setup Steps

### Prerequisites

- Node.js 18 or later
- Docker (for Kafka)
- npm

### 1. Clone and install

```bash
git clone <your-repo-url>
cd location-tracking-app
npm install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env as needed — defaults work for local development
```

### 3. Start Kafka

```bash
docker run -d --name kafka \
  -p 9092:9092 \
  -e KAFKA_CFG_NODE_ID=1 \
  -e KAFKA_CFG_PROCESS_ROLES=broker,controller \
  -e KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
  -e KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
  -e KAFKA_CFG_ADVERTISED_LISTENERS=PLAINTEXT://localhost:9092 \
  -e KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER \
  -e ALLOW_PLAINTEXT_LISTENER=yes \
  bitnami/kafka:3.7
```

Wait ~10 seconds for Kafka to finish initialising before starting the app.

### 4. Start the OIDC provider

```bash
# Terminal 1
node oidc-provider/index.js
# → 🔐 OIDC Provider running at http://localhost:4000
```

### 5. Start the app server

```bash
# Terminal 2
node server/index.js
# → 🚀 App running at http://localhost:3000
```

### 6. Open the app

Navigate to **http://localhost:3000**, click **Sign in**, and use any demo credential:

| Username | Password |
|---|---|
| adarsh | pass123 |
| demo | demo123 |
| test | test123 |

### Running both servers together

```bash
npm install concurrently --save-dev
npm run dev   # starts OIDC provider + app server concurrently
```

> Kafka must still be started separately as it is a standalone service.

---

## Environment Variables

### App server (`server/index.js`)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Port the app server listens on |
| `APP_BASE_URL` | `http://localhost:3000` | Public base URL of the app — used to construct the OIDC redirect URI |
| `OIDC_ISSUER` | `http://localhost:4000` | Base URL of the OIDC provider |
| `OIDC_CLIENT_ID` | `location-app` | Client ID registered in the OIDC provider |
| `OIDC_CLIENT_SECRET` | `location-app-secret` | Client secret registered in the OIDC provider |
| `KAFKA_BROKER` | `localhost:9092` | Kafka broker address |

### OIDC provider (`oidc-provider/index.js`)

| Variable | Default | Description |
|---|---|---|
| `OIDC_PORT` | `4000` | Port the OIDC provider listens on |
| `OIDC_ISSUER` | `http://localhost:4000` | Issuer URL embedded in issued tokens — must match what the app server expects |
| `OIDC_CLIENT_SECRET` | `location-app-secret` | Overrides the hard-coded secret for the `location-app` client |

---

## OIDC Auth Setup

### How it works

This project ships its own OpenID Connect provider. It implements the **Authorization Code flow with PKCE (Proof Key for Code Exchange)** and signs tokens with an RSA-256 key pair generated fresh on each provider startup.

```
Browser         App Server (3000)        OIDC Provider (4000)
  │                    │                        │
  │  GET /login        │                        │
  │──────────────────► │                        │
  │                    │  generate PKCE pair    │
  │                    │  state, nonce          │
  │  redirect 302      │                        │
  │◄───────────────────│                        │
  │                                             │
  │  GET /authorize?code_challenge=...          │
  │────────────────────────────────────────────►│
  │                                             │  show login form
  │◄────────────────────────────────────────────│
  │  POST /authorize/submit (username+password) │
  │────────────────────────────────────────────►│
  │                                             │  issue auth code
  │  redirect to /callback?code=...&state=...   │
  │◄────────────────────────────────────────────│
  │                    │                        │
  │  GET /callback     │                        │
  │──────────────────► │                        │
  │                    │  POST /token           │
  │                    │  (code + code_verifier)│
  │                    │───────────────────────►│
  │                    │  { id_token,           │
  │                    │    access_token }      │
  │                    │◄───────────────────────│
  │                    │  verify id_token       │
  │                    │  via /jwks             │
  │  tokens stored in  │                        │
  │  localStorage      │                        │
  │◄───────────────────│                        │
```

### OIDC provider endpoints

| Endpoint | URL | Description |
|---|---|---|
| Discovery | `http://localhost:4000/.well-known/openid-configuration` | Lists all other endpoint URLs |
| Authorization | `http://localhost:4000/authorize` | Shows login form, issues auth code |
| Token | `http://localhost:4000/token` | Exchanges auth code for tokens |
| UserInfo | `http://localhost:4000/userinfo` | Returns profile claims for a Bearer token |
| JWKS | `http://localhost:4000/jwks` | Public RSA key set for token verification |
| Logout | `http://localhost:4000/logout` | Clears session and redirects |

### Token verification

The app server never shares a secret with the OIDC provider. Instead, it fetches the provider's public RSA key from `/jwks` on first use, caches it, and uses it to verify every incoming JWT with `jwt.verify()`. This means the same token can be trusted by any service that can reach the provider's JWKS endpoint.

### Adding a new client application

Edit the `CLIENTS` object in `oidc-provider/index.js`:

```js
"my-new-app": {
  clientSecret: "my-secret",
  redirectUris: ["http://localhost:5000/callback"],
  name: "My New App",
}
```

### Adding users

Edit the `USERS` object in `oidc-provider/index.js`:

```js
newuser: { password: "password123", name: "New User", email: "new@example.com" },
```

> In production, replace plain-text passwords with bcrypt hashes and load users from a database.

---

## Socket Event Flow

Socket.IO provides the real-time bidirectional channel between each browser and the app server. Every connection is authenticated before any events are processed.

### Authentication middleware

When a client connects, Socket.IO fires the `use` middleware before any events are accepted. The client supplies its OIDC access token in the handshake:

```js
// Client side
const socket = io({ auth: { token: localStorage.getItem("access_token") } });
```

The server middleware verifies the token against the OIDC provider's JWKS and attaches the decoded claims to the socket:

```
Client connects with { auth: { token } }
  └── server calls verifyToken(token)
        ├── fetches JWKS from http://localhost:4000/jwks
        ├── verifies RS256 signature, issuer, audience
        ├── attaches claims to socket.user
        └── next()  →  connection accepted
        OR
        └── next(new Error("Authentication failed"))  →  connection rejected
```

### Events

**Client → Server**

| Event | Payload | Description |
|---|---|---|
| `location:update` | `{ lat: number, lng: number }` | Emitted by the browser each time the Geolocation API fires a new position |

**Server → Client**

| Event | Payload | Description |
|---|---|---|
| `location:broadcast` | `{ userId, username, lat, lng, timestamp }` | Broadcast to all connected clients whenever a location update arrives from Kafka |

### Full flow

```
Browser (watchPosition fires)
  │
  │  emit("location:update", { lat, lng })
  ▼
App Server
  │  enriches with userId, username, timestamp
  │  producer.send → Kafka topic "location-updates"
  ▼
Kafka Consumer (same process)
  │  eachMessage handler fires
  │  io.emit("location:broadcast", event)
  ▼
All connected browsers
  └── update or create Leaflet marker for userId
```

---

## Kafka Event Flow

Kafka decouples the location ingestion path from the broadcast path. Even though the producer and consumer run in the same Node.js process, the architecture allows them to be split across multiple independent instances without any code changes.

### Topic

| Topic | Partitions | Description |
|---|---|---|
| `location-updates` | 1 | One message per user location update |

The topic is created automatically on startup via the Kafka Admin API if it does not already exist.

### Message format

Every message published to `location-updates` is a JSON string:

```json
{
  "userId": "adarsh",
  "username": "Adarsh",
  "lat": 19.076,
  "lng": 72.877,
  "timestamp": 1714500000000
}
```

### Producer

The Kafka producer is connected once at startup and reused for every `location:update` socket event. It uses the `LegacyPartitioner` to maintain compatibility with older Kafka setups.

### Consumer

The consumer subscribes to `location-updates` with `fromBeginning: true` so any backlog of events is replayed on restart. Each message is parsed and immediately broadcast to all connected Socket.IO clients via `io.emit`.

### Flow diagram

```
Socket.IO "location:update" event
  │
  ▼
producer.send({ topic: "location-updates", messages: [{ value: JSON }] })
  │
  ▼
Kafka broker  (localhost:9092)
  │
  ▼
consumer.run({ eachMessage })
  │
  ▼
io.emit("location:broadcast", event)  →  all connected browsers
```

---

## Assumptions and Limitations

### Assumptions

- The OIDC provider and app server run on the same machine during development. In production they would each have their own hostname, and `OIDC_ISSUER` / `APP_BASE_URL` would be updated accordingly.
- A single Kafka partition is sufficient for development and low-traffic use. For high-throughput deployments with many concurrent users, increase `numPartitions` and run multiple consumer instances.
- Geolocation permission is granted by the user's browser. The app does not handle the permission-denied case — the Geolocation API simply never fires.
- The Leaflet map is centred on India (`[20.5937, 78.9629]`) on load. This is a hard-coded default that should be made configurable or auto-detected from the user's own location.

### Limitations

- **In-memory state in the OIDC provider.** Auth codes, refresh tokens, and the user store are all held in memory. A process restart clears them entirely. Production deployments should persist these in Redis or a database.
- **Tokens stored in `localStorage`.** Acceptable for local development but vulnerable to XSS attacks in production. Tokens should be stored in `HttpOnly`, `Secure` cookies instead.
- **JWKS cache is never invalidated.** The provider generates a new RSA key pair on every restart. If the provider restarts while the app server is running, the cached public key goes stale and all token verifications will fail until the app server is also restarted. A production implementation should refresh the JWKS cache on a 401 verification failure.
- **No HTTPS.** All traffic is plain HTTP. Production deployments must terminate TLS in front of both servers.
- **Plain-text passwords.** The demo user store uses plain-text passwords for simplicity. Any real deployment must use bcrypt or Argon2 and load credentials from a secured store.
- **Single Kafka consumer group.** Running multiple instances of the app server under the same `groupId` means only one instance receives each Kafka message. To broadcast to all Socket.IO clients across multiple instances, pair this with a Redis adapter (`@socket.io/redis-adapter`) and publish from each instance independently.
- **No token refresh.** Access tokens expire after one hour and the client is not automatically refreshed. Users must log in again after expiry.
- **No rate limiting** on the `/login` route or the OIDC `/authorize/submit` endpoint, making brute-force attacks possible in a public deployment.



https://github.com/user-attachments/assets/2d026a98-6fa2-41f4-a919-e9ff511134aa

