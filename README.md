# MR ANON personal forwarding preference panel

A small Node.js + Express + SQLite app with a login-protected dashboard. It stores a personal call-forwarding preference and an audit log.

## Important limitations

- This app **does not activate or change carrier call forwarding**. The saved switch is only a preference. To actually forward calls, configure the feature in your carrier's official app/settings or integrate an authorized provider's documented API on the server.
- SMS forwarding and SMS/message-content access are not implemented. Use only a carrier feature intended for your own account; never forward private messages or verification codes to an untrusted destination.
- Do not use this app to monitor or forward anyone else's calls or messages.
- GitHub Pages cannot run this backend. Deploy to a Node.js host with HTTPS and persistent storage.

## Requirements

- Node.js 20 or newer
- npm

## Run locally

```sh
npm install
cp .env.example .env
npm run hash-password -- "choose-a-long-private-password"
```

Copy the printed bcrypt hash into `ADMIN_PASSWORD_HASH` in `.env`. Set a private username and generate a session secret:

```sh
node -e "console.log(require('node:crypto').randomBytes(48).toString('hex'))"
```

Put that value in `SESSION_SECRET`, then start the app:

```sh
npm start
```

Open <http://localhost:3000>. The SQLite database and sessions are created in `data/` and are excluded from Git. Keep that directory private and backed up. For a public deployment, set `NODE_ENV=production`, use HTTPS, use a unique secret/password, and make sure the host provides persistent storage.

## Project structure

```text
index.html             Dashboard and login UI
public/app.js          Frontend requests and interactions
server.js              Express API, authentication, sessions, validation
scripts/hash-password.js  Creates a bcrypt password hash
data/                  Created at runtime; SQLite database and sessions
.env                   Local secrets; do not commit
```

## API summary

- `GET /api/csrf` — obtain a session-bound CSRF token
- `POST /api/login` — authenticate with the server-configured username and bcrypt password hash
- `POST /api/logout` — end the session
- `GET /api/settings` — fetch saved call preference (authenticated)
- `PUT /api/settings/call` — save preference (authenticated, CSRF-protected)
- `GET /api/audit` — recent account activity (authenticated)

The app uses HttpOnly, SameSite session cookies, SQLite-backed sessions, bcrypt password verification, CSRF tokens, login rate limiting, input validation, and Helmet security headers. Before connecting any live telecom provider, review its official API documentation and privacy/security requirements; keep credentials server-side and implement only controls for your own verified account.
