# Work Pro Backend API

Pi Network Freelance Marketplace — Backend Server

## Environment Variables

Copy this to `.env` and fill in your values:

```env
PORT=3000
PI_API_KEY=your_pi_api_key_here
ADMIN_API_KEY=your_random_admin_key_here
FRONTEND_URL=https://cherry19899.github.io
NODE_ENV=production
```

⚠️ **Never commit `.env` to GitHub.**

## Quick Start

```bash
npm install
npm start
```

## Health Check

```bash
curl https://workpro-api.onrender.com/health
```

## Pi Network Payment Flow

1. Frontend calls `Pi.createPayment()`
2. `onReadyForServerApproval` → `POST /api/payments/:id/approve`
3. User confirms in Pi Wallet
4. `onReadyForServerCompletion` → `POST /api/payments/:id/complete` (with txid)
5. If timeout occurs, frontend calls `onIncompletePaymentFound` → `POST /api/payments/incomplete`

## Admin Endpoints (require `Authorization: Bearer <ADMIN_API_KEY>`)

- `GET /api/admin/stats`
- `GET /api/admin/users`
- `GET /api/admin/jobs/all`
- `GET /api/admin/escrows`
- `GET /api/admin/earnings`

## Tech Stack

- Node.js + Express
- SQLite3 (WAL mode enabled)
- node-fetch v2
- CORS + Security headers

## License

MIT
