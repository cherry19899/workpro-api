# Work Pro Backend — Deploy to Render

## Quick Deploy

1. Go to https://dashboard.render.com
2. Click **New +** → **Web Service**
3. Connect your GitHub repo or use **Public Git repository**
4. Enter: `https://github.com/cherry19899/workpro-api`
5. Configure:
   - **Name**: `workpro-api`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node server.js`
6. Click **Environment** → add variables:
   - `PI_API_KEY` = your key from develop.pinet.com
   - `ADMIN_API_KEY` = generate a strong random secret (for /api/admin/* protection)
   - `NODE_ENV` = `production`
   - `FRONTEND_URL` = `https://cherry19899.github.io`
7. Click **Create Web Service**

Your backend will be at: `https://workpro-api.onrender.com`

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PI_API_KEY` | Yes | Pi Network API key from develop.pinet.com |
| `ADMIN_API_KEY` | Yes | Secret token for admin endpoints (Bearer auth) |
| `NODE_ENV` | No | `development` or `production` (default: development) |
| `FRONTEND_URL` | No | Frontend URL for CORS (default: https://cherry19899.github.io) |

## Security Features

- **Rate limiting**: 100 requests/minute per IP
- **Admin endpoints protected**: All `/api/admin/*` routes require `Authorization: Bearer <ADMIN_API_KEY>` header
- **Payment verification**: All payment callbacks verify payment status with Pi Network API
- **TXID validation**: 64-character hex format enforced
- **CORS**: Localhost origins only in development mode

## API Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/payments/:id/approve` | Approve Pi payment | None |
| POST | `/api/payments/:id/complete` | Complete Pi payment | None |
| POST | `/api/payments/:id/cancelled` | Cancel payment (verified) | None |
| GET | `/api/payments/:id` | Check payment status | None |
| POST | `/api/connects/buy` | Buy connects | None |
| POST | `/api/users/:id/balance` | Update balance | None |
| GET | `/api/users/:id` | Get user data | None |
| GET | `/api/admin/stats` | Admin statistics | Admin API Key |
| GET | `/api/admin/users` | List all users | Admin API Key |
| GET | `/api/admin/jobs/all` | List all jobs | Admin API Key |
| GET | `/api/admin/earnings` | Payment earnings | Admin API Key |
| GET | `/api/admin/escrows` | List all escrows | Admin API Key |
Thu May  7 01:10:44 CST 2026
