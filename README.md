# Work Pro Backend — Deploy to Render

## Quick Deploy

1. Go to https://dashboard.render.com
2. Click **New +** → **Web Service**
3. Connect your GitHub repo or use **Public Git repository**
4. Enter: `https://github.com/cherry19899/cherry19899.github.io`
5. Configure:
   - **Name**: `workpro-api`
   - **Environment**: `Node`
   - **Build Command**: `cd backend && npm install`
   - **Start Command**: `cd backend && node server.js`
6. Click **Environment** → add variable:
   - `PI_API_KEY` = your key from develop.pinet.com
7. Click **Create Web Service**

Your backend will be at: `https://workpro-api.onrender.com`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/payments/:id/approve` | Approve Pi payment |
| POST | `/api/payments/:id/complete` | Complete Pi payment |
| GET | `/api/payments/:id` | Check payment status |
| POST | `/api/connects/buy` | Buy connects |
| POST | `/api/users/:id/balance` | Update balance |
| GET | `/api/users/:id` | Get user data |
