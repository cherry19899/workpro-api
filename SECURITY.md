# WorkPro API — Security Hardening Documentation

## SQL Injection
All database queries use **parameterized statements** via `pg` library (`$1`, `$2`, …).  
No string concatenation is used for user input in SQL.

## XSS Protection
- **Backend**: `src/sanitize.js` strips HTML tags, encodes entities, and removes `javascript:` URIs from all user-supplied text (job titles, descriptions, proposals, chat messages, usernames) before insertion.
- **Frontend**: `DOMPurify` sanitizes all rendered HTML (chat messages, job descriptions) before insertion into the DOM.
- HTTP response headers include `X-XSS-Protection: 1; mode=block` and `X-Content-Type-Options: nosniff` via Helmet.

## CSRF
WorkPro is a **JWT-Bearer API** — credentials are sent in `Authorization: Bearer <token>` headers, not cookies, so traditional CSRF attacks do not apply. State-changing requests require a valid JWT.

## API Keys
- `JWT_SECRET`, `ADMIN_API_KEY`, `PI_API_KEY`, `DATABASE_URL`, `VAPID_*` are **environment variables only** — never hardcoded.
- Server refuses to start in production if `JWT_SECRET` or `ADMIN_API_KEY` are missing.
- Frontend bundle has no secrets; it talks to the backend via Bearer tokens.

## Rate Limiting (`express-rate-limit`)
| Endpoint group | Window | Max requests |
|---|---|---|
| Auth (`/api/me`, `/api/auth/*`) | 15 min | 20 per IP |
| Admin | 15 min | 100 per IP |
| Admin (strict) | 15 min | 50 per IP |
| Connects / Payments | 60 min | 20 per user |
| Chat messages | 1 min | 30 per IP |
| Job posting | 60 min | 10 per IP |

All limits are relaxed 10× in `SANDBOX_MODE` for development.

## JWT
- Tokens signed with `HS256`, secret minimum 64 random bytes.
- **Expiration**: 30 days (configurable via `JWT_EXPIRES_IN` env var).
- Admin role is **DB-verified** on every admin request — a tampered JWT claiming admin is rejected.
- GDPR deletion sets `status='deleted'` and blocks the account, invalidating future requests.

## Pi SDK Payment Validation
- Server calls Pi Platform API (`/payments/:id/approve` and `/payments/:id/complete`) to verify every payment.
- Replay attacks prevented by `idempotency_keys` table — duplicate payment IDs are rejected.
- `payment_id` ownership verified before approval.

## CORS
Restricted to: `https://cherry19899.github.io`, `http://localhost:3000`, `http://localhost:5173`.  
Credentials allowed only for listed origins.

## HTTPS / HSTS
In production: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

## Content Security Policy
Script sources restricted to `'self'` + Pi SDK CDN. Object sources blocked. Upgrade-insecure-requests in production.

## Admin Protection
Every `/api/admin/*` endpoint requires either:
1. A valid `ADMIN_API_KEY` in `x-admin-key` header, **or**
2. A valid JWT where the user has `role='admin'` **verified in the database** (not just the token claim).

## File Uploads
- Allowed MIME types: `image/jpeg`, `image/png`, `image/gif`, `image/webp`, `application/pdf`
- Max size: 5 MB (enforced by `multer` limits)
- Files stored as BYTEA in DB, not on the filesystem

## GDPR
`DELETE /api/me/gdpr` anonymizes all user data:
- Username replaced with `deleted_user_<timestamp>`
- Email, bio, skills, avatar, balance cleared
- Chat messages replaced with `[deleted]`
- Reviews anonymized
- Notifications and saved searches deleted
- Account blocked to prevent re-login

## Race Conditions / Double-Spending
Escrow release and milestone approval use `SELECT ... FOR UPDATE` within transactions to prevent concurrent double-release.

## Memory Leaks
- All `setInterval` calls use stored IDs and are cleared on server shutdown (`SIGTERM`).
- Socket.io event listeners are removed on disconnect.

## Dependency Audit
Run `npm audit` before each deployment. CI should fail on critical vulnerabilities.

## Reporting Security Issues
Contact: security@workpro.pi (or open a private GitHub issue).
