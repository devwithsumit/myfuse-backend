# MyFuse Auth Backend

Node.js + Express + MySQL authentication service with OTP email verification.

## Tech Stack
- Node.js, Express
- MySQL (`mysql2/promise`)
- JWT (token auth)
- Bcrypt (password hashing)
- Nodemailer (email OTP)
- dotenv, cors, helmet, morgan

## Features
- Register with name, email, password (hashed)
- Send 6-digit OTP email (HTML template)
- Verify OTP (expires in 5 minutes) → issues JWT (1h expiry)
- Login with email + password → issues JWT (1h)
- Resend OTP if not yet verified
- Protected route: `GET /api/user/me`

## Project Structure
```
backend/
  src/
    config/db.js
    controllers/authController.js
    routes/authRoutes.js
    services/emailService.js
    middlewares/authMiddleware.js
    utils/generateOtp.js
    app.js
    server.js
  sql/schema.sql
  .env.example
  package.json
  README.md
```

## Setup
1. Clone and enter the project folder.
2. Create a MySQL database (e.g., `myfuse`).
3. Import the schema:
   ```bash
   mysql -u <user> -p myfuse < sql/schema.sql
   ```
4. Copy env file and adjust values:
   ```bash
   cp .env.example .env
   ```
5. Install dependencies:
   ```bash
   npm install
   ```
6. Run in dev mode:
   ```bash
   npm run dev
   ```

Server starts on `http://localhost:4000` (configurable via `PORT`).

## Environment Variables
See `.env.example` for all options:
- Server: `PORT`, `CORS_ORIGIN`
- DB: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`
- JWT: `JWT_SECRET`
- SMTP: `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`
- App: `APP_NAME`, `APP_FROM_EMAIL`

## API
Base URL: `http://localhost:4000/api`

### Register
POST `/auth/register`
```json
{
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "password": "StrongP@ssw0rd"
}
```
Responses:
- 201: `{ "message": "Registration successful. OTP sent to email." }`
- 409: `{ "error": "Email is already registered and verified. Please log in." }`

### Verify OTP
POST `/auth/verify`
```json
{
  "email": "ada@example.com",
  "otp": "123456"
}
```
Response 200:
```json
{
  "token": "<jwt>",
  "user": { "id": 1, "name": "Ada Lovelace", "email": "ada@example.com", "isVerified": true }
}
```

### Login
POST `/auth/login`
```json
{
  "email": "ada@example.com",
  "password": "StrongP@ssw0rd"
}
```
Response 200:
```json
{
  "token": "<jwt>",
  "user": { "id": 1, "name": "Ada Lovelace", "email": "ada@example.com", "isVerified": true }
}
```

### Resend OTP
POST `/auth/resend-otp`
```json
{ "email": "ada@example.com" }
```
Response 200: `{ "message": "OTP resent to email" }`

### Get Current User
GET `/user/me`
Headers: `Authorization: Bearer <jwt>`

Response 200:
```json
{ "user": { "id": 1, "name": "Ada Lovelace", "email": "ada@example.com", "isVerified": true } }
```

## Notes
- OTP expiry is 5 minutes; JWT expiry is 1 hour.
- Passwords are hashed with bcrypt (10 rounds).
- Uses `helmet`, `cors`, `morgan` for production-friendly defaults.


