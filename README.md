# Remote Video Library – Auth Server (Identity Provider)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?logo=docker&logoColor=white)](#docker-setup-recommended)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=node.js&logoColor=white)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)]()

---

## Description


A robust, standalone **Authentication Microservice** built with Node.js and TypeScript.

While originally developed as the Identity Provider for the **[Remote Video Library](https://github.com/anp3l/remote-video-client)** ecosystem, this server is designed to be completely **agnostic**. It can be used "as-is" to handle authentication for **any project** requiring secure, stateless user management.

It acts as a centralized Authority, handling user registration, login, and secure token issuance using **RSA (RS256) signatures**. Any other service (Resource Server) can simply verify the issued tokens using the public key, enabling a true microservices architecture.


---

### 🔐 Authentication & Security
- **RSA-Signed JWTs (RS256)**: Issues RS256 tokens using a private key loaded from environment variables or local PEM files
- **Refresh Token System**: Short-lived access tokens (15min) + long-lived refresh tokens (7 days)
- **Secure Password Hashing**: bcrypt with 12 salt rounds
- **Password Reset Flow**: Mock email system for development (token-based reset)
- **Rate Limiting**: Prevents brute-force attacks (5 attempts per 15min on auth endpoints)
- **Security Headers**: Helmet.js protection

### 👥 User Management
- **User Registration & Login**: Email/password authentication
- **Profile Management**: Update name, shipping address
- **Password Management**: Change password with verification
- **Account Deletion**: Self-service account removal
- **Input Validation**: Strict email, username, and password validation

### 🛡️ Role-Based Access Control (RBAC)
- **Customer Role**: Standard user capabilities
- **Admin Role**: Full user management and audit access
- **Role-based Middleware**: Protect endpoints by role requirements

### 👨‍💼 Admin Capabilities
- **User Management**: View, search, filter users with pagination
- **Role Management**: Promote/demote user roles
- **User Deletion**: Remove users with audit trail
- **Statistics Dashboard**: Platform metrics (total users, active sessions)
- **Audit Log Access**: Full visibility into system actions

### 📊 Audit & Monitoring
- **Login History Tracking**: IP, browser, OS, device for each login attempt
- **Comprehensive Audit Logging**: All critical actions tracked (signup, login, password changes, role changes)
- **Failed Login Tracking**: Monitor suspicious activity
- **Admin Action Attribution**: Track who performed administrative actions

### 📧 Email System (Development)
- **Mock Email Service**: Logs emails to console for development
- **HTML Email Templates**: Professional templates (password reset, welcome)
- **Template Engine**: File-based templates with variable substitution
- **Easy to Extend**: Ready for production email providers (Resend, SMTP)

### 🔄 Token Management
- **List Active Sessions**: View all active refresh tokens
- **Revoke Single Token**: Logout from specific device
- **Revoke All Tokens**: Logout from all devices
- **Automatic Cleanup**: Scheduled cleanup of expired tokens every 24h

### 📝 Developer Experience
- **Full Swagger/OpenAPI Documentation**: Interactive API explorer at `/api-docs`
- **TypeScript**: Full type safety
- **Docker Setup**: One-command startup with MongoDB included
- **Health Check Endpoint**: Monitor service status
- **Graceful Shutdown**: Clean database disconnection
    

---

## Usage Scenarios

- **Microservices Auth**: Centralized login for multiple backend services
- **Standalone App**: Quick auth backend for React/Angular/Mobile apps
- **Cross-Domain Identity**: Verify users across different domains using public-key cryptography
- **Learning Project**: Study modern authentication patterns and best practices

---

## Quick Start

### Prerequisites
- **Docker & Docker Compose** (recommended), OR
- **Node.js v20+** and **MongoDB** (manual setup)

### 1. Clone the Repository

```bash
git clone https://github.com/anp3l/auth-server.git
cd auth-server
```

### 2. Generate RSA Keys

The server uses RSA asymmetric encryption for JWT signing.

```bash
# Generate private key (2048-bit)
openssl genrsa -out private.pem 2048

# Extract public key
openssl rsa -in private.pem -pubout -out public.pem
```

### 3. Configure Environment

```bash
# Copy example environment file
cp .env.example .env
```

**Encode keys to Base64:**

**Mac/Linux:**
```bash
cat private.pem | base64 | tr -d '\n'
cat public.pem | base64 | tr -d '\n'
```

**Windows (PowerShell):**
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("./private.pem"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("./public.pem"))
```

**Edit `.env`** and paste the Base64 keys:
```bash
NODE_ENV=development
PORT=4000
ENABLE_LOGS=true

MONGO_URI=mongodb://auth-mongo:27017/authdb

PRIVATE_KEY_BASE64=your_base64_encoded_private_key
PUBLIC_KEY_BASE64=your_base64_encoded_public_key

# JWT Configuration
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d

# Email (Mock for development)
EMAIL_PROVIDER=mock
EMAIL_FROM=noreply@yourapp.com
FRONTEND_URL=http://localhost:4200
APP_NAME=Your App Name
SUPPORT_EMAIL=support@yourapp.com

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:4200
```

> **Note**: Never commit `.env` or `.pem` files to Git. They're in `.gitignore` for safety.
    

### 4. Choose your Setup Method

#### Option A: Docker (Recommended)

Includes MongoDB pre-configured with health checks.

```bash
# Build and start
docker-compose up --build

# Or run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

**Server available at:** http://localhost:4000  
**Swagger Docs:** http://localhost:4000/api-docs


#### Option B: Manual Setup

Requires Node.js 20+ and MongoDB running locally.

```bash
# Install dependencies
npm install

# Start MongoDB (in another terminal)
# Make sure MongoDB is running on localhost:27017

# Development (with auto-reload)
npm run dev

# Or build and run
npm run build
npm start
```
    

---

## API Endpoints

### Core Endpoints

#### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/signup` | Register new user | No |
| POST | `/auth/login` | Login with credentials | No |
| POST | `/auth/refresh-token` | Get new access token | No |
| POST | `/auth/revoke-token` | Logout from device | Yes |
| POST | `/auth/revoke-all-tokens` | Logout from all devices | Yes |
| DELETE | `/auth/revoke-token/:tokenId` | Revoke specific token | Yes |
| GET | `/auth/refresh-tokens` | List active sessions | Yes |

#### Password Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/forgot-password` | Request password reset (mock email) | No |
| POST | `/auth/reset-password` | Reset password with token | No |
| POST | `/auth/verify-reset-token` | Verify token validity | No |
| POST | `/auth/change-password` | Change password | Yes |

#### User Profile

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/auth/profile` | Get user profile | Yes |
| PUT | `/auth/profile` | Update profile | Yes |
| GET | `/auth/login-history` | Get login history | Yes |
| DELETE | `/auth/account` | Delete account | Yes |

#### Admin (Requires Admin Role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/users` | List all users (paginated, searchable) |
| GET | `/admin/users/:id` | Get user details |
| PUT | `/admin/users/:id/role` | Change user role |
| DELETE | `/admin/users/:id` | Delete user |
| GET | `/admin/stats` | Platform statistics |
| GET | `/admin/audit-logs` | Get all audit logs |
| GET | `/admin/users/:id/audit-logs` | Get user audit logs |

#### System

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api-docs` | Swagger UI |

**Full Swagger (OpenAPI) available at:** http://localhost:4000/api-docs

---

## Testing the API

### 1. Register a User

```bash
curl -X POST http://localhost:4000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "username": "demo",
    "email": "demo@example.com",
    "password": "Demo123!",
    "firstName": "Demo",
    "lastName": "User"
  }'
```

**Response:**
```json
{
  "message": "User created",
  "accessToken": "eyJhbGc...",
  "refreshToken": "a1b2c3...",
  "user": {
    "id": "...",
    "username": "demo",
    "email": "demo@example.com",
    "role": "customer"
  }
}
```

Check your console - you should see a **mock welcome email**!

### 2. Login

```bash
curl -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "demo@example.com",
    "password": "Demo123!"
  }'
```

Save the `accessToken` from the response.

### 3. Get Profile (Authenticated)

```bash
curl http://localhost:4000/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

### 4. View Login History

```bash
curl http://localhost:4000/auth/login-history \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

See your login attempts with browser, OS, and device info!

### 5. Password Reset Flow (Mock Email)

```bash
# Request reset
curl -X POST http://localhost:4000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com"}'
```

Check your **console** - you'll see the reset email with the token:
```
========== MOCK EMAIL ==========
To: demo@example.com
Subject: Password Reset Request
...
Reset link: http://localhost:4200/reset-password?token=abc123xyz...
```

Copy the token and use it:

```bash
curl -X POST http://localhost:4000/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_TOKEN_FROM_CONSOLE",
    "newPassword": "NewPass123!",
    "confirmPassword": "NewPass123!"
  }'
```

### 6. Make Yourself Admin (for testing)

```bash
# Connect to MongoDB
docker exec -it auth-mongo mongosh

# In MongoDB shell
use authdb
db.users.updateOne(
  { email: "demo@example.com" },
  { $set: { role: "admin" } }
)
exit
```

Now login again and test admin endpoints!

---
## How it works (Auth Flow)

```
┌─────────────────────────────────────────────────────────┐
│                    Client Application                   │
└────────────────────────┬────────────────────────────────┘
                         │
                         │ 1. POST /auth/login
                         ▼
┌─────────────────────────────────────────────────────────┐
│                      Auth Server                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │  2. Validate credentials (bcrypt)                 │  │
│  │  3. Generate Access Token (15min, RS256)          │  │
│  │  4. Generate Refresh Token (7d, stored in DB)     │  │
│  └───────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────┘
                         │
                         │ 5. Return tokens
                         ▼
┌─────────────────────────────────────────────────────────┐
│                    Client Application                   │
│  - Stores tokens (localStorage / secure cookie)         │
│  - Uses Access Token for API requests                   │
└────────────────────────┬────────────────────────────────┘
                         │
                         │ 6. API Request with token
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   Resource Server                       │
│  (e.g., Video Server, Product Service)                  │
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │  7. Verify token with Public Key                  │  │
│  │  8. Extract user info (userId, role)              │  │
│  │  9. Authorize based on role                       │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘

When Access Token expires:
Client → POST /auth/refresh-token (with Refresh Token)
Server → Issue new Access Token (Refresh Token rotated)
```

---

---

## Project Structure

```
auth-server/
├── src/
│   ├── config/              # Configuration (env, keys)
│   ├── middleware/          # Auth, validation, rate limiting
│   ├── models/              # Mongoose models
│   │   ├── user.model.ts
│   │   ├── refreshToken.model.ts
│   │   ├── passwordResetToken.model.ts
│   │   ├── loginHistory.model.ts
│   │   └── auditLog.model.ts
│   ├── routes/              # API routes
│   │   ├── auth.routes.ts
│   │   └── admin.routes.ts
│   ├── services/            # Business logic
│   │   ├── email/
│   │   │   ├── templates/       # HTML email templates
│   │   │   ├── email.interface.ts
│   │   │   ├── mock-email.service.ts
│   │   │   ├── template-engine.ts
│   │   │   └── email-service.factory.ts
│   │   └── audit.service.ts
│   ├── tasks/               # Scheduled tasks (cleanup)
│   ├── utils/               # Utilities (user-agent parsing)
│   ├── validators/          # Request validators
│   |── index.ts             # Server entry point
|   └── mongo-connection.ts
├── .env.example             # Environment template
├── docker-compose.yml       # Docker setup (dev)
├── Dockerfile               # Container definition
├── package.json
├── tsconfig.json
└── README.md
```

---

## Development

### Tech Stack

- **Runtime**: Node.js 20+
- **Language**: TypeScript
- **Framework**: Express.js
- **Database**: MongoDB + Mongoose ODM
- **Security**: Helmet, bcrypt, CORS, Rate Limiting
- **Auth**: jsonwebtoken (RS256), Refresh Tokens
- **Validation**: express-validator
- **Documentation**: Swagger/OpenAPI
- **Email**: Template-based mock system (extensible)

### Development Commands

```bash
# Install dependencies
npm install

# Development (auto-reload)
npm run dev

# Build TypeScript
npm run build

# Production start (after build)
npm start

# Docker commands
docker-compose up --build       # Start
docker-compose down             # Stop
docker-compose logs -f          # View logs
docker-compose down -v          # Clean (remove volumes)
```

### Environment Variables

See `.env.example` for all available variables. Key ones:

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment | `development` |
| `PORT` | Server port | `4000` |
| `MONGO_URI` | MongoDB connection | `mongodb://auth-mongo:27017/authdb` |
| `PRIVATE_KEY_BASE64` | RSA private key | (required) |
| `PUBLIC_KEY_BASE64` | RSA public key | (required) |
| `EMAIL_PROVIDER` | Email service | `mock` |
| `ACCESS_TOKEN_EXPIRY` | Access token lifetime | `15m` |
| `REFRESH_TOKEN_EXPIRY` | Refresh token lifetime | `7d` |

---
    
## Security Best Practices

### Implemented
- ✅ **RS256 JWT**: Asymmetric signing, public key for verification
- ✅ **Refresh Token Rotation**: Single-use tokens, stored in database
- ✅ **Password Hashing**: bcrypt with 12 rounds
- ✅ **Rate Limiting**: 5 auth attempts per 15min
- ✅ **Security Headers**: Helmet.js enabled
- ✅ **CORS**: Configurable allowed origins
- ✅ **Input Validation**: express-validator on all endpoints
- ✅ **Audit Logging**: All sensitive actions tracked
- ✅ **Password Strength**: Min 8 chars, uppercase, lowercase, number, special char

---

## Roadmap & Future Features

### ✅ Completed (Current Version)
- ✅ JWT with refresh token system
- ✅ RBAC (Role-Based Access Control)
- ✅ Password reset flow (mock email)
- ✅ Login history tracking
- ✅ Comprehensive audit logging
- ✅ Admin user management
- ✅ Email template system

### 🚧 Planned (Future Production Repo)
- [ ] **Real Email Services**: Resend and SMTP providers
- [ ] **Production Deployment**: Docker Compose, Railway, Render guides
- [ ] **JWKS Endpoint**: `GET /.well-known/jwks.json` for auto-configuration
- [ ] **Key Rotation**: Automated RSA key pair rotation
- [ ] **2FA**: Two-factor authentication (TOTP)
- [ ] **OAuth**: Social login (Google, GitHub)
- [ ] **Email Verification**: Confirm email on signup
- [ ] **Rate Limiting Dashboard**: Monitor abuse patterns
- [ ] **Testing**: Unit and integration tests

---

## Learning Resources

This project demonstrates:

- **JWT Authentication**: Access + Refresh token pattern
- **RSA Cryptography**: Asymmetric key signing and verification
- **RBAC**: Role-based authorization middleware
- **MongoDB**: NoSQL database with Mongoose ODM
- **TypeScript**: Type-safe Node.js development
- **Docker**: Containerized application with Docker Compose
- **Microservices**: Service-to-service authentication
- **Security**: bcrypt, rate limiting, audit logging
- **API Design**: RESTful endpoints with Swagger docs

---

## Troubleshooting

### Port Already in Use

```bash
# Change PORT in .env
PORT=4001
```

### MongoDB Connection Failed

```bash
# Wait for MongoDB to be ready
docker-compose logs auth-mongo

# Or restart
docker-compose restart auth-mongo
```

### Invalid RSA Keys

```bash
# Regenerate keys
rm private.pem public.pem
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Re-encode and update .env
```

### Token Verification Failed

**Symptom**: "Invalid token" errors

**Solution**: Make sure your Resource Server uses the **same public key** that matches this Auth Server's private key.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Built for the [Remote Video Library](https://github.com/anp3l/remote-video-client) ecosystem
- Inspired by modern authentication best practices
- Designed for learning and development

---

**Made by [anp3l](https://github.com/anp3l)**