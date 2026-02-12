# Remote Video Library – Auth Server (Identity Provider)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?logo=docker&logoColor=white)](#docker-setup-recommended)
[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=node.js&logoColor=white)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)]()

---

## Description

A robust, standalone **Authentication Microservice** built with Node.js and TypeScript featuring **HttpOnly Cookie-based authentication** and **CSRF protection**.

While originally developed as the Identity Provider for the **[Remote Video Library](https://github.com/anp3l/remote-video-client)** ecosystem, this server is designed to be completely **agnostic**. It can be used "as-is" to handle authentication for **any project** requiring secure, stateless user management.

It acts as a centralized Authority, handling user registration, login, and secure token issuance using **RSA (RS256) signatures**. Any other service (Resource Server) can simply verify the issued tokens using the public key, enabling a true microservices architecture.

---

## Features

### 🔐 Authentication & Security
- **HttpOnly Cookie Authentication**: Tokens stored in secure, HTTP-only cookies (immune to XSS attacks)
- **CSRF Protection**: Double-submit cookie pattern with X-CSRF-Token header validation
- **RSA-Signed JWTs (RS256)**: Issues RS256 tokens using a private key loaded from environment variables or local PEM files
- **Refresh Token System**: Short-lived access tokens (15min) + long-lived refresh tokens (7 days)
- **Automatic Token Refresh**: Frontend interceptor automatically refreshes expired tokens
- **Secure Password Hashing**: bcrypt with 12 salt rounds
- **Password Reset Flow**: Token-based reset with mock email system for development
- **Rate Limiting**: Prevents brute-force attacks (5 attempts per 15min on auth endpoints)
- **Security Headers**: Helmet.js protection
- **CORS with Credentials**: Secure cross-origin cookie handling

### 👥 User Management
- **User Registration & Login**: Email/password authentication
- **Profile Management**: Update name, personal info, shipping address, email preferences
- **Avatar Upload**: Upload/delete profile pictures with automatic cleanup
- **Address Book**: Multiple shipping addresses with default selection
- **Password Management**: Change password with verification
- **Account Deletion**: Self-service account removal with cascading cleanup
- **Input Validation**: Strict email, username, and password validation

### 🛡️ Role-Based Access Control (RBAC)
- **Customer Role**: Standard user capabilities
- **Admin Role**: Full user management and audit access
- **Role-based Middleware**: Protect endpoints by role requirements

### 👨‍💼 Admin Capabilities
- **User Management**: View, search, filter users with pagination
- **Role Management**: Promote/demote user roles
- **User Banning**: Suspend/unsuspend users with reason tracking
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
git checkout feature/http-only-cookie  # Use the cookie-based auth branch
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

# Cookie Security (HttpOnly Cookie Authentication)
COOKIE_DOMAIN=           # Leave empty for localhost development
COOKIE_SECURE=false      # true in production (HTTPS only)
COOKIE_SAMESITE=lax      # strict, lax, or none

# CSRF Protection
CSRF_SECRET=your-super-secret-csrf-key-change-this-in-production
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

### ⚠️ Important: Cookie-Based Responses

All authentication endpoints return user data in the **response body**, but tokens are set as **HttpOnly cookies** in response headers. Tokens are **NEVER** returned in JSON responses.

**Example Login Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": "...",
    "username": "demo",
    "email": "demo@example.com",
    "role": "customer"
  }
  // ❌ NO "accessToken" or "refreshToken" fields!
}
```

**Tokens are in Response Headers:**
```
Set-Cookie: accessToken=eyJhbGc...; HttpOnly; Secure; SameSite=Lax
Set-Cookie: refreshToken=a1b2c3...; HttpOnly; Secure; SameSite=Lax
```

### Core Endpoints

#### Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/auth/csrf-token` | Get CSRF token (required before protected requests) | No |
| POST | `/auth/signup` | Register new user | No |
| POST | `/auth/login` | Login with credentials | No |
| POST | `/auth/refresh-token` | Refresh access token (automatic) | No |
| POST | `/auth/revoke-token` | Logout from current device | Yes |
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
| PATCH | `/auth/profile` | Update profile (basic info) | Yes |
| GET | `/auth/stats` | Get user statistics | Yes |
| GET | `/auth/login-history` | Get login history | Yes |
| DELETE | `/auth/account` | Delete account | Yes |

#### Avatar Management

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/avatar` | Upload avatar (multipart/form-data) | Yes |
| GET | `/auth/avatar` | Get current avatar URL | Yes |
| DELETE | `/auth/avatar` | Delete avatar | Yes |

#### Email Preferences

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| PATCH | `/auth/profile/email-preferences` | Update email/notification settings | Yes |

#### Address Book

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/profile/addresses` | Add new address | Yes |
| PUT | `/auth/profile/addresses/:addressId` | Update address | Yes |
| DELETE | `/auth/profile/addresses/:addressId` | Delete address | Yes |

#### Admin (Requires Admin Role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/admin/users` | List all users (paginated, searchable) |
| GET | `/admin/users/:id` | Get user details |
| PUT | `/admin/users/:id/role` | Change user role |
| PUT | `/admin/users/:id/ban` | Ban user |
| PUT | `/admin/users/:id/unban` | Unban user |
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

This server uses **HttpOnly cookies** for authentication. Tokens are set as secure cookies in response headers, not in JSON responses.

### Quick Test Flow

1. **Get CSRF Token**: `GET /auth/csrf-token`
2. **Register/Login**: Include CSRF token in `X-CSRF-Token` header
3. **Use cookies.txt**: Save cookies with `-c cookies.txt`, send with `-b cookies.txt`

**👉 See [API_TESTING.md](./API_TESTING.md) for complete curl examples and testing workflows**

### Testing Tools

- **curl**: Use `-c` and `-b` flags for cookies
- **Postman/Insomnia**: Enable "Cookie Jar" for automatic cookie management
- **Swagger UI**: Interactive API explorer at http://localhost:4000/api-docs

---

## How it works (Auth Flow)

```
┌──────────────────────────────────────────────────────┐
│                 Client Application                   │
│               (Browser / Mobile App)                 │
└────────────────────────┬─────────────────────────────┘
                         │
                         │ 1. GET /auth/csrf-token
                         ▼
┌──────────────────────────────────────────────────────┐
│                    Auth Server                       │
│  ┌────────────────────────────────────────────────┐  │
│  │ 2. Generate CSRF token                         │  │
│  │ 3. Set _csrf cookie + return token             │  │
│  └────────────────────────────────────────────────┘  │
└────────────────────────┬─────────────────────────────┘
                         │
                         │ 4. POST /auth/login
                         │ + X-CSRF-Token header
                         ▼
┌──────────────────────────────────────────────────────┐
│                    Auth Server                       │
│  ┌────────────────────────────────────────────────┐  │
│  │ 5. Validate CSRF token                         │  │
│  │ 6. Validate credentials (bcrypt)               │  │
│  │ 7. Generate Access Token (15min, RS256)        │  │
│  │ 8. Generate Refresh Token (7d, stored in DB)   │  │
│  │ 9. Set HttpOnly cookies:                       │  │
│  │ - accessToken (HttpOnly, Secure, SameSite)     │  │
│  │ - refreshToken (HttpOnly, Secure, SameSite)    │  │
│  └────────────────────────────────────────────────┘  │
└────────────────────────┬─────────────────────────────┘
                         │
                         │ 10. Return user info (NO tokens in body!)
                         ▼
┌──────────────────────────────────────────────────────┐
│                 Client Application                   │ 
│ - Browser stores cookies automatically               │
│ - Cookies sent with EVERY request (automatic)        │
│ - JavaScript CANNOT access tokens (XSS protection)   │
└────────────────────────┬─────────────────────────────┘
                         │
                         │ 11. API Request (cookies auto-sent)
                         ▼
┌──────────────────────────────────────────────────────┐
│                    Auth Server                       │
│  ┌────────────────────────────────────────────────┐  │
│  │ 12. Read accessToken from cookie               │  │
│  │ 13. Verify token signature (RS256)             │  │
│  │ 14. Extract user info (userId, role)           │  │
│  │ 15. Authorize based on role                    │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘

        When Access Token expires (after 15min):
┌──────────────────────────────────────────────────────┐
│                 Client Application                   │
│ - Receives 401 Unauthorized                          │
│ - Interceptor automatically triggers refresh         │
└────────────────────────┬─────────────────────────────┘
                         │
                         │ POST /auth/refresh-token
                         │ (refreshToken cookie auto-sent)
                         ▼
┌──────────────────────────────────────────────────────┐
│                    Auth Server                       │
│  ┌────────────────────────────────────────────────┐  │
│  │ 1. Read refreshToken from cookie               │  │
│  │ 2. Validate token from database                │  │
│  │ 3. Revoke old refresh token                    │  │
│  │ 4. Generate NEW tokens                         │  │
│  │ 5. Set NEW cookies                             │  │
│  └────────────────────────────────────────────────┘  │
└────────────────────────┬─────────────────────────────┘
                         │
                         │ New tokens in cookies
                         ▼
┌──────────────────────────────────────────────────────┐
│                 Client Application                   │
│ - Retry original request automatically               │
│ - User never notices token refresh!                  │
└──────────────────────────────────────────────────────┘

        For Resource Servers (Microservices):
┌──────────────────────────────────────────────────────┐
│                   Resource Server                    │
│         (e.g., Video Server, Product Service)        │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │ 1. Receive request with accessToken cookie     │  │
│  │ 2. Verify token with Public Key (RS256)        │  │
│  │ 3. Extract user info (userId, role)            │  │
│  │ 4. Authorize based on role                     │  │
│  │ 5. NO database call needed!                    │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

---

## Project Structure

```
auth-server/
├── src/
│   ├── config/              # Configuration (env, keys)
│   ├── middleware/          # Auth, validation, rate limiting, upload
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
│   ├── index.ts             # Server entry point
│   └── mongo-connection.ts
├── uploads/avatars/         # Avatar upload directory
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
- **Security**: Helmet, bcrypt, CORS, Rate Limiting, CSRF
- **Auth**: jsonwebtoken (RS256), HttpOnly Cookies, Refresh Tokens
- **File Upload**: Multer (avatar management)
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
| `COOKIE_DOMAIN` | Cookie domain (leave empty for localhost) | (empty) |
| `COOKIE_SECURE` | Use secure cookies (HTTPS only) | `false` |
| `COOKIE_SAMESITE` | SameSite cookie policy | `lax` |
| `CSRF_SECRET` | Secret for CSRF token generation | (required) |
| `ALLOWED_ORIGINS` | CORS allowed origins | `http://localhost:4200` |
| `FRONTEND_URL` | Frontend URL for emails | `http://localhost:4200` |

---

## Security Best Practices

### Implemented
- ✅ **HttpOnly Cookies**: Tokens inaccessible to JavaScript (XSS protection)
- ✅ **CSRF Protection**: Double-submit cookie pattern with token validation
- ✅ **Secure Cookies**: Configurable Secure flag for HTTPS-only transmission
- ✅ **SameSite Cookies**: Protection against CSRF attacks
- ✅ **RS256 JWT**: Asymmetric signing, public key for verification
- ✅ **Refresh Token Rotation**: Single-use tokens, automatically rotated on refresh
- ✅ **Token Storage in Database**: Refresh tokens stored and revocable
- ✅ **Automatic Token Refresh**: Seamless UX without interruptions
- ✅ **Password Hashing**: bcrypt with 12 rounds
- ✅ **Rate Limiting**: 5 auth attempts per 15min
- ✅ **Security Headers**: Helmet.js enabled
- ✅ **CORS with Credentials**: Strict origin validation
- ✅ **Input Validation**: express-validator on all endpoints
- ✅ **Audit Logging**: All sensitive actions tracked
- ✅ **Password Strength**: Min 8 chars, uppercase, lowercase, number, special char
- ✅ **Session Revocation**: Logout from specific or all devices
- ✅ **File Upload Security**: Multer with size/type restrictions

### Why HttpOnly Cookies?

**Traditional Approach (localStorage):**
```javascript
// ❌ Vulnerable to XSS attacks
localStorage.setItem('token', accessToken);
// Any injected script can steal this!
```

**HttpOnly Cookie Approach:**
```javascript
// ✅ Immune to XSS - JavaScript cannot access
// Browser automatically sends with requests
// Token stored securely, managed by browser
```

**Benefits:**
- **XSS Protection**: Tokens cannot be stolen by malicious scripts
- **Automatic Management**: Browser handles cookie lifecycle
- **CSRF Protection**: Additional CSRF token layer
- **Seamless UX**: Automatic token refresh on expiration
- **Microservices Ready**: Same cookies work across services

### Production Checklist

Before deploying to production:

```bash
# .env
NODE_ENV=production
COOKIE_SECURE=true           # ✅ HTTPS only
COOKIE_SAMESITE=strict       # ✅ Strongest CSRF protection
CSRF_SECRET=<strong-random>  # ✅ Change from default
PRIVATE_KEY_BASE64=<secure>  # ✅ Store in secrets manager
ALLOWED_ORIGINS=https://yourdomain.com  # ✅ Specific origins only
```

- ✅ Enable HTTPS (required for secure cookies)
- ✅ Use environment-specific secrets
- ✅ Configure strict CORS
- ✅ Enable rate limiting in production
- ✅ Set up monitoring and alerts
- ✅ Regular security audits

---

## 🚀 Frontend Integration

This Auth Server uses **HttpOnly cookies** for authentication. The frontend must be configured to handle cookies automatically and include CSRF tokens.

### Quick Start

For detailed integration examples with **Angular**, including:
- ✅ Complete interceptor implementations
- ✅ CSRF token management
- ✅ Automatic token refresh
- ✅ Error handling
- ✅ Reactive state management

**👉 See [FRONTEND_INTEGRATION.md](./FRONTEND_INTEGRATION.md) for complete examples**

### Key Requirements

- **withCredentials: true** - Always send cookies with requests
- **CSRF Token** - Fetch on app startup: `GET /auth/csrf-token`
- **X-CSRF-Token Header** - Include on all POST/PUT/PATCH/DELETE to protected endpoints
- **Auto-Refresh** - Handle 401 errors by calling `POST /auth/refresh-token`
- **No localStorage** - Tokens are stored in HttpOnly cookies (managed by browser)

---

## Roadmap & Future Features

### ✅ Completed (Current Version)
- ✅ HttpOnly Cookie-based authentication
- ✅ CSRF protection
- ✅ JWT with refresh token system
- ✅ RBAC (Role-Based Access Control)
- ✅ Password reset flow (mock email)
- ✅ Avatar upload/management
- ✅ Address book management
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
- **HttpOnly Cookies**: XSS-resistant token storage
- **CSRF Protection**: Double-submit cookie pattern
- **RSA Cryptography**: Asymmetric key signing and verification
- **RBAC**: Role-based authorization middleware
- **MongoDB**: NoSQL database with Mongoose ODM
- **TypeScript**: Type-safe Node.js development
- **Docker**: Containerized application with Docker Compose
- **Microservices**: Service-to-service authentication
- **Security**: bcrypt, rate limiting, audit logging
- **File Upload**: Multer for avatar management
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

### Cookies Not Saved

**Symptoms**:
- 401 errors after login
- Cookies not appearing in DevTools

**Solutions**:
1. Check CORS: `ALLOWED_ORIGINS` must include your frontend URL
2. Check cookie domain: Leave `COOKIE_DOMAIN` empty for localhost
3. Use `withCredentials: true` in frontend requests
4. Clear browser cookies and retry

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