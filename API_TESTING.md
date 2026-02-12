# API Testing Guide

Complete guide for testing the Auth Server API using **curl**, **Postman**, and **Swagger UI**.

***

## Overview

This Auth Server uses **HttpOnly Cookie-based authentication**. Understanding how cookies work is essential for testing:

- **Tokens are NOT in JSON responses** - They're set as `Set-Cookie` headers
- **Cookies are automatically sent** - Browser/curl handles this
- **CSRF token required** - For all protected POST/PUT/PATCH/DELETE requests

***

## Important: Cookie-Based Authentication

### Token Response Format

**❌ What you WON'T see:**
```json
{
  "accessToken": "eyJhbGc...",
  "refreshToken": "abc123..."
}
```

**✅ What you WILL see:**
```json
{
  "message": "Login successful",
  "user": {
    "id": "...",
    "username": "demo",
    "email": "demo@example.com",
    "role": "customer"
  }
}
```

**Tokens are in Response Headers:**
```
Set-Cookie: accessToken=eyJhbGc...; HttpOnly; Secure; SameSite=Lax; Path=/
Set-Cookie: refreshToken=a1b2c3...; HttpOnly; Secure; SameSite=Lax; Path=/
Set-Cookie: _csrf=xyz789...; Path=/
```

***

## Testing with curl

### Prerequisites

- curl installed
- Auth Server running on `http://localhost:4000`
- A text editor to save CSRF tokens

### Cookie Management with curl

```bash
# Save cookies to file
curl -c cookies.txt <url>

# Send cookies from file
curl -b cookies.txt <url>

# Both save and send
curl -b cookies.txt -c cookies.txt <url>
```

***

## Step-by-Step Testing Flow

### 1. Get CSRF Token

**Request:**
```bash
curl -X GET http://localhost:4000/auth/csrf-token \
  -c cookies.txt \
  -v
```

**Response:**
```json
{
  "csrfToken": "abc123xyz..."
}
```

**What happens:**
- CSRF token returned in response body
- `_csrf` cookie automatically set
- Cookie saved to `cookies.txt`

**Save the `csrfToken` value** - You'll need it for all protected requests.

***

### 2. Register a New User

**Request:**
```bash
curl -X POST http://localhost:4000/auth/signup \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -c cookies.txt \
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
  "message": "User created successfully",
  "user": {
    "id": "65f1234567890abcdef12345",
    "username": "demo",
    "email": "demo@example.com",
    "role": "customer",
    "firstName": "Demo",
    "lastName": "User",
    "createdAt": "2026-02-12T11:00:00.000Z"
  }
}
```

**What happens:**
- User created in database
- `accessToken` and `refreshToken` cookies set
- Mock welcome email logged to console
- Cookies automatically saved to `cookies.txt`

**Check your terminal** where the server is running - you should see:
```
📧 [Mock Email] Sending email to: demo@example.com
📧 Subject: Welcome to Your App Name!
📧 Content:
   Welcome Demo! Your account has been created...
```

***

### 3. Login

**Request:**
```bash
curl -X POST http://localhost:4000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -c cookies.txt \
  -d '{
    "email": "demo@example.com",
    "password": "Demo123!"
  }'
```

**Response:**
```json
{
  "message": "Login successful",
  "user": {
    "id": "65f1234567890abcdef12345",
    "username": "demo",
    "email": "demo@example.com",
    "role": "customer"
  }
}
```

**What happens:**
- Credentials validated
- New `accessToken` and `refreshToken` issued
- Login history recorded (IP, browser, device)
- Cookies updated in `cookies.txt`

***

### 4. Get User Profile (Authenticated Request)

**Request:**
```bash
curl http://localhost:4000/auth/profile \
  -b cookies.txt
```

**Note:** No `X-CSRF-Token` needed for GET requests!

**Response:**
```json
{
  "id": "65f1234567890abcdef12345",
  "username": "demo",
  "email": "demo@example.com",
  "role": "customer",
  "firstName": "Demo",
  "lastName": "User",
  "avatar": null,
  "emailPreferences": {
    "marketing": true,
    "newsletter": true,
    "updates": true
  },
  "addresses": [],
  "createdAt": "2026-02-12T11:00:00.000Z",
  "updatedAt": "2026-02-12T11:00:00.000Z"
}
```

***

### 5. Update Profile

**Request:**
```bash
curl -X PATCH http://localhost:4000/auth/profile \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -c cookies.txt \
  -d '{
    "firstName": "Andrea",
    "lastName": "Rossi",
    "phoneNumber": "+39 123 456 7890"
  }'
```

**Response:**
```json
{
  "message": "Profile updated successfully",
  "user": {
    "id": "65f1234567890abcdef12345",
    "username": "demo",
    "firstName": "Andrea",
    "lastName": "Rossi",
    "phoneNumber": "+39 123 456 7890"
  }
}
```

***

### 6. View Login History

**Request:**
```bash
curl http://localhost:4000/auth/login-history \
  -b cookies.txt
```

**Response:**
```json
{
  "history": [
    {
      "id": "65f1234567890abcdef12346",
      "timestamp": "2026-02-12T11:05:00.000Z",
      "ipAddress": "127.0.0.1",
      "userAgent": "curl/7.88.1",
      "device": "Other",
      "browser": "Unknown",
      "os": "Unknown",
      "success": true
    },
    {
      "id": "65f1234567890abcdef12347",
      "timestamp": "2026-02-12T11:00:00.000Z",
      "ipAddress": "127.0.0.1",
      "userAgent": "curl/7.88.1",
      "device": "Other",
      "browser": "Unknown",
      "os": "Unknown",
      "success": true
    }
  ],
  "total": 2
}
```

***

### 7. List Active Sessions

**Request:**
```bash
curl http://localhost:4000/auth/refresh-tokens \
  -b cookies.txt
```

**Response:**
```json
{
  "tokens": [
    {
      "id": "65f1234567890abcdef12348",
      "createdAt": "2026-02-12T11:05:00.000Z",
      "lastUsedAt": "2026-02-12T11:10:00.000Z",
      "expiresAt": "2026-02-19T11:05:00.000Z",
      "device": "curl",
      "ipAddress": "127.0.0.1",
      "isCurrentToken": true
    }
  ],
  "total": 1
}
```

***

### 8. Change Password

**Request:**
```bash
curl -X POST http://localhost:4000/auth/change-password \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -c cookies.txt \
  -d '{
    "currentPassword": "Demo123!",
    "newPassword": "NewPass123!"
  }'
```

**Response:**
```json
{
  "message": "Password changed successfully. All sessions revoked."
}
```

**What happens:**
- Password updated with bcrypt
- ALL refresh tokens revoked (security measure)
- New tokens issued automatically
- Audit log entry created

***

### 9. Password Reset Flow

#### Step 1: Request Password Reset

**Request:**
```bash
curl -X POST http://localhost:4000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -d '{
    "email": "demo@example.com"
  }'
```

**Response:**
```json
{
  "message": "If that email exists, a password reset link has been sent"
}
```

**Check your server console** - you'll see the mock email with reset token:
```
📧 [Mock Email] Sending email to: demo@example.com
📧 Subject: Password Reset Request
📧 Reset Token: a1b2c3d4e5f6g7h8i9j0...
📧 Reset URL: http://localhost:4200/reset-password?token=a1b2c3d4e5f6g7h8i9j0...
```

**Copy the token from console.**

#### Step 2: Verify Reset Token (Optional)

**Request:**
```bash
curl -X POST http://localhost:4000/auth/verify-reset-token \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_TOKEN_FROM_CONSOLE"
  }'
```

**Response:**
```json
{
  "valid": true,
  "message": "Token is valid"
}
```

#### Step 3: Reset Password

**Request:**
```bash
curl -X POST http://localhost:4000/auth/reset-password \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -d '{
    "token": "YOUR_TOKEN_FROM_CONSOLE",
    "newPassword": "NewPass123!",
    "confirmPassword": "NewPass123!"
  }'
```

**Response:**
```json
{
  "message": "Password reset successful"
}
```

**What happens:**
- Password updated
- Reset token deleted
- ALL refresh tokens revoked
- User must login again

***

### 10. Logout from Current Device

**Request:**
```bash
curl -X POST http://localhost:4000/auth/revoke-token \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt
```

**Response:**
```json
{
  "message": "Token revoked successfully"
}
```

**What happens:**
- Current refresh token revoked in database
- Cookies cleared
- Access token still valid until expiry (15min)

***

### 11. Logout from All Devices

**Request:**
```bash
curl -X POST http://localhost:4000/auth/revoke-all-tokens \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt
```

**Response:**
```json
{
  "message": "All tokens revoked successfully"
}
```

**What happens:**
- ALL refresh tokens revoked
- All active sessions terminated
- User logged out everywhere

***

## Admin Testing

### Make User Admin

First, promote your user to admin role:

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

**Login again** to get new tokens with admin role.

***

### List All Users (Admin)

**Request:**
```bash
curl "http://localhost:4000/admin/users?page=1&limit=10" \
  -b cookies.txt
```

**Response:**
```json
{
  "users": [
    {
      "id": "65f1234567890abcdef12345",
      "username": "demo",
      "email": "demo@example.com",
      "role": "admin",
      "createdAt": "2026-02-12T11:00:00.000Z"
    }
  ],
  "pagination": {
    "total": 1,
    "page": 1,
    "limit": 10,
    "totalPages": 1
  }
}
```

***

### Search Users (Admin)

**Request:**
```bash
curl "http://localhost:4000/admin/users?search=demo&role=admin" \
  -b cookies.txt
```

***

### Get User Details (Admin)

**Request:**
```bash
curl http://localhost:4000/admin/users/65f1234567890abcdef12345 \
  -b cookies.txt
```

**Response:**
```json
{
  "user": {
    "id": "65f1234567890abcdef12345",
    "username": "demo",
    "email": "demo@example.com",
    "role": "admin",
    "firstName": "Andrea",
    "lastName": "Rossi"
  },
  "activeTokensCount": 1,
  "createdAt": "2026-02-12T11:00:00.000Z",
  "updatedAt": "2026-02-12T11:15:00.000Z"
}
```

***

### Change User Role (Admin)

**Request:**
```bash
curl -X PUT http://localhost:4000/admin/users/USER_ID/role \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -c cookies.txt \
  -d '{
    "role": "customer"
  }'
```

**Response:**
```json
{
  "message": "User role updated. All active sessions revoked.",
  "user": {
    "id": "USER_ID",
    "role": "customer"
  }
}
```

***

### Ban User (Admin)

**Request:**
```bash
curl -X PUT http://localhost:4000/admin/users/USER_ID/ban \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -c cookies.txt \
  -d '{
    "reason": "Violation of terms of service"
  }'
```

**Response:**
```json
{
  "message": "User banned successfully",
  "user": {
    "id": "USER_ID",
    "banned": true,
    "banReason": "Violation of terms of service"
  }
}
```

***

### Unban User (Admin)

**Request:**
```bash
curl -X PUT http://localhost:4000/admin/users/USER_ID/unban \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt \
  -c cookies.txt
```

**Response:**
```json
{
  "message": "User unbanned successfully",
  "user": {
    "id": "USER_ID",
    "banned": false
  }
}
```

***

### Delete User (Admin)

**Request:**
```bash
curl -X DELETE http://localhost:4000/admin/users/USER_ID \
  -H "X-CSRF-Token: YOUR_CSRF_TOKEN_HERE" \
  -b cookies.txt
```

**Response:**
```json
{
  "message": "User deleted successfully",
  "deletedUser": {
    "id": "USER_ID",
    "username": "demo",
    "email": "demo@example.com"
  }
}
```

***

### Platform Statistics (Admin)

**Request:**
```bash
curl http://localhost:4000/admin/stats \
  -b cookies.txt
```

**Response:**
```json
{
  "totalUsers": 15,
  "totalCustomers": 12,
  "totalAdmins": 3,
  "activeTokens": 8,
  "newUsersLast30Days": 5,
  "timestamp": "2026-02-12T11:30:00.000Z"
}
```

***

### Audit Logs (Admin)

**Request:**
```bash
curl "http://localhost:4000/admin/audit-logs?page=1&limit=20" \
  -b cookies.txt
```

**Response:**
```json
{
  "logs": [
    {
      "id": "65f1234567890abcdef12349",
      "action": "PASSWORD_CHANGED",
      "user": {
        "id": "65f1234567890abcdef12345",
        "username": "demo",
        "email": "demo@example.com"
      },
      "success": true,
      "timestamp": "2026-02-12T11:20:00.000Z",
      "ipAddress": "127.0.0.1"
    }
  ],
  "pagination": {
    "total": 1,
    "page": 1,
    "limit": 20,
    "totalPages": 1
  }
}
```

***

## Testing with Postman/Insomnia

### Setup

1. **Enable Cookie Jar**
   - Postman: Settings → Enable "Automatically follow redirects" and "Cookie jar"
   - Insomnia: Preferences → Enable "Automatically manage cookies"

2. **Create Environment**
   ```json
   {
     "baseUrl": "http://localhost:4000",
     "csrfToken": ""
   }
   ```

### Workflow

#### 1. Get CSRF Token

```
GET {{baseUrl}}/auth/csrf-token
```

**After request:** Copy `csrfToken` from response and save to environment variable.

#### 2. Login

```
POST {{baseUrl}}/auth/login
Headers:
  Content-Type: application/json
  X-CSRF-Token: {{csrfToken}}
Body:
{
  "email": "demo@example.com",
  "password": "Demo123!"
}
```

**Cookies are now stored automatically!**

#### 3. Test Protected Endpoint

```
GET {{baseUrl}}/auth/profile
```

No headers needed - cookies sent automatically!

#### 4. Test Protected Mutation

```
PATCH {{baseUrl}}/auth/profile
Headers:
  Content-Type: application/json
  X-CSRF-Token: {{csrfToken}}
Body:
{
  "firstName": "Andrea"
}
```

***

## Testing with Swagger UI

### Access Swagger

Open http://localhost:4000/api-docs in your browser.

### Workflow

1. **Get CSRF Token**
   - Execute `GET /auth/csrf-token`
   - Copy the `csrfToken` from response

2. **Login**
   - Execute `POST /auth/login`
   - Add `X-CSRF-Token` header manually (Swagger doesn't auto-add it)
   - Cookies are set automatically in browser

3. **Test Protected Endpoints**
   - Browser automatically sends cookies
   - Remember to add `X-CSRF-Token` header for POST/PUT/PATCH/DELETE

**Note:** Swagger UI has limited cookie support. For full testing, use curl or Postman.

***

## Troubleshooting

### "CSRF token invalid or missing"

**Symptoms:**
```json
{ "error": "CSRF token invalid or missing" }
```

**Solutions:**
1. Fetch fresh CSRF token: `GET /auth/csrf-token`
2. Include `X-CSRF-Token` header in request
3. Ensure cookies are sent (use `-b cookies.txt`)

***

### "Unauthorized" (401)

**Symptoms:**
```json
{ "error": "Unauthorized" }
```

**Solutions:**
1. Check if cookies are being sent: `curl -v -b cookies.txt <url>`
2. Login again to refresh tokens
3. Ensure access token hasn't expired (15min lifetime)

***

### Cookies Not Saved

**Symptoms:**
- Authenticated requests fail
- No cookies in `cookies.txt`

**Solutions:**
1. Use `-c cookies.txt` to save cookies
2. Check response headers for `Set-Cookie`
3. Ensure CORS is configured: `ALLOWED_ORIGINS` in `.env`

***

### "Forbidden" (403)

**Symptoms:**
```json
{ "error": "Access denied" }
```

**Solutions:**
1. Check user role (customer vs admin)
2. Ensure CSRF token is included for mutations
3. Verify endpoint requires your role

***

## Tips & Best Practices

### 1. Use jq for Pretty JSON

```bash
curl http://localhost:4000/auth/profile -b cookies.txt | jq
```

### 2. View Response Headers

```bash
curl -v http://localhost:4000/auth/login ... | grep Set-Cookie
```

### 3. Test Token Expiry

```bash
# Wait 15+ minutes after login
curl http://localhost:4000/auth/profile -b cookies.txt
# Should return 401, triggering auto-refresh in frontend
```

### 4. Clean Start

```bash
# Delete cookies and start fresh
rm cookies.txt
curl -X GET http://localhost:4000/auth/csrf-token -c cookies.txt
```

### 5. Monitor Server Logs

```bash
# In another terminal
docker-compose logs -f auth-server
```

***

## Additional Resources

- [Main Documentation](./README.md)
- [Frontend Integration Guide](./FRONTEND_INTEGRATION.md)
- [Swagger UI](http://localhost:4000/api-docs)
- [curl Documentation](https://curl.se/docs/manpage.html)

***

**Made by [anp3l](https://github.com/anp3l)**