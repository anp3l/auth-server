# Remote Video Library – Auth Server (Identity Provider)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-2496ED?logo=docker&logoColor=white)](#option-a-docker)

## Description


A robust, standalone **Authentication Microservice** built with Node.js and TypeScript.

While originally developed as the Identity Provider for the **[Remote Video Library](https://github.com/anp3l/remote-video-client)** ecosystem, this server is designed to be completely **agnostic**. It can be used "as-is" to handle authentication for **any project** requiring secure, stateless user management.

It acts as a centralized Authority, handling user registration, login, and secure token issuance using **RSA (RS256) signatures**. Any other service (Resource Server) can simply verify the issued tokens using the public key, enabling a true microservices architecture.


---

## Features

- 🔐 **RSA-Signed JWTs (RS256):**: Issues RS256 tokens using a private key loaded from environment variables (recommended) or from local PEM files (dev fallback).
    
- 🛡️ **Secure Password Hashing**: Uses `bcrypt` for password storage.
    
- 📝 **Input Validation**: Strict validation for emails and usernames.
    
- ⚡ **Stateless Architecture**: Fully RESTful and scalable.
    
- 📄 **Documentation**: Full Swagger/OpenAPI UI.
    

---

## Usage Scenarios

- **Microservices Auth**: Centralized login for multiple backend services.
- **Standalone App**: Quick auth backend for a React/Angular/Mobile app.
- **Cross-Domain Identity**: Verify users across different domains using public-key cryptography.

---

## Setup & Installation

## 1. Clone the repository

```
git clone https://github.com/anp3l/auth-server.git
cd auth-server
```

## 2. Configuration & Keys

1.  **Copy the example environment file:**
    
    ```
    cp .env.example .env
    ```
    
2.  **Generate RSA keys (local dev / initial setup):**  
    
    ```
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -pubout -out public.pem
    ```
3. **Store keys in environment variables (recommended):**
    PEM files are multi-line; to avoid newline escaping issues, store them as Base64 and decode at runtime.

    **Mac / Linux**
    ```
    cat private.pem | base64 | tr -d '\n'
    cat public.pem | base64 | tr -d '\n'
    ```
    **Windows (PowerShell)**
    ```
    [Convert]::ToBase64String([IO.File]::ReadAllBytes("./private.pem"))
    [Convert]::ToBase64String([IO.File]::ReadAllBytes("./public.pem"))
    ```
4. **Update your `.env`:**
    ```
    PORT=4000
    MONGO_URI=mongodb://auth-mongo:27017/authdb

    PRIVATE_KEY_BASE64=...
    PUBLIC_KEY_BASE64=...
    ```

> Note: Never commit secrets. Keep `.env` and any `.pem` files out of Git.

    

## 3. Choose your Setup Method

## Option A: Docker (Recommended)

Includes MongoDB pre-configured.

- **Build and start:**
    
    ```
    docker-compose up --build
    ```
    
- **Server running at:** [http://localhost:4000](http://localhost:4000/)
    

The container receives configuration via `env_file` (the `.env` file) so you don't need to mount PEM files as volumes.

## Option B: Manual Setup

Requires **Node.js v18+** and **MongoDB**.

1.  **Install dependencies:**
    
    ```
    npm install
    ```
    
2.  **Start MongoDB:**
    
    - Ensure MongoDB is running locally on port 27017.

3.  **Start Server:**
    
    ```
    npm run dev
    ```
    

---

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/auth/signup` | Register a new user (returns JWT) |
| POST | `/auth/login` | Login with email/password (returns JWT) |
| GET | `/health` | Server health check |

- **Full Swagger (OpenAPI) available at:** http://localhost:4000/api-docs

---

## How it works (Auth Flow)

1.  **Client Request**: Frontend sends credentials to `POST /auth/login`.
    
2.  **Validation**: Server verifies email format and password strength.
    
3.  **Authentication**: Checks credentials against MongoDB (hashed passwords).
    
4.  **Token Issuance**: If valid, the server signs a JWT using the **Private Key** (RS256).
    
5.  **Verification**: The client sends this token to the **Video Server**, which verifies it using the corresponding **RSA Public Key**.
    

---

## Development

- **Tech Stack**: Node.js, Express, TypeScript, Mongoose.
    
- **Security**: RS256 Algorithm, Bcrypt, Helmet, CORS.
    
---
## Roadmap & Future Architecture

This server is designed to evolve into a centralized Identity Authority for a federated ecosystem of Video Servers.

### Planned Features
- 🔄 **Key Rotation**: Automated rotation of RSA key pairs for enhanced security.
- 🌐 **JWKS Endpoint**: Implementation of `GET /.well-known/jwks.json` to expose public keys dynamically. This will allow Resource Servers (like the Video Server) to auto-configure themselves without manual key copying.
- 🔐 **Password Reset Flow**: Secure forgot/reset password mechanism via email tokens.
- 📧 **Email Verification**: Account confirmation loop upon registration.
- 🔐 **2FA**: Two-factor authentication support.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.