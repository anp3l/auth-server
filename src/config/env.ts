import dotenv from 'dotenv';
dotenv.config();

if (!process.env.MONGO_URI) {
  throw new Error('Missing: process.env.MONGO_URI');
}

export const MONGO_URI = process.env.MONGO_URI;
export const NODE_ENV = process.env.NODE_ENV || 'development';
export const ENABLE_LOGS = process.env.ENABLE_LOGS === 'true';
export const PORT = process.env.PORT;

// JWT Token Configuration
export const ACCESS_TOKEN_EXPIRY = process.env.ACCESS_TOKEN_EXPIRY || '15m';
export const REFRESH_TOKEN_EXPIRY = process.env.REFRESH_TOKEN_EXPIRY || '7d';

// CORS Origins (production)
export const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : ['http://localhost:3000', 'http://localhost:4200']; // Default Angular + fallback

export const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:4200';

export const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || 'localhost';
export const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
export const COOKIE_SAMESITE = process.env.COOKIE_SAMESITE || 'strict';
export const CSRF_SECRET = process.env.CSRF_SECRET!;