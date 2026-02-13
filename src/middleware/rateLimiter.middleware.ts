import rateLimit from 'express-rate-limit';

/**
 * Rate limiter for authentication endpoints.
 * Limits to 5 attempts every 15 minutes to prevent brute force attacks.
 */
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuts
  max: 5, // Max 5 requests for IP
  message: {
    error: 'Too many authentication attempts, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Skip for whitelisted IPs (optional)
  skip: (req) => {
    // Example: skip localhost in development
    return process.env.NODE_ENV === 'development' && req.ip === '::1';
  }
});

/**
 * Rate limiter for general API endpoints.
 * Limits to 100 requests every 15 minutes.
 */
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: {
    error: 'Too many requests, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
});

export const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Max 10 refreshes in 15 minutes
  message: 'Too many refresh attempts'
});
