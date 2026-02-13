import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { NODE_ENV } from '../config/env';


export interface AuthRequest extends Request {
  userId?: string;
  userRole?: string;
  username?: string;
}

const publicKeyPath = path.join(__dirname, '../../public.pem');
let PUB_KEY: string;
try {
  PUB_KEY = fs.readFileSync(publicKeyPath, 'utf8');
} catch (error) {
  // Fallback: if the public key is missing, the auth server could derive it from the private key
  // but for simplicity we assume it exists, as in the video server
  console.error('Missing public.pem in Auth Server middleware');
  throw new Error('Public key not found');
}

/**
 * Middleware to verify JWT tokens in the Authorization header.
 * 
 * Extracts the Bearer token from the request's Authorization header,
 * verifies it using RS256 algorithm with a public key, and attaches
 * the decoded userId to the request object if valid.
 * 
 * @param req - The Express request object with custom AuthRequest interface
 * @param res - The Express response object
 * @param next - The Express next function to proceed to the next middleware
 * @returns Sends a 401 error response if token is missing or invalid, otherwise calls next()
 * 
 * @throws Will return 401 status if:
 *   - Authorization header is missing or doesn't start with 'Bearer '
 *   - Token verification fails (invalid signature, expired, etc.)
 */
export const verifyToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  //Try cookies first (priority)
  let token = req.cookies?.accessToken;
  
  // Fallback: Authorization header (for compatibility)
  if (!token && NODE_ENV !== 'production') {
    // Fallback ONLY in development
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    }
  }

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, PUB_KEY, { algorithms: ['RS256'] }) as { 
      userId: string;
      username: string;
      role: string;
    };
    
    req.userId = decoded.userId;
    req.username = decoded.username;
    req.userRole = decoded.role;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
};

