import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PUB_KEY } from '../config/keys';

export interface AuthRequest extends Request {
  userId?: string;
  userRole?: string;
  username?: string;
}

/**
 * Middleware to verify JWT tokens in the Authorization header.
 */
export const verifyToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, PUB_KEY, { algorithms: ['RS256'] }) as { 
      userId: string
      username: string;
      role: string;
    };
    
    req.userId = decoded.userId;
    req.username = decoded.username;
    req.userRole = decoded.role;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};
