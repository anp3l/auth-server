
import { Response, NextFunction } from 'express';
import { AuthRequest } from './auth.middleware';
import { User } from '../models/user.model';


/**
 * Authorization middleware factory that verifies the authenticated user's role.
 *
 * This factory returns an Express middleware which:
 * - Expects `req.userId` to be set (e.g. by a preceding token verification middleware).
 * - Loads the user's role from the database (selecting only the 'role' field).
 * - If no `req.userId` or user is found, responds with HTTP 401 Unauthorized.
 * - If a non-empty `roles` array is provided and the user's role is not included, responds with HTTP 403 Forbidden.
 * - Calls `next()` when authorization succeeds.
 * - Catches unexpected errors and responds with HTTP 500.
 *
 * @param roles - Array of allowed role names. When empty (default), any authenticated user is allowed.
 * @returns An Express middleware function: (req: AuthRequest, res: Response, next: NextFunction) => Promise<void>
 *
 * @example
 * // Allow only admins
 * app.get('/admin', authorize(['admin']), adminHandler);
 *
 * @example
 * // Allow any authenticated user
 * app.get('/profile', authorize(), profileHandler);
 */
export const authorize = (roles: string[] = []) => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const user = await User.findById(req.userId).select('role');
      
      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }

      // if roles is empty, allow any authenticated user
      if (roles.length && !roles.includes(user.role)) {
        return res.status(403).json({ 
          error: 'Forbidden',
          message: `Role '${user.role}' is not authorized to access this resource` 
        });
      }

      next();
    } catch (error) {
      return res.status(500).json({ error: 'Authorization check failed' });
    }
  };
};
