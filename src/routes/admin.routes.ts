import { Router, Response } from 'express';
import { User } from '../models/user.model';
import { RefreshToken } from '../models/refreshToken.model';
import { verifyToken, AuthRequest } from '../middleware/auth.middleware';
import { authorize } from '../middleware/authorize.middleware';
import { body, param, query } from 'express-validator';
import { validateRequest } from '../middleware/validateRequest.middleware';
import { logAuditAction } from '../services/audit.service';
import { AuditLog } from '../models/auditLog.model';

const router = Router();

//All admin endpoints require authentication + admin role
router.use(verifyToken, authorize(['admin']));

/**
 * @swagger
 * /admin/users:
 *   get:
 *     summary: Get all users (Admin only)
 *     description: Retrieve a paginated list of all users with optional filtering
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           minimum: 1
 *           default: 1
 *         description: Page number
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 10
 *         description: Number of users per page
 *       - in: query
 *         name: role
 *         schema:
 *           type: string
 *           enum: [customer, admin]
 *         description: Filter by role
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search by username or email
 *     responses:
 *       200:
 *         description: List of users
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 users:
 *                   type: array
 *                 pagination:
 *                   type: object
 *                   properties:
 *                     total:
 *                       type: number
 *                     page:
 *                       type: number
 *                     limit:
 *                       type: number
 *                     totalPages:
 *                       type: number
 *       403:
 *         description: Forbidden - Admin only
 *       500:
 *         description: Server error
 */
router.get('/users', async (req: AuthRequest, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 10, 100);
    const role = req.query.role as string;
    const search = req.query.search as string;

    // Build query
    const query: any = {};
    
    if (role) {
      query.role = role;
    }
    
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    // Get total count
    const total = await User.countDocuments(query);
    
    // Get paginated users
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      users,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to retrieve users' });
  }
});

/**
 * @swagger
 * /admin/users/{id}:
 *   get:
 *     summary: Get user by ID (Admin only)
 *     description: Retrieve detailed information about a specific user
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       200:
 *         description: User details
 *       403:
 *         description: Forbidden - Admin only
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.get('/users/:id', 
  param('id').isMongoId().withMessage('Invalid user ID'),
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const user = await User.findById(req.params.id).select('-password');
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Get active refresh tokens count
      const activeTokensCount = await RefreshToken.countDocuments({
        user: user._id,
        revoked: { $exists: false },
        expires: { $gt: new Date() }
      });

      res.json({
        user,
        activeTokensCount,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      });

    } catch (error) {
      console.error('Get user error:', error);
      res.status(500).json({ error: 'Failed to retrieve user' });
    }
  }
);

/**
 * @swagger
 * /admin/users/{id}/role:
 *   put:
 *     summary: Update user role (Admin only)
 *     description: Change a user's role between customer and admin
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - role
 *             properties:
 *               role:
 *                 type: string
 *                 enum: [customer, admin]
 *                 example: admin
 *     responses:
 *       200:
 *         description: Role updated successfully
 *       400:
 *         description: Invalid role or cannot modify own role
 *       403:
 *         description: Forbidden - Admin only
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.put('/users/:id/role',
  param('id').isMongoId().withMessage('Invalid user ID'),
  body('role').isIn(['customer', 'admin']).withMessage('Role must be customer or admin'),
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const { role } = req.body;
      
      // Prevent admin from changing their own role
      if (req.params.id === req.userId) {
        return res.status(400).json({ error: 'Cannot modify your own role' });
      }

      const user = await User.findByIdAndUpdate(
        req.params.id,
        { role, updatedAt: new Date() },
        { new: true, runValidators: true }
      ).select('-password');

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // LOG AUDIT: Role changed by admin
      await logAuditAction(
        'ROLE_CHANGED', 
        req, 
        user._id.toString(), 
        req.userId,
        {
          newRole: role,
          targetUser: {
            email: user.email,
            username: user.username
          }
        }
      );

      // Revoke all refresh tokens when role changes (security measure)
      await RefreshToken.updateMany(
        { user: user._id, revoked: { $exists: false } },
        { 
          revoked: new Date(),
          revokedByIp: 'admin-role-change'
        }
      );

      res.json({
        message: 'User role updated. All active sessions revoked.',
        user
      });

    } catch (error) {
      console.error('Update role error:', error);
      res.status(500).json({ error: 'Failed to update user role' });
    }
  }
);

/**
 * @swagger
 * /admin/users/{id}:
 *   delete:
 *     summary: Delete/Disable user (Admin only)
 *     description: Soft delete a user account and revoke all tokens
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       200:
 *         description: User deleted successfully
 *       400:
 *         description: Cannot delete own account
 *       403:
 *         description: Forbidden - Admin only
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.delete('/users/:id',
  param('id').isMongoId().withMessage('Invalid user ID'),
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      // Prevent admin from deleting their own account
      if (req.params.id === req.userId) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
      }

      const user = await User.findByIdAndDelete(req.params.id);

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // LOG AUDIT: User deleted by admin
      await logAuditAction(
        'USER_DELETED_BY_ADMIN', 
        req, 
        user._id.toString(), 
        req.userId, // Admin who performed the action
        {
          deletedUser: {
            email: user.email,
            username: user.username,
            role: user.role
          }
        }
      );

      // Revoke all refresh tokens
      await RefreshToken.deleteMany({ user: user._id });

      res.json({
        message: 'User deleted successfully',
        deletedUser: {
          id: user._id,
          username: user.username,
          email: user.email
        }
      });

    } catch (error) {
      console.error('Delete user error:', error);
      res.status(500).json({ error: 'Failed to delete user' });
    }
  }
);

/**
 * @swagger
 * /admin/stats:
 *   get:
 *     summary: Get platform statistics (Admin only)
 *     description: Retrieve statistics about users and platform usage
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Platform statistics
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 totalUsers:
 *                   type: number
 *                 totalCustomers:
 *                   type: number
 *                 totalAdmins:
 *                   type: number
 *                 activeTokens:
 *                   type: number
 *                 newUsersLast30Days:
 *                   type: number
 *       403:
 *         description: Forbidden - Admin only
 *       500:
 *         description: Server error
 */
router.get('/stats', async (req: AuthRequest, res: Response) => {
  try {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const [
      totalUsers,
      totalCustomers,
      totalAdmins,
      activeTokens,
      newUsersLast30Days
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ role: 'customer' }),
      User.countDocuments({ role: 'admin' }),
      RefreshToken.countDocuments({
        revoked: { $exists: false },
        expires: { $gt: new Date() }
      }),
      User.countDocuments({
        createdAt: { $gte: thirtyDaysAgo }
      })
    ]);

    res.json({
      totalUsers,
      totalCustomers,
      totalAdmins,
      activeTokens,
      newUsersLast30Days,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve statistics' });
  }
});

/**
 * @swagger
 * /admin/audit-logs:
 *   get:
 *     summary: Get audit logs (Admin only)
 *     description: Retrieve audit logs with filtering and pagination
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *           maximum: 100
 *       - in: query
 *         name: action
 *         schema:
 *           type: string
 *         description: Filter by action type
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *         description: Filter by user ID
 *       - in: query
 *         name: success
 *         schema:
 *           type: boolean
 *         description: Filter by success status
 *     responses:
 *       200:
 *         description: Audit logs retrieved
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Server error
 */
router.get('/audit-logs', async (req: AuthRequest, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    const action = req.query.action as string;
    const userId = req.query.userId as string;
    const success = req.query.success as string;

    const query: any = {};
    
    if (action) query.action = action;
    if (userId) query.user = userId;
    if (success !== undefined) query.success = success === 'true';

    const total = await AuditLog.countDocuments(query);
    
    const logs = await AuditLog.find(query)
      .populate('user', 'username email')
      .populate('performedBy', 'username email')
      .sort({ timestamp: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    res.json({
      logs,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Failed to retrieve audit logs' });
  }
});

/**
 * @swagger
 * /admin/users/{id}/audit-logs:
 *   get:
 *     summary: Get audit logs for specific user (Admin only)
 *     description: Retrieve all audit logs related to a specific user
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *     responses:
 *       200:
 *         description: User audit logs
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.get('/users/:id/audit-logs',
  param('id').isMongoId().withMessage('Invalid user ID'),
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);

      const user = await User.findById(req.params.id);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      const logs = await AuditLog.find({ user: req.params.id })
        .populate('performedBy', 'username email')
        .sort({ timestamp: -1 })
        .limit(limit);

      res.json({ 
        logs,
        total: logs.length,
        user: {
          id: user._id,
          username: user.username,
          email: user.email
        }
      });

    } catch (error) {
      console.error('Get user audit logs error:', error);
      res.status(500).json({ error: 'Failed to retrieve user audit logs' });
    }
  }
);

export default router;
