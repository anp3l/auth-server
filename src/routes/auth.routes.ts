import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import multer from 'multer';
import jwt, { SignOptions } from 'jsonwebtoken';
import { User } from '../models/user.model';
import { RefreshToken, generateRefreshToken } from '../models/refreshToken.model';
import { PRIV_KEY } from '../config/keys';
import { ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY } from '../config/env';
import { loginValidator, signupValidator, refreshTokenValidator, updateProfileValidator, updateEmailPreferencesValidator, addressValidator } from '../validators/auth.validators';
import { validateRequest } from '../middleware/validateRequest.middleware';
import { verifyToken, AuthRequest } from '../middleware/auth.middleware';
import { authLimiter } from '../middleware/rateLimiter.middleware';
import { changePasswordValidator } from '../validators/auth.validators';
import { body, param } from 'express-validator';
import { PasswordResetToken, generatePasswordResetToken } from '../models/passwordResetToken.model';
import { getEmailService } from '../services/email/email-service.factory';
import { forgotPasswordValidator, resetPasswordValidator } from '../validators/auth.validators';
import { logLoginAttempt, logAuditAction } from '../services/audit.service';
import { LoginHistory } from '../models/loginHistory.model';
import { avatarUpload, deleteAvatarFile } from '../middleware/upload.middleware';
import { ENABLE_LOGS, COOKIE_DOMAIN, COOKIE_SAMESITE, COOKIE_SECURE } from '../config/env';

const router = Router();

// === HELPER FUNCTIONS ===

/**
 * Generate short-lived JWT access tokens
 */
function generateAccessToken(userId: string, username: string, role: string): string {
  return jwt.sign(
    { userId, username, role },
    PRIV_KEY as jwt.Secret,
    { 
      algorithm: 'RS256',
      expiresIn: ACCESS_TOKEN_EXPIRY
    } as jwt.SignOptions
  );
}

/**
 * Generate and save refresh token in the database
 */
async function generateAndSaveRefreshToken(userId: string, ipAddress: string): Promise<string> {
  const token = generateRefreshToken();
  
  // Calculate expiry in milliseconds based on REFRESH_TOKEN_EXPIRY
  let expiryMs: number;
  
  if (REFRESH_TOKEN_EXPIRY.endsWith('d')) {
    const days = parseInt(REFRESH_TOKEN_EXPIRY.replace('d', ''));
    expiryMs = days * 24 * 60 * 60 * 1000;
  } else if (REFRESH_TOKEN_EXPIRY.endsWith('h')) {
    const hours = parseInt(REFRESH_TOKEN_EXPIRY.replace('h', ''));
    expiryMs = hours * 60 * 60 * 1000;
  } else if (REFRESH_TOKEN_EXPIRY.endsWith('m')) {
    const minutes = parseInt(REFRESH_TOKEN_EXPIRY.replace('m', ''));
    expiryMs = minutes * 60 * 1000;
  } else {
    // Default 7 days
    expiryMs = 7 * 24 * 60 * 60 * 1000;
  }
  
  const refreshToken = new RefreshToken({
    user: userId,
    token,
    expires: new Date(Date.now() + expiryMs),
    createdByIp: ipAddress
  });
  
  await refreshToken.save();
  
  // Cleanup old expired tokens
  await RefreshToken.deleteMany({
    user: userId,
    expires: { $lt: new Date() }
  });
  
  return token;
}

/**
 * IP address extraction helper
 */
function getIpAddress(req: Request): string {
  return (req.headers['x-forwarded-for'] as string)?.split(',')[0] || 
         req.socket.remoteAddress || 
         'unknown';
}

// === AUTH ENDPOINTS ===

/**
 * @swagger
 * /auth/signup:
 *   post:
 *     summary: Register a new user
 *     description: Create a new user account. Sets HttpOnly cookies with access token (15min) and refresh token (7 days).
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - email
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 minLength: 3
 *                 maxLength: 30
 *                 example: johndoe
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 example: SecurePass123!
 *               firstName:
 *                 type: string
 *                 example: John
 *               lastName:
 *                 type: string
 *                 example: Doe
 *     responses:
 *       201:
 *         description: User registered successfully. Authentication cookies set automatically.
 *         headers:
 *           Set-Cookie:
 *             description: HttpOnly cookies containing accessToken and refreshToken
 *             schema:
 *               type: string
 *               example: accessToken=eyJhbGc...; HttpOnly; Secure; SameSite=Strict
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User created
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: 507f1f77bcf86cd799439011
 *                     username:
 *                       type: string
 *                       example: johndoe
 *                     email:
 *                       type: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       enum: [customer, admin]
 *                       example: customer
 *       400:
 *         description: Validation error
 *       409:
 *         description: User already exists
 *       500:
 *         description: Server error
 */

router.post('/signup', authLimiter, signupValidator, validateRequest, async (req: Request, res: Response) => {
  try {
    const { username, email, password, firstName, lastName } = req.body;

    // Check if user already exists
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password with salt rounds 12 for security
    const hashedPassword = await bcrypt.hash(password, 12);
    
    const user = new User({ 
      username, 
      email, 
      password: hashedPassword,
      firstName,
      lastName,
      role: 'customer' // Default role
    });
    
    await user.save();

    // LOG AUDIT: Signup
    await logAuditAction('USER_SIGNUP', req, user._id.toString(), undefined, {
      email: user.email,
      username: user.username
    });

    // Generate access token (short-lived)
    const accessToken = generateAccessToken(user._id.toString(), user.username, user.role);
    
    // Generate refresh token (long duration)
    const refreshToken = await generateAndSaveRefreshToken(user._id.toString(), getIpAddress(req));

    // Send welcome email
    try {
      const emailService = getEmailService();
      await emailService.sendWelcomeEmail(user.email, user.username);
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
    }
    
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(201).json({ 
      message: 'User created',
      user: { 
        id: user._id, 
        username: user.username,
        email: user.email,
        role: user.role
      } 
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Authenticate a user
 *     description: User login with email and password. Sets HttpOnly cookies with access token and refresh token.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: SecurePass123!
 *     responses:
 *       200:
 *         description: Login successful. Authentication cookies set automatically.
 *         headers:
 *           Set-Cookie:
 *             description: HttpOnly cookies containing accessToken and refreshToken
 *             schema:
 *               type: string
 *               example: accessToken=eyJhbGc...; HttpOnly; Secure; SameSite=Strict
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Login successful
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: 507f1f77bcf86cd799439011
 *                     username:
 *                       type: string
 *                       example: johndoe
 *                     email:
 *                       type: string
 *                       example: john@example.com
 *                     role:
 *                       type: string
 *                       example: customer
 *                     firstName:
 *                       type: string
 *                       example: John
 *                     lastName:
 *                       type: string
 *                       example: Doe
 *                     avatar:
 *                       type: string
 *                       nullable: true
 *                       example: /uploads/avatars/johndoe.jpg
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid credentials
 *       403:
 *         description: Account banned or inactive
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Account suspended
 *                 reason:
 *                   type: string
 *                   example: Your account has been suspended. Contact support for more information.
 *       429:
 *         description: Too many login attempts
 *       500:
 *         description: Server error
 */

router.post('/login', authLimiter, loginValidator, validateRequest, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    
    if (!user) {
      // LOG: Login failed - user not found
      await logLoginAttempt(null, req, false, 'User not found');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.isBanned) {
      await logLoginAttempt(user._id.toString(), req, false, 'User is banned');
      return res.status(403).json({ 
        error: 'Account suspended', 
        reason: user.banReason || 'Your account has been suspended. Contact support for more information.'
      });
    }

    if (!user.isActive) {
      await logLoginAttempt(user._id.toString(), req, false, 'Account inactive');
      return res.status(403).json({ 
        error: 'Account inactive',
        message: 'Your account is not active. Please contact support.'
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      // LOG: Login failed - password incorrect
      await logLoginAttempt(user._id.toString(), req, false, 'Invalid password');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    user.lastLogin = new Date();
    await user.save();

    // LOG: Login successful
    await logLoginAttempt(user._id.toString(), req, true);

    // Generate access token
    const accessToken = generateAccessToken(user._id.toString(), user.username, user.role);
    
    // Generate refresh token
    const refreshToken = await generateAndSaveRefreshToken(user._id.toString(), getIpAddress(req));

    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      maxAge: 15 * 60 * 1000, // 15 minuts
    });

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ 
      message: 'Login successful',
      user: { 
        id: user._id, 
        username: user.username,
        email: user.email,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName,
        avatar: user.avatar
      } 
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

/**
 * @swagger
 * /auth/refresh-token:
 *   post:
 *     summary: Refresh access token
 *     description: Generate a new access token using the refresh token from HttpOnly cookies. Old tokens are automatically rotated.
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Tokens refreshed successfully. New cookies set automatically.
 *         headers:
 *           Set-Cookie:
 *             description: Updated HttpOnly cookies with new tokens
 *             schema:
 *               type: string
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Tokens refreshed successfully
 *       401:
 *         description: Invalid or expired refresh token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Refresh token not found
 *       500:
 *         description: Server error
 */

router.post('/refresh-token', async (req: Request, res: Response) => {
  try {
    const token = req.cookies.refreshToken; // Read from cookies
    
    if (!token) {
      return res.status(401).json({ error: 'Refresh token not found' });
    }
    
    const refreshToken = await RefreshToken.findOne({ token }).populate('user');
    
    if (!refreshToken || !refreshToken.isActive) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const user = refreshToken.user as any;

    // Revoke the old token
    refreshToken.revoked = new Date();
    refreshToken.revokedByIp = getIpAddress(req);
    
    // Generate new tokens
    const newAccessToken = generateAccessToken(user._id.toString(), user.username, user.role);
    const newRefreshToken = await generateAndSaveRefreshToken(user._id.toString(), getIpAddress(req));
    
    // Save reference to new token
    refreshToken.replacedByToken = newRefreshToken;
    await refreshToken.save();

    // Set cookies with new tokens
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ message: 'Tokens refreshed successfully' });

  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

/**
 * @swagger
 * /auth/revoke-token:
 *   post:
 *     summary: Revoke refresh token (logout)
 *     description: Invalidate refresh token to log out the user and clear authentication cookies. Refresh token is read from HttpOnly cookies automatically.
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful. Authentication cookies cleared.
 *         headers:
 *           Set-Cookie:
 *             description: Cleared authentication cookies
 *             schema:
 *               type: string
 *               example: accessToken=; Expires=Thu, 01 Jan 1970 00:00:00 GMT
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Logout successful
 *       400:
 *         description: Refresh token not found in cookies
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Refresh token not found in cookies
 *       401:
 *         description: Unauthorized or invalid token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid refresh token
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Token revocation failed
 */

router.post('/revoke-token', verifyToken, async (req: AuthRequest, res: Response) => {
  try {
    const token = req.cookies.refreshToken;
    
    if (!token) {
      return res.status(400).json({ error: 'Refresh token not found in cookies' });
    }
    
    const refreshToken = await RefreshToken.findOne({ token });
    
    if (!refreshToken || refreshToken.user.toString() !== req.userId) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Revoke the token
    refreshToken.revoked = new Date();
    refreshToken.revokedByIp = getIpAddress(req);
    await refreshToken.save();

    // LOG AUDIT: Logout
    await logAuditAction('USER_LOGOUT', req, req.userId);

    // Clear authentication cookies
    res.clearCookie('accessToken', { 
      httpOnly: true, 
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      ...(COOKIE_DOMAIN && { domain: COOKIE_DOMAIN })
    });
    
    res.clearCookie('refreshToken', { 
      httpOnly: true, 
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      ...(COOKIE_DOMAIN && { domain: COOKIE_DOMAIN })
    });

    res.json({ message: 'Logout successful' });

  } catch (error) {
    console.error('Revoke token error:', error);
    res.status(500).json({ error: 'Token revocation failed' });
  }
});

/**
 * @swagger
 * /auth/profile:
 *   get:
 *     summary: Get user profile
 *     description: Retrieve authenticated user's profile information
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                 username:
 *                   type: string
 *                 email:
 *                   type: string
 *                 role:
 *                   type: string
 *                 firstName:
 *                   type: string
 *                 lastName:
 *                   type: string
 *                 shippingAddress:
 *                   type: object
 *                 createdAt:
 *                   type: string
 *                   format: date-time
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */

router.get('/profile', verifyToken, async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);

  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Failed to retrieve profile' });
  }
});

/**
 * @swagger
 * /auth/profile:
 *   patch:
 *     summary: Update user profile (basic info)
 *     description: Update basic profile information. Only provided fields will be updated.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               firstName:
 *                 type: string
 *                 example: John
 *               lastName:
 *                 type: string
 *                 example: Doe
 *               email:
 *                 type: string
 *                 format: email
 *                 example: newemail@example.com
 *               phone:
 *                 type: string
 *                 example: +39 123 456 7890
 *               dateOfBirth:
 *                 type: string
 *                 format: date
 *                 example: 1990-01-15
 *               gender:
 *                 type: string
 *                 example: male
 *               bio:
 *                 type: string
 *                 example: Full-stack developer passionate about technology
 *               avatar:
 *                 type: string
 *                 example: https://example.com/avatars/newavatar.jpg
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Profile updated successfully
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: 507f1f77bcf86cd799439011
 *                     username:
 *                       type: string
 *                       example: johndoe
 *                     email:
 *                       type: string
 *                       example: newemail@example.com
 *                     role:
 *                       type: string
 *                       example: user
 *                     firstName:
 *                       type: string
 *                       example: John
 *                     lastName:
 *                       type: string
 *                       example: Doe
 *                     phone:
 *                       type: string
 *                       example: +39 123 456 7890
 *                     dateOfBirth:
 *                       type: string
 *                       format: date-time
 *                       example: 1990-01-15T00:00:00.000Z
 *                     gender:
 *                       type: string
 *                       example: male
 *                     bio:
 *                       type: string
 *                       example: Full-stack developer passionate about technology
 *                     avatar:
 *                       type: string
 *                       nullable: true
 *                       example: https://example.com/avatars/newavatar.jpg
 *       400:
 *         description: Validation error or invalid fields
 *         content:
 *           application/json:
 *             schema:
 *               oneOf:
 *                 - type: object
 *                   properties:
 *                     error:
 *                       type: string
 *                       example: No fields provided for update
 *                 - type: object
 *                   properties:
 *                     error:
 *                       type: string
 *                       example: Invalid fields
 *                     invalidFields:
 *                       type: array
 *                       items:
 *                         type: string
 *                       example: ["unknownField", "anotherInvalidField"]
 *                 - type: object
 *                   properties:
 *                     error:
 *                       type: string
 *                       example: Validation failed
 *                     details:
 *                       type: string
 *                       example: Invalid email format
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found
 *       409:
 *         description: Email already in use by another user
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Email already in use
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to update profile
 */

router.patch('/profile', 
  verifyToken,
  updateProfileValidator,
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const allowedFields = ['firstName', 'lastName', 'email', 'phone', 'dateOfBirth', 'gender', 'bio', 'avatar'];
      const updates = Object.keys(req.body);

      if (updates.length === 0) {
        return res.status(400).json({ error: 'No fields provided for update' });
      }

      const invalidFields = updates.filter(field => !allowedFields.includes(field));
      if (invalidFields.length > 0) {
        return res.status(400).json({ 
          error: 'Invalid fields', 
          invalidFields 
        });
      }

      if (req.body.email) {
        const existingUser = await User.findOne({ 
          email: req.body.email.toLowerCase(),
          _id: { $ne: req.userId } 
        });
        if (existingUser) {
          return res.status(409).json({ error: 'Email already in use' });
        }
      }

      const updateData: any = {};
      allowedFields.forEach(field => {
        if (req.body[field] !== undefined) {
          if (field === 'dateOfBirth') {
            updateData[field] = new Date(req.body[field]);
          } else if (field === 'email') {
            updateData[field] = req.body[field].toLowerCase();
          } else {
            updateData[field] = req.body[field];
          }
        }
      });

      const user = await User.findByIdAndUpdate(
        req.userId,
        { $set: updateData },
        { new: true, runValidators: true }
      ).select('-password');

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      await logAuditAction('PROFILE_UPDATED', req, req.userId, undefined, {
        updatedFields: Object.keys(updateData)
      });

      res.json({ 
        message: 'Profile updated successfully',
        user 
      });

    } catch (error) {
      console.error('Update profile error:', error);
      
      if ((error as any).name === 'ValidationError') {
        return res.status(400).json({ 
          error: 'Validation failed', 
          details: (error as any).message 
        });
      }
      
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }
);

/**
 * @swagger
 * /auth/change-password:
 *   post:
 *     summary: Change password
 *     description: Change authenticated user's password
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - currentPassword
 *               - newPassword
 *               - confirmPassword
 *             properties:
 *               currentPassword:
 *                 type: string
 *                 format: password
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *               confirmPassword:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Password changed successfully
 *       400:
 *         description: Validation error or incorrect current password
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */

router.post('/change-password', verifyToken, changePasswordValidator, validateRequest, async (req: AuthRequest, res: Response) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    user.updatedAt = new Date();
    await user.save();

    // LOG AUDIT: Password changed
    await logAuditAction('PASSWORD_CHANGED', req, user._id.toString());

    // Revoke all OLD refresh tokens for security (force re-login on all OTHER devices)
    await RefreshToken.updateMany(
      { user: user._id, revoked: { $exists: false } },
      { 
        revoked: new Date(),
        revokedByIp: 'password-change'
      }
    );

    // Generate NEW tokens for THIS device (keep user logged in)
    const newAccessToken = generateAccessToken(user._id.toString(), user.username, user.role);
    const newRefreshToken = await generateAndSaveRefreshToken(user._id.toString(), getIpAddress(req));

    // Set new cookies
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      maxAge: 15 * 60 * 1000,
    });

    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: COOKIE_SAMESITE as 'strict' | 'lax' | 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ 
      message: 'Password changed successfully. You have been logged out from all other devices for security.'
    });

  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});


// ==================== UPLOAD AVATAR ====================

/**
 * @swagger
 * /auth/avatar:
 *   post:
 *     summary: Upload user avatar
 *     description: Upload a new avatar image. Replaces existing avatar if present.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - avatar
 *             properties:
 *               avatar:
 *                 type: string
 *                 format: binary
 *                 description: Avatar image file (max 5MB, JPEG/PNG/GIF/WebP)
 *     responses:
 *       200:
 *         description: Avatar uploaded successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Avatar uploaded successfully
 *                 avatarUrl:
 *                   type: string
 *                   example: /uploads/avatars/1234567890-avatar.jpg
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: 507f1f77bcf86cd799439011
 *                     username:
 *                       type: string
 *                       example: johndoe
 *                     email:
 *                       type: string
 *                       example: john@example.com
 *                     avatar:
 *                       type: string
 *                       example: /uploads/avatars/1234567890-avatar.jpg
 *       400:
 *         description: No file uploaded, invalid file type, or file too large
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: File too large. Maximum size is 5MB
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to upload avatar
 */

router.post('/avatar',
  verifyToken,
  (req, res, next) => {
    avatarUpload.single('avatar')(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ error: 'File too large. Maximum size is 5MB' });
        }
        return res.status(400).json({ error: err.message });
      } else if (err) {
        return res.status(400).json({ error: err.message });
      }
      next();
    });
  },
  async (req: AuthRequest, res: Response) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      const user = await User.findById(req.userId);
      
      if (!user) {
        // Delete the newly loaded file if user does not exist
        await deleteAvatarFile(`/uploads/avatars/${req.file.filename}`);
        return res.status(404).json({ error: 'User not found' });
      }

      // Delete the old avatar if it exists
      if (user.avatar) {
        try {
          await deleteAvatarFile(user.avatar);
        } catch (error) {
          console.error('Failed to delete old avatar:', error);
          // Do not block the operation if deletion fails
        }
      }

      // Build public URL
      const avatarUrl = `/uploads/avatars/${req.file.filename}`;

      user.avatar = avatarUrl;
      await user.save();

      await logAuditAction('AVATAR_UPLOADED', req, req.userId, undefined, {
        filename: req.file.filename,
        size: req.file.size
      });

      res.json({ 
        message: 'Avatar uploaded successfully',
        avatarUrl,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          avatar: user.avatar
        }
      });

    } catch (error) {
      console.error('Upload avatar error:', error);
      
      // Cleanup: delete the file if something goes wrong
      if (req.file) {
        try {
          await deleteAvatarFile(`/uploads/avatars/${req.file.filename}`);
        } catch (cleanupError) {
          console.error('Failed to cleanup uploaded file:', cleanupError);
        }
      }
      
      res.status(500).json({ error: 'Failed to upload avatar' });
    }
  }
);

/**
 * @swagger
 * /auth/avatar:
 *   delete:
 *     summary: Delete user avatar
 *     description: Remove the current avatar and delete the file from server
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Avatar deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Avatar deleted successfully
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                       example: 507f1f77bcf86cd799439011
 *                     username:
 *                       type: string
 *                       example: johndoe
 *                     email:
 *                       type: string
 *                       example: john@example.com
 *                     avatar:
 *                       type: string
 *                       nullable: true
 *                       example: null
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User not found or no avatar to delete
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: No avatar to delete
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to delete avatar
 */

router.delete('/avatar',
  verifyToken,
  async (req: AuthRequest, res: Response) => {
    try {
      const user = await User.findById(req.userId);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (!user.avatar) {
        return res.status(404).json({ error: 'No avatar to delete' });
      }

      const avatarPath = user.avatar;

      // Delete the physical file
      try {
        await deleteAvatarFile(avatarPath);
      } catch (error) {
        console.error('Failed to delete avatar file:', error);
        // However, continue to remove the reference from the DB
      }

      // Remove reference from DB
      user.avatar = undefined;
      await user.save();

      await logAuditAction('AVATAR_DELETED', req, req.userId);

      res.json({ 
        message: 'Avatar deleted successfully',
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          avatar: user.avatar
        }
      });

    } catch (error) {
      console.error('Delete avatar error:', error);
      res.status(500).json({ error: 'Failed to delete avatar' });
    }
  }
);

/**
 * @swagger
 * /auth/avatar:
 *   get:
 *     summary: Get current user avatar URL
 *     description: Returns the avatar URL of the authenticated user
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Avatar URL retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 avatarUrl:
 *                   type: string
 *                   example: /uploads/avatars/1234567890-avatar.jpg
 *                 username:
 *                   type: string
 *                   example: johndoe
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User not found or no avatar set
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: No avatar set
 *                 message:
 *                   type: string
 *                   example: User has not uploaded an avatar yet
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to get avatar
 */

router.get('/avatar',
  verifyToken,
  async (req: AuthRequest, res: Response) => {
    try {
      const user = await User.findById(req.userId).select('avatar username');
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (!user.avatar) {
        return res.status(404).json({ 
          error: 'No avatar set',
          message: 'User has not uploaded an avatar yet'
        });
      }

      res.json({ 
        avatarUrl: user.avatar,
        username: user.username
      });

    } catch (error) {
      console.error('Get avatar error:', error);
      res.status(500).json({ error: 'Failed to get avatar' });
    }
  }
);


// ==================== GET USER STATS ====================

/**
 * @swagger
 * /auth/stats:
 *   get:
 *     summary: Get user statistics
 *     description: Returns statistics about user activity (orders, spending, etc.)
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User statistics retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 totalOrders:
 *                   type: number
 *                   example: 0
 *                 totalSpent:
 *                   type: number
 *                   example: 0
 *                 wishlistItems:
 *                   type: number
 *                   example: 0
 *                 savedAddresses:
 *                   type: number
 *                   example: 2
 *                 reviewsCount:
 *                   type: number
 *                   example: 0
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to retrieve stats
 */

router.get('/stats', verifyToken, async (req: AuthRequest, res: Response) => {
  try {
    const user = await User.findById(req.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // TODO: Implement logic to calculate real stats
    // mock 
    const stats = {
      totalOrders: 0,
      totalSpent: 0,
      wishlistItems: 0,
      savedAddresses: user.addresses?.length || 0,
      reviewsCount: 0
    };

    res.json(stats);

  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve stats' });
  }
});

/**
 * @swagger
 * /auth/profile/email-preferences:
 *   patch:
 *     summary: Update email preferences
 *     description: Update user email notification preferences, language, and currency
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newsletter:
 *                 type: boolean
 *                 example: true
 *               notifications:
 *                 type: boolean
 *                 example: false
 *               language:
 *                 type: string
 *                 example: en
 *               currency:
 *                 type: string
 *                 example: EUR
 *     responses:
 *       200:
 *         description: Email preferences updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Email preferences updated
 *                 emailPreferences:
 *                   type: object
 *                   properties:
 *                     newsletter:
 *                       type: boolean
 *                       example: true
 *                     notifications:
 *                       type: boolean
 *                       example: false
 *                     language:
 *                       type: string
 *                       example: en
 *                     currency:
 *                       type: string
 *                       example: EUR
 *       400:
 *         description: No preferences provided or validation error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: No preferences provided
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to update preferences
 */

router.patch('/profile/email-preferences', 
  verifyToken,
  updateEmailPreferencesValidator,
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const updates: any = {};
      
      if (req.body.newsletter !== undefined) {
        updates['emailPreferences.newsletter'] = req.body.newsletter;
      }
      if (req.body.notifications !== undefined) {
        updates['emailPreferences.notifications'] = req.body.notifications;
      }
      if (req.body.language !== undefined) {
        updates['emailPreferences.language'] = req.body.language;
      }
      if (req.body.currency !== undefined) {
        updates['emailPreferences.currency'] = req.body.currency;
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: 'No preferences provided' });
      }

      const user = await User.findByIdAndUpdate(
        req.userId,
        { $set: updates },
        { new: true, runValidators: true }
      ).select('-password');

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      await logAuditAction('EMAIL_PREFERENCES_UPDATED', req, req.userId);

      res.json({ 
        message: 'Email preferences updated',
        emailPreferences: user.emailPreferences 
      });

    } catch (error) {
      console.error('Update email preferences error:', error);
      res.status(500).json({ error: 'Failed to update preferences' });
    }
  }
);

/**
 * @swagger
 * /auth/profile/addresses:
 *   post:
 *     summary: Add a new address
 *     description: Add a new shipping or billing address. First address is automatically set as default.
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - lastName
 *               - addressLine1
 *               - city
 *               - postalCode
 *               - country
 *               - phone
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [shipping, billing]
 *                 default: shipping
 *                 example: shipping
 *               firstName:
 *                 type: string
 *                 example: John
 *               lastName:
 *                 type: string
 *                 example: Doe
 *               company:
 *                 type: string
 *                 example: Acme Corp
 *               addressLine1:
 *                 type: string
 *                 example: Via Roma 123
 *               addressLine2:
 *                 type: string
 *                 example: Apartment 4B
 *               city:
 *                 type: string
 *                 example: Milano
 *               state:
 *                 type: string
 *                 example: MI
 *               postalCode:
 *                 type: string
 *                 example: 20100
 *               country:
 *                 type: string
 *                 example: Italy
 *               phone:
 *                 type: string
 *                 example: +39 123 456 7890
 *               isDefault:
 *                 type: boolean
 *                 example: false
 *     responses:
 *       201:
 *         description: Address added successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Address added successfully
 *                 address:
 *                   type: object
 *                   properties:
 *                     _id:
 *                       type: string
 *                       example: 507f1f77bcf86cd799439011
 *                     type:
 *                       type: string
 *                       example: shipping
 *                     firstName:
 *                       type: string
 *                       example: John
 *                     lastName:
 *                       type: string
 *                       example: Doe
 *                     company:
 *                       type: string
 *                       example: Acme Corp
 *                     addressLine1:
 *                       type: string
 *                       example: Via Roma 123
 *                     addressLine2:
 *                       type: string
 *                       example: Apartment 4B
 *                     city:
 *                       type: string
 *                       example: Milano
 *                     state:
 *                       type: string
 *                       example: MI
 *                     postalCode:
 *                       type: string
 *                       example: 20100
 *                     country:
 *                       type: string
 *                       example: Italy
 *                     phone:
 *                       type: string
 *                       example: +39 123 456 7890
 *                     isDefault:
 *                       type: boolean
 *                       example: true
 *       400:
 *         description: Validation error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Validation error
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to add address
 */

router.post('/profile/addresses', 
  verifyToken,
  addressValidator,
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const user = await User.findById(req.userId);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      const isFirstAddress = !user.addresses || user.addresses.length === 0;
      const shouldBeDefault = req.body.isDefault === true || isFirstAddress;

      if (shouldBeDefault && user.addresses) {
        user.addresses.forEach((addr: any) => {
          addr.isDefault = false;
        });
      }

      const newAddress = {
        type: req.body.type || 'shipping',
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        company: req.body.company,
        addressLine1: req.body.addressLine1,
        addressLine2: req.body.addressLine2,
        city: req.body.city,
        state: req.body.state,
        postalCode: req.body.postalCode,
        country: req.body.country,
        phone: req.body.phone,
        isDefault: shouldBeDefault
      };

      if (!user.addresses) {
        user.addresses = [];
      }
      user.addresses.push(newAddress as any);

      await user.save();

      await logAuditAction('ADDRESS_ADDED', req, req.userId);

      res.status(201).json({ 
        message: 'Address added successfully',
        address: user.addresses[user.addresses.length - 1]
      });

    } catch (error) {
      console.error('Add address error:', error);
      res.status(500).json({ error: 'Failed to add address' });
    }
  }
);

/**
 * @swagger
 * /auth/profile/addresses/{addressId}:
 *   put:
 *     summary: Update an existing address
 *     description: Update all fields of an existing address
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: addressId
 *         required: true
 *         schema:
 *           type: string
 *         description: MongoDB ObjectId of the address
 *         example: 507f1f77bcf86cd799439011
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - firstName
 *               - lastName
 *               - addressLine1
 *               - city
 *               - postalCode
 *               - country
 *               - phone
 *             properties:
 *               type:
 *                 type: string
 *                 enum: [shipping, billing]
 *                 example: shipping
 *               firstName:
 *                 type: string
 *                 example: John
 *               lastName:
 *                 type: string
 *                 example: Doe
 *               company:
 *                 type: string
 *                 example: Acme Corp
 *               addressLine1:
 *                 type: string
 *                 example: Via Roma 123
 *               addressLine2:
 *                 type: string
 *                 example: Apartment 4B
 *               city:
 *                 type: string
 *                 example: Milano
 *               state:
 *                 type: string
 *                 example: MI
 *               postalCode:
 *                 type: string
 *                 example: 20100
 *               country:
 *                 type: string
 *                 example: Italy
 *               phone:
 *                 type: string
 *                 example: +39 123 456 7890
 *               isDefault:
 *                 type: boolean
 *                 example: false
 *     responses:
 *       200:
 *         description: Address updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Address updated successfully
 *                 address:
 *                   type: object
 *                   properties:
 *                     _id:
 *                       type: string
 *                       example: 507f1f77bcf86cd799439011
 *                     type:
 *                       type: string
 *                       example: shipping
 *                     firstName:
 *                       type: string
 *                       example: John
 *                     lastName:
 *                       type: string
 *                       example: Doe
 *                     company:
 *                       type: string
 *                       example: Acme Corp
 *                     addressLine1:
 *                       type: string
 *                       example: Via Roma 123
 *                     addressLine2:
 *                       type: string
 *                       example: Apartment 4B
 *                     city:
 *                       type: string
 *                       example: Milano
 *                     state:
 *                       type: string
 *                       example: MI
 *                     postalCode:
 *                       type: string
 *                       example: 20100
 *                     country:
 *                       type: string
 *                       example: Italy
 *                     phone:
 *                       type: string
 *                       example: +39 123 456 7890
 *                     isDefault:
 *                       type: boolean
 *                       example: true
 *       400:
 *         description: Invalid address ID or validation error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid address ID
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User or address not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Address not found
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to update address
 */

router.put('/profile/addresses/:addressId',
  verifyToken,
  param('addressId').isMongoId().withMessage('Invalid address ID'),
  addressValidator,
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const user = await User.findById(req.userId);
      
      if (!user || !user.addresses) {
        return res.status(404).json({ error: 'User or addresses not found' });
      }

      const address = user.addresses.find((a: any) => 
        a._id.toString() === req.params.addressId
      );

      if (!address) {
        return res.status(404).json({ error: 'Address not found' });
      }

      // Update fields
      Object.assign(address, {
        type: req.body.type || address.type,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        company: req.body.company,
        addressLine1: req.body.addressLine1,
        addressLine2: req.body.addressLine2,
        city: req.body.city,
        state: req.body.state,
        postalCode: req.body.postalCode,
        country: req.body.country,
        phone: req.body.phone
      });

      // Handle default
      if (req.body.isDefault === true) {
        user.addresses.forEach((addr: any) => {
          addr.isDefault = false;
        });
        (address as any).isDefault = true;
      }

      await user.save();

      await logAuditAction('ADDRESS_UPDATED', req, req.userId);

      res.json({ 
        message: 'Address updated successfully',
        address 
      });

    } catch (error) {
      console.error('Update address error:', error);
      res.status(500).json({ error: 'Failed to update address' });
    }
  }
);

/**
 * @swagger
 * /auth/profile/addresses/{addressId}:
 *   delete:
 *     summary: Delete an address
 *     description: Remove an address from user's saved addresses
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: addressId
 *         required: true
 *         schema:
 *           type: string
 *         description: MongoDB ObjectId of the address
 *         example: 507f1f77bcf86cd799439011
 *     responses:
 *       200:
 *         description: Address deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Address deleted successfully
 *       400:
 *         description: Invalid address ID
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid address ID
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User or address not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Address not found
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to delete address
 */

router.delete('/profile/addresses/:addressId',
  verifyToken,
  param('addressId').isMongoId().withMessage('Invalid address ID'),
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const user = await User.findById(req.userId);
      
      if (!user || !user.addresses) {
        return res.status(404).json({ error: 'User or addresses not found' });
      }

      const addressIndex = user.addresses.findIndex((a: any) => 
        a._id.toString() === req.params.addressId
      );

      if (addressIndex === -1) {
        return res.status(404).json({ error: 'Address not found' });
      }

      user.addresses.splice(addressIndex, 1);
      await user.save();

      await logAuditAction('ADDRESS_DELETED', req, req.userId);

      res.json({ message: 'Address deleted successfully' });

    } catch (error) {
      console.error('Delete address error:', error);
      res.status(500).json({ error: 'Failed to delete address' });
    }
  }
);

/**
 * @swagger
 * /auth/refresh-tokens:
 *   get:
 *     summary: Get all active refresh tokens
 *     description: List all active refresh tokens for the authenticated user (for session management)
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of active refresh tokens
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 tokens:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       created:
 *                         type: string
 *                         format: date-time
 *                       createdByIp:
 *                         type: string
 *                       expires:
 *                         type: string
 *                         format: date-time
 *                       isActive:
 *                         type: boolean
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */

router.get('/refresh-tokens', verifyToken, async (req: AuthRequest, res: Response) => {
  try {
    const tokens = await RefreshToken.find({ 
      user: req.userId,
      revoked: { $exists: false },
      expires: { $gt: new Date() }
    })
    .select('-token -user')
    .sort({ created: -1 });

    res.json({ 
      tokens: tokens.map(t => ({
        id: t._id,
        created: t.created,
        createdByIp: t.createdByIp,
        expires: t.expires,
        isActive: t.isActive
      })),
      count: tokens.length
    });

  } catch (error) {
    console.error('Get refresh tokens error:', error);
    res.status(500).json({ error: 'Failed to retrieve tokens' });
  }
});

/**
 * @swagger
 * /auth/revoke-all-tokens:
 *   post:
 *     summary: Revoke all refresh tokens (logout from all devices)
 *     description: Invalidate all active refresh tokens for the authenticated user
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: All tokens revoked successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 revokedCount:
 *                   type: number
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */

router.post('/revoke-all-tokens', verifyToken, async (req: AuthRequest, res: Response) => {
  try {
    const result = await RefreshToken.updateMany(
      { 
        user: req.userId,
        revoked: { $exists: false }
      },
      { 
        revoked: new Date(),
        revokedByIp: getIpAddress(req)
      }
    );

    // LOG AUDIT: Tokens revoked
    await logAuditAction('TOKENS_REVOKED', req, req.userId, undefined, {
      count: result.modifiedCount,
      type: 'all'
    });

    res.json({ 
      message: 'All refresh tokens revoked successfully',
      revokedCount: result.modifiedCount
    });

  } catch (error) {
    console.error('Revoke all tokens error:', error);
    res.status(500).json({ error: 'Failed to revoke tokens' });
  }
});

/**
 * @swagger
 * /auth/revoke-token/{tokenId}:
 *   delete:
 *     summary: Revoke specific refresh token
 *     description: Invalidate a specific refresh token by ID (logout from specific device)
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: tokenId
 *         required: true
 *         schema:
 *           type: string
 *         description: Refresh token ID
 *     responses:
 *       200:
 *         description: Token revoked successfully
 *       401:
 *         description: Unauthorized or token not found
 *       404:
 *         description: Token not found
 *       500:
 *         description: Server error
 */

router.delete('/revoke-token/:tokenId',
  verifyToken,
  param('tokenId').isMongoId().withMessage('Invalid token ID'),
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const token = await RefreshToken.findOne({
        _id: req.params.tokenId,
        user: req.userId
      });

      if (!token) {
        return res.status(404).json({ error: 'Token not found' });
      }

      if (token.revoked) {
        return res.status(400).json({ error: 'Token already revoked' });
      }

      token.revoked = new Date();
      token.revokedByIp = getIpAddress(req);
      await token.save();

      res.json({ message: 'Token revoked successfully' });

    } catch (error) {
      console.error('Revoke token error:', error);
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  }
);

/**
 * @swagger
 * /auth/account:
 *   delete:
 *     summary: Delete own account
 *     description: Permanently delete the authenticated user's account and all associated data (avatar, tokens, login history, password reset tokens)
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - password
 *               - confirmation
 *             properties:
 *               password:
 *                 type: string
 *                 format: password
 *                 description: Current password for confirmation
 *                 example: SecurePass123!
 *               confirmation:
 *                 type: string
 *                 example: DELETE
 *                 description: Type "DELETE" to confirm account deletion
 *     responses:
 *       200:
 *         description: Account deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Account deleted successfully
 *                 deletedAt:
 *                   type: string
 *                   format: date-time
 *                   example: 2026-02-05T22:12:00.000Z
 *       400:
 *         description: Invalid password, confirmation text, or validation error
 *         content:
 *           application/json:
 *             schema:
 *               oneOf:
 *                 - type: object
 *                   properties:
 *                     error:
 *                       type: string
 *                       example: Incorrect password
 *                 - type: object
 *                   properties:
 *                     error:
 *                       type: string
 *                       example: Type DELETE to confirm
 *       401:
 *         description: Unauthorized - Invalid or missing token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized
 *       404:
 *         description: User not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Failed to delete account
 */

router.delete('/account', 
  verifyToken,
  body('password').notEmpty().withMessage('Password is required'),
  body('confirmation').equals('DELETE').withMessage('Type DELETE to confirm'),
  validateRequest,
  async (req: AuthRequest, res: Response) => {
    try {
      const { password } = req.body;

      const user = await User.findById(req.userId);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ error: 'Incorrect password' });
      }

      // Delete avatar file if exists
      if (user.avatar) {
        try {
          await deleteAvatarFile(user.avatar);
          if (ENABLE_LOGS) {
            console.log(`[Delete Account] Avatar deleted for user ${user._id}`);
          }
        } catch (avatarError) {
          console.error('[Delete Account] Failed to delete avatar file:', avatarError);
          // Do not block account deletion if avatar deletion fails
        }
      }

      // LOG AUDIT: Account deleted
      await logAuditAction('ACCOUNT_DELETED', req, req.userId, undefined, {
        email: user.email,
        username: user.username,
        hadAvatar: !!user.avatar
      });

      // Delete all refresh tokens
      await RefreshToken.deleteMany({ user: user._id });

      // Delete login history
      await LoginHistory.deleteMany({ user: user._id });

      // Delete password reset tokens
      await PasswordResetToken.deleteMany({ user: user._id });

      // Delete user account
      await User.findByIdAndDelete(user._id);

      res.json({ 
        message: 'Account deleted successfully',
        deletedAt: new Date().toISOString()
      });

    } catch (error) {
      console.error('Delete account error:', error);
      res.status(500).json({ error: 'Failed to delete account' });
    }
  }
);

/**
 * @swagger
 * /auth/forgot-password:
 *   post:
 *     summary: Request password reset
 *     description: Send a password reset email to the user. Rate limited to prevent abuse.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: Reset email sent (always returns success for security)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: If the email exists, a password reset link has been sent
 *       400:
 *         description: Validation error
 *       429:
 *         description: Too many requests
 *       500:
 *         description: Server error
 */

router.post('/forgot-password', authLimiter, forgotPasswordValidator, validateRequest, async (req: Request, res: Response) => {
  try {
    const { email } = req.body;
    
    // Find user by email
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.json({ 
        message: 'If the email exists, a password reset link has been sent' 
      });
    }

    // LOG AUDIT: Password reset requested
    await logAuditAction('PASSWORD_RESET_REQUESTED', req, user._id.toString());

    // Invalidates all previous tokens for this user
    await PasswordResetToken.updateMany(
      { user: user._id, used: false },
      { used: true, usedAt: new Date() }
    );

    // Generate new token
    const resetToken = generatePasswordResetToken();
    const expires = new Date();
    expires.setHours(expires.getHours() + 1); // Token valid for 1 hour

    // Save token to database
    const passwordResetToken = new PasswordResetToken({
      user: user._id,
      token: resetToken,
      expires,
      ipAddress: getIpAddress(req)
    });
    await passwordResetToken.save();

    // Send email
    try {
      const emailService = getEmailService();
      await emailService.sendPasswordResetEmail(
        user.email,
        resetToken,
        user.username || user.firstName || 'User'
      );
    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
    }

    res.json({ 
      message: 'If the email exists, a password reset link has been sent' 
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

/**
 * @swagger
 * /auth/reset-password:
 *   post:
 *     summary: Reset password with token
 *     description: Reset user password using the token received via email
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *               - newPassword
 *               - confirmPassword
 *             properties:
 *               token:
 *                 type: string
 *                 description: Reset token from email
 *                 minLength: 64
 *                 maxLength: 64
 *               newPassword:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 example: NewSecurePass123!
 *               confirmPassword:
 *                 type: string
 *                 format: password
 *                 example: NewSecurePass123!
 *     responses:
 *       200:
 *         description: Password reset successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Password reset successful. Please login with your new password.
 *       400:
 *         description: Invalid or expired token
 *       500:
 *         description: Server error
 */

router.post('/reset-password', resetPasswordValidator, validateRequest, async (req: Request, res: Response) => {
  try {
    const { token, newPassword } = req.body;

    // Find the valid token
    const resetToken = await PasswordResetToken.findOne({
      token,
      used: false,
      expires: { $gt: new Date() }
    }).populate('user');

    if (!resetToken) {
      return res.status(400).json({ 
        error: 'Invalid or expired reset token' 
      });
    }

    const user = resetToken.user as any;

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);
    user.password = hashedPassword;
    user.updatedAt = new Date();
    await user.save();

    // Mark the token as used
    resetToken.used = true;
    resetToken.usedAt = new Date();
    await resetToken.save();

    // LOG AUDIT: Password reset completed
    await logAuditAction('PASSWORD_RESET_COMPLETED', req, user._id.toString());

    // Revoke all refresh tokens for security (force re-login)
    await RefreshToken.updateMany(
      { user: user._id, revoked: { $exists: false } },
      { 
        revoked: new Date(),
        revokedByIp: 'password-reset'
      }
    );

    res.json({ 
      message: 'Password reset successful. Please login with your new password.' 
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

/**
 * @swagger
 * /auth/verify-reset-token:
 *   post:
 *     summary: Verify reset token validity
 *     description: Check if a password reset token is valid (useful for frontend)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - token
 *             properties:
 *               token:
 *                 type: string
 *                 minLength: 64
 *                 maxLength: 64
 *     responses:
 *       200:
 *         description: Token is valid
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 valid:
 *                   type: boolean
 *                   example: true
 *                 email:
 *                   type: string
 *                   example: user@example.com
 *                   description: Email address (partially hidden for privacy)
 *       400:
 *         description: Token is invalid or expired
 */

router.post('/verify-reset-token', 
  body('token').isLength({ min: 64, max: 64 }).withMessage('Invalid token format'),
  validateRequest,
  async (req: Request, res: Response) => {
    try {
      const { token } = req.body;

      const resetToken = await PasswordResetToken.findOne({
        token,
        used: false,
        expires: { $gt: new Date() }
      }).populate('user');

      if (!resetToken) {
        return res.status(400).json({ 
          valid: false,
          error: 'Invalid or expired reset token' 
        });
      }

      const user = resetToken.user as any;
      
      // Hide part of the email for privacy
      const email = user.email;
      const [localPart, domain] = email.split('@');
      const hiddenEmail = localPart.length > 3
        ? `${localPart.substring(0, 2)}***@${domain}`
        : `***@${domain}`;

      res.json({ 
        valid: true,
        email: hiddenEmail
      });

    } catch (error) {
      console.error('Verify reset token error:', error);
      res.status(500).json({ error: 'Failed to verify token' });
    }
  }
);

/**
 * @swagger
 * /auth/login-history:
 *   get:
 *     summary: Get login history
 *     description: Retrieve recent login attempts for the authenticated user
 *     tags: [User]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 20
 *         description: Number of records to return
 *     responses:
 *       200:
 *         description: Login history retrieved
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 history:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       ipAddress:
 *                         type: string
 *                       browser:
 *                         type: string
 *                       os:
 *                         type: string
 *                       device:
 *                         type: string
 *                       loginAt:
 *                         type: string
 *                         format: date-time
 *                       success:
 *                         type: boolean
 *                       failureReason:
 *                         type: string
 *                 total:
 *                   type: number
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */

router.get('/login-history', verifyToken, async (req: AuthRequest, res: Response) => {
  try {
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);

    const history = await LoginHistory.find({ user: req.userId })
      .sort({ loginAt: -1 })
      .limit(limit)
      .select('-user -userAgent -__v');

    const total = await LoginHistory.countDocuments({ user: req.userId });

    res.json({ 
      history,
      total,
      showing: history.length
    });

  } catch (error) {
    console.error('Get login history error:', error);
    res.status(500).json({ error: 'Failed to retrieve login history' });
  }
});

export default router;
