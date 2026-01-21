import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt, { SignOptions } from 'jsonwebtoken';
import { User } from '../models/user.model';
import { RefreshToken, generateRefreshToken } from '../models/refreshToken.model';
import { PRIV_KEY } from '../config/keys';
import { ACCESS_TOKEN_EXPIRY, REFRESH_TOKEN_EXPIRY } from '../config/env';
import { loginValidator, signupValidator, refreshTokenValidator, updateProfileValidator } from '../validators/auth.validators';
import { validateRequest } from '../middleware/validateRequest.middleware';
import { verifyToken, AuthRequest } from '../middleware/auth.middleware';
import { authLimiter } from '../middleware/rateLimiter.middleware';

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
 *     description: Create a new user account. Returns access token (15min) and refresh token (7 days).
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
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User created
 *                 accessToken:
 *                   type: string
 *                   description: JWT access token (expires in 15 minutes)
 *                 refreshToken:
 *                   type: string
 *                   description: Refresh token (expires in 7 days)
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     username:
 *                       type: string
 *                     email:
 *                       type: string
 *                     role:
 *                       type: string
 *                       enum: [customer, admin]
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

    // Generate access token (short-lived)
    const accessToken = generateAccessToken(user._id.toString(), user.username, user.role);
    
    // Genera refresh token (lunga durata)
    const refreshToken = await generateAndSaveRefreshToken(user._id.toString(), getIpAddress(req));

    res.status(201).json({ 
      message: 'User created', 
      accessToken,
      refreshToken,
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
 *     description: User login with email and password. Returns access token and refresh token.
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
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                 refreshToken:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     username:
 *                       type: string
 *                     email:
 *                       type: string
 *                     role:
 *                       type: string
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid credentials
 *       429:
 *         description: Too many login attempts
 *       500:
 *         description: Server error
 */
router.post('/login', authLimiter, loginValidator, validateRequest, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate access token
    const accessToken = generateAccessToken(user._id.toString(), user.username, user.role);
    
    // Generate refresh token
    const refreshToken = await generateAndSaveRefreshToken(user._id.toString(), getIpAddress(req));

    res.json({ 
      accessToken,
      refreshToken,
      user: { 
        id: user._id, 
        username: user.username,
        email: user.email,
        role: user.role
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
 *     description: Generate a new access token using a valid refresh token. The old refresh token is revoked and replaced.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: The refresh token received during login/signup
 *     responses:
 *       200:
 *         description: Tokens refreshed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 accessToken:
 *                   type: string
 *                 refreshToken:
 *                   type: string
 *                   description: New refresh token (old one is revoked)
 *       400:
 *         description: Refresh token is required
 *       401:
 *         description: Invalid or expired refresh token
 *       500:
 *         description: Server error
 */
router.post('/refresh-token', refreshTokenValidator, validateRequest, async (req: Request, res: Response) => {
  try {
    const { refreshToken: token } = req.body;
    
    const refreshToken = await RefreshToken.findOne({ token }).populate('user');
    
    if (!refreshToken || !refreshToken.isActive) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const user = refreshToken.user as any;

    // Revoke old refresh token
    refreshToken.revoked = new Date();
    refreshToken.revokedByIp = getIpAddress(req);
    
    // Generate new access token
    const newAccessToken = generateAccessToken(user._id.toString(), user.username, user.role);
    
    // Generate new refresh token
    const newRefreshToken = await generateAndSaveRefreshToken(user._id.toString(), getIpAddress(req));
    
    // Save reference to the new token
    refreshToken.replacedByToken = newRefreshToken;
    await refreshToken.save();

    res.json({ 
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    });

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
 *     description: Invalidate a refresh token to log out the user.
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - refreshToken
 *             properties:
 *               refreshToken:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token revoked successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Token revoked
 *       400:
 *         description: Refresh token is required
 *       401:
 *         description: Unauthorized or invalid token
 *       500:
 *         description: Server error
 */
router.post('/revoke-token', verifyToken, async (req: AuthRequest, res: Response) => {
  try {
    const { refreshToken: token } = req.body;
    
    if (!token) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }
    
    const refreshToken = await RefreshToken.findOne({ token });
    
    if (!refreshToken || refreshToken.user.toString() !== req.userId) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Revoke the token
    refreshToken.revoked = new Date();
    refreshToken.revokedByIp = getIpAddress(req);
    await refreshToken.save();

    res.json({ message: 'Token revoked' });

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
 *   put:
 *     summary: Update user profile
 *     description: Update authenticated user's profile information
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
 *                 minLength: 1
 *                 maxLength: 50
 *                 example: John
 *               lastName:
 *                 type: string
 *                 minLength: 1
 *                 maxLength: 50
 *                 example: Doe
 *               shippingAddress:
 *                 type: object
 *                 properties:
 *                   street:
 *                     type: string
 *                     example: Via Roma 123
 *                   city:
 *                     type: string
 *                     example: Milano
 *                   postalCode:
 *                     type: string
 *                     example: 20100
 *                   country:
 *                     type: string
 *                     example: Italy
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 *       500:
 *         description: Server error
 */
router.put('/profile', verifyToken, updateProfileValidator, validateRequest, async (req: AuthRequest, res: Response) => {
  try {
    const { firstName, lastName, shippingAddress } = req.body;
    
    const updateData: any = { updatedAt: new Date() };
    
    if (firstName !== undefined) updateData.firstName = firstName;
    if (lastName !== undefined) updateData.lastName = lastName;
    if (shippingAddress !== undefined) updateData.shippingAddress = shippingAddress;

    const user = await User.findByIdAndUpdate(
      req.userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ 
      message: 'Profile updated',
      user 
    });

  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

export default router;
