import { Router, Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { User } from '../models/user.model';
import { PRIV_KEY } from '../config/keys';
import { loginValidator, signupValidator } from '../validators/auth.validators';
import { validateRequest } from '../middleware/validateRequest.middleware';

const router = Router();

/**
 * @swagger
 * /auth/signup:
 *   post:
 *     summary: Register a new user
 *     description: Create a new user account with unique username and email. Returns an RSA-signed JWT on success.
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
 *                 example: yourSecurePass123!
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
 *                 token:
 *                   type: string
 *                   description: RSA-signed JWT auth token
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     username:
 *                       type: string
 *       400:
 *         description: Validation error (invalid email, password too short, etc.)
 *       409:
 *         description: User already exists (email or username conflict)
 *       500:
 *         description: Server error
 */
router.post('/signup', signupValidator, validateRequest, async (req: Request, res: Response) => {
  try {
    const { username, email, password } = req.body;

    // Check if user already exists
    const existing = await User.findOne({ $or: [{ email }, { username }] });
    if (existing) return res.status(409).json({ error: 'User already exists' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    // SIGNING THE TOKEN WITH PRIVATE KEY (RS256)
    const token = jwt.sign(
      { userId: user._id, username: user.username }, // Payload
      PRIV_KEY,                                      // Private Key
      { expiresIn: '7d', algorithm: 'RS256' }        // Algorithm and Expiry
    );

    res.status(201).json({ 
      message: 'User created', 
      token, 
      user: { id: user._id, username: user.username } 
    });

  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Authenticate a user
 *     description: User login with email and password. Returns an RSA-signed JWT on success.
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
 *                 example: yourSecurePass123!
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: RSA-signed JWT auth token
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: string
 *                     username:
 *                       type: string
 *       400:
 *         description: Validation error (missing fields)
 *       401:
 *         description: Invalid credentials
 *       500:
 *         description: Server error
 */
router.post('/login', loginValidator, validateRequest, async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // SIGNING THE TOKEN WITH PRIVATE KEY (RS256)
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      PRIV_KEY,
      { expiresIn: '7d', algorithm: 'RS256' }
    );

    res.json({ token, user: { id: user._id, username: user.username } });

  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

export default router;
