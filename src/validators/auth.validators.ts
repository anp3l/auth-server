import { body } from 'express-validator';

export const signupValidator = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 chars')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can contain letters, numbers and underscore only'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Invalid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
];

export const loginValidator = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Invalid email')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
];