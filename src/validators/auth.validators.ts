import { body, ValidationChain } from 'express-validator';

/**
 * Validator for signup with optional firstName/lastName fields
 */
export const signupValidator: ValidationChain[] = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_-]+$/)
    .withMessage('Username can only contain letters, numbers, underscores and hyphens')
    .escape(),
  
  body('email')
    .trim()
    .isEmail()
    .withMessage('Must be a valid email address')
    .normalizeEmail()
    .toLowerCase(),
  
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)'),
  
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters')
    .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/)
    .withMessage('First name can only contain letters, spaces, hyphens and apostrophes')
    .escape(),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters')
    .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/)
    .withMessage('Last name can only contain letters, spaces, hyphens and apostrophes')
    .escape()
];

/**
 * Validator for login
 */
export const loginValidator: ValidationChain[] = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Must be a valid email address')
    .normalizeEmail()
    .toLowerCase(),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

/**
 * Validator for refresh token
 */
export const refreshTokenValidator: ValidationChain[] = [
  body('refreshToken')
    .notEmpty()
    .withMessage('Refresh token is required')
    .isString()
    .withMessage('Refresh token must be a string')
    .isLength({ min: 40, max: 100 })
    .withMessage('Invalid refresh token format')
];

/**
 * Validator for update profile
 */
export const updateProfileValidator: ValidationChain[] = [
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name must be between 1 and 50 characters')
    .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/)
    .withMessage('First name can only contain letters, spaces, hyphens and apostrophes')
    .escape(),
  
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name must be between 1 and 50 characters')
    .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/)
    .withMessage('Last name can only contain letters, spaces, hyphens and apostrophes')
    .escape(),
  
  body('shippingAddress')
    .optional()
    .isObject()
    .withMessage('Shipping address must be an object'),
  
  body('shippingAddress.street')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Street must be between 1 and 100 characters')
    .escape(),
  
  body('shippingAddress.city')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('City must be between 1 and 50 characters')
    .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/)
    .withMessage('City can only contain letters, spaces, hyphens and apostrophes')
    .escape(),
  
  body('shippingAddress.postalCode')
    .optional()
    .trim()
    .matches(/^[A-Z0-9\s-]{3,10}$/i)
    .withMessage('Invalid postal code format')
    .escape(),
  
  body('shippingAddress.country')
    .optional()
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Country must be between 2 and 50 characters')
    .matches(/^[a-zA-ZÀ-ÿ\s'-]+$/)
    .withMessage('Country can only contain letters, spaces, hyphens and apostrophes')
    .escape()
];

/**
 * Validator for change password
 */
export const changePasswordValidator: ValidationChain[] = [
  body('currentPassword')
    .notEmpty()
    .withMessage('Current password is required'),
  
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('New password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)')
    .custom((value, { req }) => {
      if (value === req.body.currentPassword) {
        throw new Error('New password must be different from current password');
      }
      return true;
    }),
  
  body('confirmPassword')
    .notEmpty()
    .withMessage('Password confirmation is required')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match');
      }
      return true;
    })
];

/**
 * Validator per forgot password
 */
export const forgotPasswordValidator: ValidationChain[] = [
  body('email')
    .trim()
    .isEmail()
    .withMessage('Must be a valid email address')
    .normalizeEmail()
    .toLowerCase()
];

/**
 * Validator for reset password
 */
export const resetPasswordValidator: ValidationChain[] = [
  body('token')
    .notEmpty()
    .withMessage('Reset token is required')
    .isLength({ min: 64, max: 64 })
    .withMessage('Invalid reset token format'),
  
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)'),
  
  body('confirmPassword')
    .notEmpty()
    .withMessage('Password confirmation is required')
    .custom((value, { req }) => {
      if (value !== req.body.newPassword) {
        throw new Error('Password confirmation does not match');
      }
      return true;
    })
];
