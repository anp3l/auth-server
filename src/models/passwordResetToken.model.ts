import { Schema, model, Document, Types } from 'mongoose';
import crypto from 'crypto';

export interface IPasswordResetToken extends Document {
  user: Types.ObjectId;
  token: string;
  expires: Date;
  used: boolean;
  createdAt: Date;
  usedAt?: Date;
  ipAddress: string;
}

const passwordResetTokenSchema = new Schema<IPasswordResetToken>({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  token: {
    type: String,
    required: true,
    unique: true
  },
  expires: {
    type: Date,
    required: true
  },
  used: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  usedAt: Date,
  ipAddress: {
    type: String,
    required: true
  }
});

// Index for performance and automatic cleanup
passwordResetTokenSchema.index({ expires: 1 }, { expireAfterSeconds: 0 }); // TTL index - MongoDB elimina automaticamente
passwordResetTokenSchema.index({ user: 1 });

export const PasswordResetToken = model<IPasswordResetToken>('PasswordResetToken', passwordResetTokenSchema);

/**
 * Generate a secure password reset token
 */
export function generatePasswordResetToken(): string {
  return crypto.randomBytes(32).toString('hex');
}
