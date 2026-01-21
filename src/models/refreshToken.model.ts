import { Schema, model, Document, Types } from 'mongoose';
import crypto from 'crypto';

export interface IRefreshToken extends Document {
  user: Types.ObjectId;
  token: string;
  expires: Date;
  created: Date;
  createdByIp: string;
  revoked?: Date;
  revokedByIp?: string;
  replacedByToken?: string;
  isExpired: boolean;
  isActive: boolean;
}

const refreshTokenSchema = new Schema<IRefreshToken>({
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
  created: { 
    type: Date, 
    default: Date.now 
  },
  createdByIp: { 
    type: String,
    required: true
  },
  revoked: Date,
  revokedByIp: String,
  replacedByToken: String
});


// Virtual properties 
refreshTokenSchema.virtual('isExpired').get(function() {
  return Date.now() >= this.expires.getTime();
});

refreshTokenSchema.virtual('isActive').get(function() {
  return !this.revoked && !this.isExpired;
});

// Index for efficient cleanup queries
refreshTokenSchema.index({ expires: 1 });
refreshTokenSchema.index({ user: 1 });

export const RefreshToken = model<IRefreshToken>('RefreshToken', refreshTokenSchema);

// Helper function to generate a new refresh token
export function generateRefreshToken(): string {
  return crypto.randomBytes(40).toString('hex');
}
