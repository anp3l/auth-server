import { Schema, model, Document, Types } from 'mongoose';

export type AuditAction = 
  | 'USER_SIGNUP'
  | 'USER_LOGIN'
  | 'USER_LOGOUT'
  | 'PASSWORD_CHANGED'
  | 'PASSWORD_RESET_REQUESTED'
  | 'PASSWORD_RESET_COMPLETED'
  | 'PROFILE_UPDATED'
  | 'ACCOUNT_DELETED'
  | 'ROLE_CHANGED'
  | 'USER_DELETED_BY_ADMIN'
  | 'TOKENS_REVOKED'
  | 'AVATAR_UPDATED'
  | 'EMAIL_PREFERENCES_UPDATED'
  | 'LOGOUT'
  | 'LOGOUT_ALL_DEVICES'
  | 'USER_BANNED'
  | 'USER_UNBANNED'
  | 'ADDRESS_ADDED'
  | 'ADDRESS_UPDATED'
  | 'ADDRESS_DELETED'
  | 'AVATAR_UPLOADED'
  | 'AVATAR_DELETED'

export interface IAuditLog extends Document {
  user?: Types.ObjectId;
  action: AuditAction;
  performedBy?: Types.ObjectId;
  ipAddress: string;
  userAgent: string;
  details?: any;
  timestamp: Date;
  success: boolean;
  errorMessage?: string;
}

const auditLogSchema = new Schema<IAuditLog>({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  action: {
    type: String,
    enum: [
      'USER_SIGNUP',
      'USER_LOGIN',
      'USER_LOGOUT',
      'PASSWORD_CHANGED',
      'PASSWORD_RESET_REQUESTED',
      'PASSWORD_RESET_COMPLETED',
      'PROFILE_UPDATED',
      'ACCOUNT_DELETED',
      'ROLE_CHANGED',
      'USER_DELETED_BY_ADMIN',
      'TOKENS_REVOKED',
      'AVATAR_UPDATED',
      'EMAIL_PREFERENCES_UPDATED',
      'LOGOUT',
      'LOGOUT_ALL_DEVICES',
      'USER_BANNED',
      'USER_UNBANNED',
      'ADDRESS_ADDED',
      'ADDRESS_UPDATED',
      'ADDRESS_DELETED',
      'AVATAR_UPLOADED',
      'AVATAR_DELETED'
      
    ],
    required: true
  },
  performedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User'
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: true
  },
  details: Schema.Types.Mixed,
  timestamp: {
    type: Date,
    default: Date.now
  },
  success: {
    type: Boolean,
    required: true,
    default: true
  },
  errorMessage: String
});


auditLogSchema.index({ user: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ performedBy: 1, timestamp: -1 });

auditLogSchema.index({ timestamp: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

export const AuditLog = model<IAuditLog>('AuditLog', auditLogSchema);
