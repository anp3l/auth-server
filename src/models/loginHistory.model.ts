import { Schema, model, Document, Types } from 'mongoose';

export interface ILoginHistory extends Document {
  user: Types.ObjectId;
  ipAddress: string;
  userAgent: string;
  browser?: string;
  os?: string;
  device?: string;
  location?: {
    country?: string;
    city?: string;
  };
  loginAt: Date;
  success: boolean;
  failureReason?: string;
}

const loginHistorySchema = new Schema<ILoginHistory>({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: true
  },
  browser: String,
  os: String,
  device: String,
  location: {
    country: String,
    city: String
  },
  loginAt: {
    type: Date,
    default: Date.now
  },
  success: {
    type: Boolean,
    required: true
  },
  failureReason: String
});

loginHistorySchema.index({ user: 1, loginAt: -1 });
loginHistorySchema.index({ ipAddress: 1 });

loginHistorySchema.index({ loginAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

export const LoginHistory = model<ILoginHistory>('LoginHistory', loginHistorySchema);
