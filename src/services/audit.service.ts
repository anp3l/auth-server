import { Request } from 'express';
import { LoginHistory } from '../models/loginHistory.model';
import { AuditLog, AuditAction } from '../models/auditLog.model';
import { parseUserAgent } from '../utils/user-agent.util';
import { ENABLE_LOGS } from '../config/env';

/**
 * Log a login attempt (success or failure)
 */
export async function logLoginAttempt(
  userId: string | null,
  req: Request,
  success: boolean,
  failureReason?: string
): Promise<void> {
  try {
    const ipAddress = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || 
                      req.socket.remoteAddress || 
                      'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';
    const parsed = parseUserAgent(userAgent);

    // Log in login history only if there is a userId
    if (userId) {
      await LoginHistory.create({
        user: userId,
        ipAddress,
        userAgent,
        browser: parsed.browser,
        os: parsed.os,
        device: parsed.device,
        success,
        failureReason
      });
    }

    // Log in audit log
    await AuditLog.create({
      user: userId || undefined,
      action: 'USER_LOGIN',
      ipAddress,
      userAgent,
      success,
      errorMessage: failureReason
    });

    if (ENABLE_LOGS) {
      console.log(`[Audit] Login ${success ? 'success' : 'failed'} from ${ipAddress} (${parsed.browser})`);
    }
  } catch (error) {
    console.error('Failed to log login attempt:', error);
  }
}

/**
 * Log an action in the audit log
 */
export async function logAuditAction(
  action: AuditAction,
  req: Request,
  userId?: string,
  performedBy?: string,
  details?: any,
  success: boolean = true,
  errorMessage?: string
): Promise<void> {
  try {
    const ipAddress = (req.headers['x-forwarded-for'] as string)?.split(',')[0] || 
                      req.socket.remoteAddress || 
                      'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    await AuditLog.create({
      user: userId || undefined,
      action,
      performedBy: performedBy || undefined,
      ipAddress,
      userAgent,
      details,
      success,
      errorMessage
    });

    if (ENABLE_LOGS) {
      console.log(`[Audit] ${action} - User: ${userId || 'N/A'} - Success: ${success}`);
    }
  } catch (error) {
    console.error('Failed to log audit action:', error);
  }
}
