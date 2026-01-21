import { RefreshToken } from '../models/refreshToken.model';
import { ENABLE_LOGS } from '../config/env';
import { PasswordResetToken } from '../models/passwordResetToken.model';

/**
 *Delete expired refresh tokens from the database
 */
export async function cleanupExpiredTokens(): Promise<number> {
  try {
    // Cleanup refresh tokens
    const refreshResult = await RefreshToken.deleteMany({
      expires: { $lt: new Date() }
    });

    // Cleanup password reset tokens (already managed by TTL index, but for security)
    const resetResult = await PasswordResetToken.deleteMany({
      $or: [
        { expires: { $lt: new Date() } },
        { used: true, usedAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } } // Elimina token usati dopo 7 giorni
      ]
    });

    const total = refreshResult.deletedCount + resetResult.deletedCount;

    if (ENABLE_LOGS) {
      console.log(`[Cleanup] Deleted ${refreshResult.deletedCount} expired refresh tokens`);
      console.log(`[Cleanup] Deleted ${resetResult.deletedCount} expired/used reset tokens`);
      console.log(`[Cleanup] Total: ${total} tokens cleaned`);
    }

    return total;
  } catch (error) {
    console.error('[Cleanup] Error cleaning up expired tokens:', error);
    return 0;
  }
}

/**
 * Delete expired or used password reset tokens
 */
export async function cleanupPasswordResetTokens(): Promise<number> {
  try {
    const result = await PasswordResetToken.deleteMany({
      $or: [
        { expires: { $lt: new Date() } },
        { used: { $exists: true } }
      ]
    });

    if (ENABLE_LOGS) {
      console.log(`[Cleanup] Deleted ${result.deletedCount} password reset tokens`);
    }

    return result.deletedCount;
  } catch (error) {
    console.error('[Cleanup] Error cleaning up password reset tokens:', error);
    return 0;
  }
}

/**
 * Start automatic cleanup every 24 hours
 */
export function startCleanupScheduler() {
  // Run immediately on startup
  cleanupExpiredTokens();
  cleanupPasswordResetTokens();

  // Then every 24 hours
  setInterval(() => {
    cleanupExpiredTokens();
    cleanupPasswordResetTokens();
  }, 24 * 60 * 60 * 1000);

  console.log('✅ Cleanup scheduler started (runs every 24 hours)');
}