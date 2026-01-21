import { RefreshToken } from '../models/refreshToken.model';
import { ENABLE_LOGS } from '../config/env';

/**
 *Delete expired refresh tokens from the database
 */
export async function cleanupExpiredTokens(): Promise<number> {
  try {
    const result = await RefreshToken.deleteMany({
      expires: { $lt: new Date() }
    });

    if (ENABLE_LOGS) {
      console.log(`[Cleanup] Deleted ${result.deletedCount} expired refresh tokens`);
    }

    return result.deletedCount;
  } catch (error) {
    console.error('[Cleanup] Error cleaning up expired tokens:', error);
    return 0;
  }
}

/**
 *Start automatic cleanup every 24 hours
 */
export function startCleanupScheduler() {
  //Run immediately on startup
  cleanupExpiredTokens();

  //Then every 24 hours
  setInterval(() => {
    cleanupExpiredTokens();
  }, 24 * 60 * 60 * 1000); // 24 hours in milliseconds

  console.log('✅ Cleanup scheduler started (runs every 24 hours)');
}
