import { RefreshToken } from '../models/refreshToken.model';
import { ENABLE_LOGS } from '../config/env';
import { PasswordResetToken } from '../models/passwordResetToken.model';
import { LoginHistory } from '../models/loginHistory.model';
import { User } from '../models/user.model';
import fs from 'fs';
import path from 'path';

/**
 * Delete expired refresh tokens from the database
 */
export async function cleanupExpiredTokens(): Promise<number> {
  try {
    const refreshResult = await RefreshToken.deleteMany({
      expires: { $lt: new Date() }
    });

    const resetResult = await PasswordResetToken.deleteMany({
      $or: [
        { expires: { $lt: new Date() } },
        { used: true, usedAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } }
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
 * Delete old login history records (older than 90 days)
 * Note: MongoDB TTL index also handles this automatically, this is a backup
 */
export async function cleanupLoginHistory(): Promise<number> {
  try {
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    
    const result = await LoginHistory.deleteMany({
      loginAt: { $lt: ninetyDaysAgo }
    });

    if (ENABLE_LOGS) {
      console.log(`[Cleanup] Deleted ${result.deletedCount} old login history records`);
    }

    return result.deletedCount;
  } catch (error) {
    console.error('[Cleanup] Error cleaning up login history:', error);
    return 0;
  }
}

/**
 * Delete orphaned avatar files (files not referenced in database)
 */
export async function cleanupOrphanedAvatars(): Promise<number> {
  const uploadsDir = path.join(__dirname, '../../uploads/avatars');
  
  try {
    // Verify that the directory exists
    if (!fs.existsSync(uploadsDir)) {
      if (ENABLE_LOGS) {
        console.log('[Cleanup] Avatars directory does not exist, skipping cleanup');
      }
      return 0;
    }

    // Get all files in the directory
    const files = fs.readdirSync(uploadsDir);
    
    if (files.length === 0) {
      if (ENABLE_LOGS) {
        console.log('[Cleanup] No avatar files to clean');
      }
      return 0;
    }

    // Get all avatars currently in use in the database
    const users = await User.find({ 
      avatar: { $exists: true, $ne: null } 
    }).select('avatar');
    
    // Create a Set with the filenames in use
    const avatarsInUse = new Set(
      users
        .map(u => u.avatar?.split('/').pop())
        .filter(Boolean) as string[]
    );

    let deletedCount = 0;
    
    // Delete orphaned files
    for (const file of files) {
      if (!avatarsInUse.has(file)) {
        const filePath = path.join(uploadsDir, file);
        
        try {
          fs.unlinkSync(filePath);
          deletedCount++;
          
          if (ENABLE_LOGS) {
            console.log(`[Cleanup] Deleted orphaned avatar: ${file}`);
          }
        } catch (fileError) {
          console.error(`[Cleanup] Failed to delete file ${file}:`, fileError);
        }
      }
    }
    
    if (ENABLE_LOGS) {
      console.log(`[Cleanup] Deleted ${deletedCount} orphaned avatar file(s)`);
    }
    
    return deletedCount;
    
  } catch (error) {
    console.error('[Cleanup] Error during avatar cleanup:', error);
    return 0;
  }
}

/**
 * Start automatic cleanup every 24 hours
 */
export function startCleanupScheduler() {
  // Run immediately on startup
  const runCleanup = async () => {
    console.log('\n🧹 Starting scheduled cleanup...');
    const startTime = Date.now();
    
    const tokens = await cleanupExpiredTokens();
    const resetTokens = await cleanupPasswordResetTokens();
    const loginHistory = await cleanupLoginHistory();
    const avatars = await cleanupOrphanedAvatars();
    
    const duration = Date.now() - startTime;
    const total = tokens + resetTokens + loginHistory + avatars;
    
    console.log(`\n✅ Cleanup completed in ${duration}ms`);
    console.log(`📊 Summary:`);
    console.log(`   - Tokens: ${tokens}`);
    console.log(`   - Reset tokens: ${resetTokens}`);
    console.log(`   - Login history: ${loginHistory}`);
    console.log(`   - Avatar files: ${avatars}`);
    console.log(`   - Total: ${total} items cleaned\n`);
  };

  // Run immediately
  runCleanup();

  // Then every 24 hours
  setInterval(runCleanup, 24 * 60 * 60 * 1000);

  console.log('✅ Cleanup scheduler started (runs every 24 hours)');
}