import multer from 'multer';
import path from 'path';
import fs from 'fs';

// Make sure the directory exists
const uploadDir = 'uploads/avatars';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Format: avatar-{userId}-{timestamp}.{ext}
    const ext = path.extname(file.originalname);
    const userId = (req as any).userId || 'unknown';
    const uniqueSuffix = Date.now();
    cb(null, `avatar-${userId}-${uniqueSuffix}${ext}`);
  }
});

// File filter for type validation
const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  const allowedMimes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
  
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only image files (JPEG, PNG, GIF, WebP) are allowed'));
  }
};

// Multer configuration for avatar
export const avatarUpload = multer({
  storage,
  limits: { 
    fileSize: 5 * 1024 * 1024, // 5MB max
    files: 1 // Only one file at a time
  },
  fileFilter
});

// Helper to delete avatar files
export const deleteAvatarFile = (avatarPath: string): Promise<void> => {
  return new Promise((resolve, reject) => {
    // Extract only the filename from the URL
    const filename = avatarPath.split('/').pop();
    if (!filename) {
      return resolve();
    }

    const fullPath = path.join(uploadDir, filename);
    
    fs.unlink(fullPath, (err) => {
      if (err && err.code !== 'ENOENT') {
        // Ignore error if file does not exist
        console.error('Error deleting avatar file:', err);
        return reject(err);
      }
      resolve();
    });
  });
};
