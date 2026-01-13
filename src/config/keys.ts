import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

// Helper function to get the key (Env Var > File System)
const getKey = (type: 'PRIVATE' | 'PUBLIC'): string => {
  const envVarName = `${type}_KEY_BASE64`;
  const fileName = type === 'PRIVATE' ? 'private.pem' : 'public.pem';
  
  // 1. PRIORITY: Environment Variable (Docker / Production)
  const base64Key = process.env[envVarName];
  if (base64Key) {
    try {
      return Buffer.from(base64Key, 'base64').toString('utf-8');
    } catch (error) {
      console.error(`❌ FATAL ERROR: Failed to decode ${envVarName}`);
      process.exit(1);
    }
  }

  // 2. FALLBACK: File System (Local Development)
  const filePath = path.join(process.cwd(), fileName);
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    console.error(`❌ FATAL ERROR: Key missing.`);
    console.error(`   - Docker/Prod: Set ${envVarName} in .env`);
    console.error(`   - Local Dev: Place ${fileName} in project root`);
    process.exit(1);
  }
};

export const PRIV_KEY = getKey('PRIVATE');
export const PUB_KEY = getKey('PUBLIC');
