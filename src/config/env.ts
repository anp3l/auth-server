import dotenv from 'dotenv';
dotenv.config();

if (!process.env.MONGO_URI) {
  throw new Error('Missing: process.env.MONGO_URI');
}

export const MONGO_URI = process.env.MONGO_URI;
export const NODE_ENV = process.env.NODE_ENV || 'development';
export const ENABLE_LOGS = process.env.ENABLE_LOGS === 'true';
export const PORT = process.env.PORT;
