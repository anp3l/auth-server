import fs from 'fs';
import path from 'path';

const privateKeyPath = path.join(__dirname, '../../private.pem');

let privateKey: string;

try {
  privateKey = fs.readFileSync(privateKeyPath, 'utf8');
} catch (error) {
  console.error('❌ FATAL ERROR: private.pem not found in project root');
  console.error('Ensure you have generated the RSA keys in the project root.');
  process.exit(1);
}

export const PRIV_KEY = privateKey;
