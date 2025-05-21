

import crypto from 'crypto';

export function hashPassword(password, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.scryptSync(password, salt, 32).toString('hex');
}

export function deriveKeyFromTOTP(totp, saltHex) {
  const salt = Buffer.from(saltHex, 'hex');
  return crypto.scryptSync(totp, salt, 32);
}

export function encryptMessage(message, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

export function decryptMessage(encrypted, key, ivHex, authTagHex) {
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}