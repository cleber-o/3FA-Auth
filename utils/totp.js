import { authenticator } from 'otplib';

export function generateSecret() {
  return authenticator.generateSecret();
}

export function generateTOTP(secret) {
  return authenticator.generate(secret);
}

export function verifyTOTP(token, secret) {
  return authenticator.check(token, secret);
}

export function generateKeyUri(user, service, secret) {
  return authenticator.keyuri(user, service, secret);
}
