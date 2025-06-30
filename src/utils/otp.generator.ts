// This file contains utility functions related to OTP (One-Time Password) generation.
export function generateOTP(length = 6): string {
  return Math.floor(Math.pow(10, length - 1) + Math.random() * 9 * Math.pow(10, length - 1)).toString();
}

export function isValidOTP(otp: string, userOtp: string): boolean {
  return /^\d{6}$/.test(otp) && otp === userOtp;
}

export function isOTPExpired(expiryDate: Date): boolean {
  return new Date() > expiryDate;
}

export function isEmailValid(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}