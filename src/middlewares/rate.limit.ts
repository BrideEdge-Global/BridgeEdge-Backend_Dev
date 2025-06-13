import rateLimit from 'express-rate-limit';

export const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login requests per windowMs
    message: 'Too many login attempts from this IP, please try again',
    standardHeaders: true,
    legacyHeaders: false,
});

export const otpRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // limit each IP to 3 OTP requests per windowMs
    message: 'Too many OTP requests from this IP, please try again',
    standardHeaders: true,
    legacyHeaders: false,
});