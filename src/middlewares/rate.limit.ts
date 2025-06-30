import rateLimit from 'express-rate-limit';

export const otpRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 3 OTP requests per windowMs
    message: 'Too many OTP requests, please try again',
    standardHeaders: true,
    legacyHeaders: false,
});

export const endpointRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // limit each IP to 5 registration requests per windowMs
    message: {
        status: 429,
        error: 'Too many registration attempts, please try again',
    },
    standardHeaders: true,
    legacyHeaders: false,
});



