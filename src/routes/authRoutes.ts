import express from 'express';
import { 
  createUser, 
  verifyOtp,
  resendOTP, 
  OTPForPasswordReset,
  changePassword,
  logoutUser,
} from './../controllers/auths.control';
import { 
  adminLogin,
  changePasswordWhenLoggedIn
} from './../controllers/admin.control';
import authMiddleware from "./../middlewares/Auth"
import { otpRateLimiter, endpointRateLimiter } from './..//middlewares/rate.limit';

const router = express.Router();

router.post('/register', endpointRateLimiter,  createUser);
router.post('/admin-login', endpointRateLimiter, otpRateLimiter, adminLogin);
router.post('/resend-otp', otpRateLimiter, resendOTP);
router.post('/otp-for-password-reset', otpRateLimiter, OTPForPasswordReset);
// Endpoint to verify OTP for password reset
router.post('/verify-otp', otpRateLimiter, verifyOtp);
router.post('/change-password', changePassword);
// Endpoint to change password when user is logged in
router.post('/change-password-logged-in-user', authMiddleware, changePasswordWhenLoggedIn)
router.post('/logout', authMiddleware, logoutUser);

router.get('/test', (_req, res) => {
  res.json({ message: 'Auth routes are working' });
});

export default router;
