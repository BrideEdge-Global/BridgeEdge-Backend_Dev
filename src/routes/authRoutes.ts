import express from 'express';
import { 
  createUser, 
  verifyOtp,
  resendOTP, 
  changePassword,
  sendOtpForPasswordChanging 
} from './../controllers/auths.control';
import { 
  adminLogin,
  changePasswordWhenLoggedIn
} from './../controllers/admin.control';
import authMiddleware from "./../middlewares/Auth"
import { otpRateLimiter, loginRateLimiter } from './..//middlewares/rate.limit';

const router = express.Router();

router.post('/register',  createUser);
router.post('/admin-login', loginRateLimiter, otpRateLimiter, adminLogin);
router.post('/resend-otp', otpRateLimiter, resendOTP);
router.post('/verify-otp', verifyOtp);
router.post('/send-otp-for-password-changing', otpRateLimiter, sendOtpForPasswordChanging);
router.post('/change-password', changePassword);
router.post('/change-password-logged-in-user', authMiddleware, changePasswordWhenLoggedIn)


router.get('/test', (_req, res) => {
  res.json({ message: 'Auth routes are working' });
});

export default router;
