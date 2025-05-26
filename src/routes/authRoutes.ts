import express from 'express';
import { 
  createUser, 
  login, 
  sendOtp, 
  verifyOtp, 
  changePassword,
  sendOtpForPasswordChanging 
} from './../controllers/auths.control';

const router = express.Router();

router.post('/register', createUser);
router.post('/login', login);
router.post('/send-otp', sendOtp);
router.post('/verify-otp', verifyOtp);
router.post('/send-otp-for-password-changing', sendOtpForPasswordChanging);
router.post('/change-password', changePassword);


router.get('/test', (_req, res) => {
  res.json({ message: 'Auth routes are working' });
});

export default router;
