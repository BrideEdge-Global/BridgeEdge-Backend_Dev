import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import User from './../models/user.model';
import { config } from './../config/index';
import CustomResponse from './../utils/custom.response';
import jwt from 'jsonwebtoken';
import { generateOTP } from './../services/otp.generator';
import { sendEmail } from './../services/email.service';
import passwordRules from './../utils/password.check';
import { UserAttributes } from './../models/user.model';

const JWT_SECRET = config.jwtSecret;
if (!JWT_SECRET) throw new Error('JWT_SECRET is not defined');

declare module 'express-serve-static-core' {
  interface Request {
    user?: UserAttributes; // or whatever type your user object is
  }
}

/**
 * Log in an existing user
 */
export const adminLogin = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ where: { email } });
    if (!user) {
      CustomResponse.errorResponse(res, 'User not found', 404, {});
      return;
    }

    const isPasswordValid = await bcrypt.compare(password, user.getDataValue('password'));
    if (!isPasswordValid) {
      CustomResponse.errorResponse(res, 'Invalid login details. Please try again.', 401, {});
      return;
    }

    if (!user.isAdmin){
        CustomResponse.errorResponse(res, 'Invalid login details. This user is not an Admin', 401, {});
      return;
    }

    if (!user.isVerified) {
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes

        user.otp = otp;
        user.otpExpires = otpExpires;
        await user.save();

        await sendEmail({
            to: email,
            subject: 'Your OTP Code',
            text: `Your OTP code is ${otp}. It will expire in 10 minutes.`,
        });
        CustomResponse.successResponse(res, 'Your account as not been verified, OTP sent successfully', 200, {
        email,
        otpExpires,
        });
        return;
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });

    CustomResponse.successResponse(res, 'Login successful', 200, {
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    });
    return;
  } catch (error: any) {
    CustomResponse.errorResponse(res, `Server Error: ${error.message || error}`, 500, {});
    return;
  }
};

/**
 * Reset password endpoint when user is logged in
 * This endpoint allows a user to change their password while logged in.
 */
export const changePasswordWhenLoggedIn = async (req: Request, res: Response): Promise<void> => {
  const userId = req.user?.id; // Assuming user ID is stored in req.user after authentication
  const { currentPassword, newPassword, confirmNewPassword } = req.body;

  if (!userId) {
    CustomResponse.errorResponse(res, 'User not authenticated', 401, {});
    return;
  }

  if (!currentPassword || !newPassword || !confirmNewPassword) {
    CustomResponse.errorResponse(res, 'All fields are required', 400, []);
    return;
  }

  if (!passwordRules.test(newPassword)) {
    CustomResponse.errorResponse(
      res,
      'Password must be at least 8 characters and include uppercase, lowercase, number, and special character',
      400,
      []
    );
    return;
  }

  if (newPassword !== confirmNewPassword) {
    CustomResponse.errorResponse(res, 'New passwords do not match', 400, []);
    return;
  }

  try {
    const user = await User.findByPk(userId);

    if (!user) {
      CustomResponse.errorResponse(res, 'User not found', 404, {});
      return;
    }
    
    if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
      CustomResponse.errorResponse(res, 'Current password is incorrect', 401, {});
      return;
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedNewPassword;
    await user.save();

    CustomResponse.successResponse(res, 'Password changed successfully', 200, {});
    return;
  } catch (error) {
    CustomResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    return;
  }
};