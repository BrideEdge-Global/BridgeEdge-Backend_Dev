import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from './../models/user.model';
import { config } from './../config/index';
import CustomResponse from './../utils/custom.response';
import passwordRules from './../utils/password.check';
import { generateOTP } from './../services/otp.generator';
import { sendEmail } from './../services/email.service';

const JWT_SECRET = config.jwtSecret;
if (!JWT_SECRET) throw new Error('JWT_SECRET is not defined');

/**
 * Create a new user (admin or customer)
 */
export const createUser = async (req: Request, res: Response): Promise<void> => {
  const { email, password, confirmPassword, isAdmin, isCustomer, isActive } = req.body;

  if (!passwordRules.test(password)) {
    CustomResponse.errorResponse(
      res,
      'Password must be at least 8 characters and include uppercase, lowercase, number, and special character',
      400,
      []
    );
    return;
  }

  if (password !== confirmPassword) {
    CustomResponse.errorResponse(res, 'Password does not match', 409, []);
    return;
  }

  try {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      CustomResponse.errorResponse(res, 'User already exists', 409, []);
      return;
    }

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await User.create({
      email,
      password: hashedPassword,
      isAdmin: isAdmin ?? false,
      isCustomer: isCustomer ?? true,
      isActive: isActive ?? true,
    });

    CustomResponse.successResponse(res, 'User created successfully', 201, {
      user: {
        id: newUser.id,
        email: newUser.email,
        isAdmin: newUser.isAdmin,
        isCustomer: newUser.isCustomer,
        isActive: newUser.isActive,
      },
    });
    return;
  } catch (error: any) {
    CustomResponse.errorResponse(res, `Server Error: ${error.message || error}`, 500, []);
    return;
  }
};

/**
 * Log in an existing user
 */
export const login = async (req: Request, res: Response): Promise<void> => {
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
 * Sending OTP endpoint for user verification
 */
export const sendOtp = async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      CustomResponse.errorResponse(res, 'User not found', 404, {});
      return;
    }

    if (user.isVerified) {
      CustomResponse.errorResponse(res, 'User is already verified', 400, {});
      return;
    }

    if (!user.isActive) {
      CustomResponse.errorResponse(res, 'User is not active', 403, {});
      return;
    }

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
    CustomResponse.successResponse(res, 'OTP sent successfully', 200, {
      email,
      otpExpires,
    });
  }
  catch (error) {
    CustomResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    return;
  }
};

/**
 * Verify OTP endpoint
 */
export const verifyOtp = async (req: Request, res: Response): Promise<void> => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ where: { email } });

    if (!email || !otp) {
      CustomResponse.errorResponse(res, 'Email and OTP are required', 400, {});
      return;
    }
    

    if (!user || !user.otp || !user.otpExpires) {
      CustomResponse.errorResponse(res, 'Invalid request', 404, {});
      return;
    }

    if (user.otp !== otp) {
      CustomResponse.errorResponse(res, 'Invalid OTP', 400, {});
      return;
    }

    if (user.otpExpires < new Date()) {
      CustomResponse.errorResponse(res, 'OTP has expired', 400, {});
      return;
    }

    // OTP is valid, clear it
    user.otp = null;
    user.otpExpires = null;
    user.isVerified = true; // Mark user as verified
    await user.save();

    CustomResponse.successResponse(res, 'OTP verified successfully', 200, {});
    return;
  } catch (error) {
    CustomResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    return;
  }
};

/**
 * Forget password section with OTP sending and verification
 * This endpoint allows a user to change their password using an OTP sent to their email.
 * Below is the implementation of sending an OTP for password changing.
 */
export const sendOtpForPasswordChanging = async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      CustomResponse.errorResponse(res, 'User not found', 404, {});
      return;
    }

    if (!user.isActive) {
      CustomResponse.errorResponse(res, 'User is not active', 403, {});
      return;
    }

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
    CustomResponse.successResponse(res, 'OTP sent successfully', 200, {
      email,
      otpExpires,
    });
  }
  catch (error) {
    CustomResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    return;
  }
};

/**
 * Change password endpoint using OTP
 * This endpoint allows a user to change their password using an OTP sent to their email.
 */
export const changePassword = async (req: Request, res: Response): Promise<void> => {
  const {email, otp, newPassword, confirmNewPassword} = req.body;

  try {

    if (!email || !otp || !newPassword || !confirmNewPassword) {
      CustomResponse.errorResponse(res, 'All fields are required', 400, []);
      return;
    }

    const user = await User.findOne({ where: { email } });

    if (!user || user.otp !== otp || !user.otpExpires || user.otpExpires < new Date()) {
      CustomResponse.errorResponse(res, 'Invalid request', 404, {});
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

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = null; // Clear OTP after successful password change
    user.otpExpires = null; // Clear OTP expiration
    await user.save();

    CustomResponse.successResponse(res, 'Password reset successfully', 200, {});
    return;
  } catch (error) { 
    CustomResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
    return;
  }
};

/**
 * Reset password endpoint when user is logged in
 * This endpoint allows a user to change their password while logged in.
 */

// export const changePasswordWhenLoggedIn = async (req: Request, res: Response): Promise<void> => {
//   const userId = req.user?.id; // Assuming user ID is stored in req.user after authentication
//   const { currentPassword, newPassword, confirmNewPassword } = req.body;

//   if (!userId) {
//     CustomResponse.errorResponse(res, 'User not authenticated', 401, {});
//     return;
//   }

//   if (!currentPassword || !newPassword || !confirmNewPassword) {
//     CustomResponse.errorResponse(res, 'All fields are required', 400, []);
//     return;
//   }

//   if (!passwordRules.test(newPassword)) {
//     CustomResponse.errorResponse(
//       res,
//       'Password must be at least 8 characters and include uppercase, lowercase, number, and special character',
//       400,
//       []
//     );
//     return;
//   }

//   if (newPassword !== confirmNewPassword) {
//     CustomResponse.errorResponse(res, 'New passwords do not match', 400, []);
//     return;
//   }

//   try {
//     const user = await User.findByPk(userId);

//     if (!user) {
//       CustomResponse.errorResponse(res, 'User not found', 404, {});
//       return;
//     }
    
//     if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
//       CustomResponse.errorResponse(res, 'Current password is incorrect', 401, {});
//       return;
//     }

//     const hashedNewPassword = await bcrypt.hash(newPassword, 10);
//     user.password = hashedNewPassword;
//     await user.save();

//     CustomResponse.successResponse(res, 'Password changed successfully', 200, {});
//     return;
//   } catch (error) {
//     CustomResponse.errorResponse(res, `Server Error: ${error}`, 500, {});
//     return;
//   }
// };