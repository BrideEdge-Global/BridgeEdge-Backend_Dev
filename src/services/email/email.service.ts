import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';
import { config } from './../../config/index';

function loadTemplate(templateName: string, variables: Record<string, any>): string {
  const templatePath = path.join(__dirname, '..', 'email\\template', templateName);
  let template = fs.readFileSync(templatePath, 'utf-8');

  Object.entries(variables).forEach(([key, value]) => {
    template = template.replace(new RegExp(`{{${key}}}`, 'g'), value);
  });

  return template;
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: config.emailUser,
    pass: config.emailPass,
  },
});

export const sendVerificationEmail = async (email: string, otp: string) => {
   const html = loadTemplate('verification_template.html', {
      otp,
      expiryTime: '10 minutes',
      year: new Date().getFullYear(),
    });

    await transporter.sendMail({
      from: '"BridgeEdge" <no-reply@bridgeedge.com>',
      to: email,
      subject: 'Verify Your BridgeEdge Account',
      html,
    });
  };

export const sendResetPasswordOTP = async (email: string, otp: string) => {
  const html = loadTemplate('forget_password_template.html', {
    otp,
    expiryTime: '10 minutes',
    year: new Date().getFullYear(),
  });

  await transporter.sendMail({
    from: '"BridgeEdge" <no-reply@bridgeedge.com>',
    to: email,
    subject: 'BridgeEdge Password Reset OTP',
    html,
  });
};

