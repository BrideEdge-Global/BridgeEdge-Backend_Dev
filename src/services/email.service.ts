import nodemailer from 'nodemailer';
import { config } from './../config/index'

export const sendEmail = async ({
    to, 
    subject,
    text,
}: {
    to: string;
    subject: string;
    text: string;
}) => {
    try {
        const transporter = nodemailer.createTransport({
            service: 'Gmail', // or any other email service
            auth: {
                user: config.emailUser, // Your email address
                pass: config.emailPass, // Your email password or app password
            },
        });

        await transporter.sendMail({
            from: `"No Reply" <${config.emailUser}>`, // sender address
            to,
            subject,
            text,
        });
        
    } catch (error) {
        throw new Error(`Email sending failed: ${error}`);
    }
}