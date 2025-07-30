import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config/index';

const JWT_SECRET = config.jwtSecret;
if (!JWT_SECRET) throw new Error('JWT_SECRET is not defined');

const authMiddleware = (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ message: 'No token provided' });
        return;
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET as string);
        (req as any).user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid token' });
        return;
    }
};

export default authMiddleware;