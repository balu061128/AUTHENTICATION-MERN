 
import express from 'express'
import { login, register, logout, verifyEmail, verifyUser, isAuthenticated, resetPassword, sendPasswordResetOtp } from '../controllers/authcontroller.js';
import userAuth from '../middleware/userAuth.js';

const authRouter = express.Router();

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp', userAuth, verifyUser);
authRouter.post('/verify-account', userAuth, verifyEmail);
authRouter.post('/is-auth', userAuth, isAuthenticated);
authRouter.post('/send-reset-otp', sendPasswordResetOtp);
authRouter.post('/reset-password', resetPassword);


export default authRouter;