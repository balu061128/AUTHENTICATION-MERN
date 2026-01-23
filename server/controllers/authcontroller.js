// server/controllers/authcontroller.js

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import UsersModel from '../models/usersmodel.js';
import transporter from '../config/nodemailer.js';

/* ================= REGISTER ================= */
export const register = async (req, res) => {
    const { name, email, password } = req.body;
// Validate input
    if (!name || !email || !password) {
        return res.json({ success: false, message: "Missing required details" });
    }

    try {
        const existingUser = await UsersModel.findOne({ email });
        if (existingUser) {     
            return res.json({ success: false, message: "User already exists" });
        }
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new UsersModel({
            name,
            email,
            password: hashedPassword,
            isAccountVerified: false
        });

        await newUser.save();

        const token = jwt.sign(
            { userId: newUser._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        try {
            await transporter.sendMail({
                from: process.env.SENDER_EMAIL,
                to: newUser.email,
                subject: 'Welcome',
                text: `Hello ${name}, welcome to our application!`
            });
        } catch (e) {
            console.log("Email failed:", e.message);
        }

        return res.json({ success: true, message: "Registration successful" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

/* ================= LOGIN ================= */
export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "Missing required details" });
    }

    try {
        const user = await UsersModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: "Invalid email" });
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if (!isPasswordCorrect) {
            return res.json({ success: false, message: "Invalid password" });
        }

        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true, message: "Login successful" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

/* ================= LOGOUT ================= */
export const logout = async (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });

        return res.json({ success: true, message: "Logout successful" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

/* ================= SEND OTP ================= */
export const verifyUser = async (req, res) => {
    try {
        const userId = req.userId; // ✅ from JWT
        const user = await UsersModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: "User already verified" });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpiry = Date.now() + 24 * 60 * 60 * 1000;
        await user.save();

        await transporter.sendMail({
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification',
            text: `Your OTP is ${otp}. Valid for 24 hours.`
        });

        return res.json({ success: true, message: "OTP sent to email" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
};

/* ================= VERIFY EMAIL ================= */
export const verifyEmail = async (req, res) => {
    try {
        const userId = req.userId; // ✅ from JWT
        const { otp } = req.body;

        if (!otp) {
            return res.json({ success: false, message: "OTP required" });
        }

        const user = await UsersModel.findById(userId);
        if (!user) {
            return res.json({ success: false, message: "User not found" });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: "User already verified" });
        }

        if (!user.verifyOtp || user.verifyOtp !== otp) {
            return res.json({ success: false, message: "Invalid OTP" });
        }

        if (user.verifyOtpExpiry < Date.now()) {
            return res.json({ success: false, message: "OTP expired" });
        }

        user.isAccountVerified = true;
        user.verifyOtp = null;
        user.verifyOtpExpiry = null;
        await user.save();

        return res.json({ success: true, message: "Email verified successfully" });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// ================= CHECK AUTHENTICATION =================
export const isAuthenticated = async (req, res) => {
    try {
        return res.json({ success: true, message: "User is authenticated" }); 
    }
    catch (error) {
        return res.json({ success: false, message: error.message });
    }
} 
//=====================send password reset otp==================
//==============================================================
export const sendPasswordResetOtp = async (req, res) => {
    const { email } = req.body;
    if(!email){
        return res.json({ success: false, message: "Email is required" });
    }
    try 
    {
        const user= await UsersModel.findOne({email});
        if(!user){
            return res.json({ success: false, message: "User not found" });
        }
        
        
    }
    catch (error) 
    {
        return res.json({ success: false, message: error.message });
    }

    
    
}