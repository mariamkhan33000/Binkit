import UserModel from "../models/userModels.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import verifyEmailTemplate from "../utils/verifyEmailTemplate.js";
import generatedAccessToken from "../utils/generatedAccessToken.js";


export const userRegister = async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: "All fields are required", error: true, success: false });
        }
        // Check if user already exists
        const user = await UserModel.findOne({ email });
        if (user) {
            return res.status(400).json({ message: "User already exists", error: true, success: false });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const payload = {
            name,
            email,
            password: hashedPassword,
        };
        const newUser = await UserModel.create(payload);
        const save = await newUser.save();
        if (!save) {
            return res.status(400).json({ message: "User not created", error: true, success: false });
        }
        const verifyEmailUrl = `${process.env.FRONTEND_URL}/verify-email/${save?._id}`;

        const verifyEmail = await sendEmail({
            sendTo : email,
            subject : "Verify Email from binkeyit",
            html : verifyEmailTemplate({ 
                name, 
                url : verifyEmailUrl 
            })
        })
        return res.status(200).json({ message: "User created successfully", error: false, success: true });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}

export const userLogin = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: "All fields are required", error: true, success: false });
        }
        // Check if user exists
        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User not found", error: true, success: false });
        }

        if(user.status !== "active"){
            return res.status(400).json({ message: "User not verified", error: true, success: false });
        }
        // Check password

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials", error: true, success: false });
        }
        const accessToken = await generatedAccessToken(user._id);
        const refreshToken = await genertedRefreshToken(user._id);

        const updateUser = await UserModel.findByIdAndUpdate(user?._id, {
            last_login_date : new Date()
        })
        
        const cookieOptions = {
            expires : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            httpOnly : true,
            secure : true,
            sameSite : "none",
        }
        res.cookie("refreshToken", refreshToken, cookieOptions);
        res.cookie("accessToken", accessToken, cookieOptions);
        if (!updateUser) {
            return res.status(400).json({ message: "User not updated", error: true, success: false });
        }

        
        return res.status(200).json({ message: "Login successful", error: false, success: true, accessToken, refreshToken });
    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}

export const verifyEmailController = async (req, res) => {
    try {
        const { code } = req.params;

        const user = await UserModel.findOne({ _id: code });
        if (!user) {
            return res.status(400).json({ message: "User not found", error: true, success: false });
        }
        const updateUser = await UserModel.updateOne({ _id: code }, { verify_email: true, status: "active" });
        if (!updateUser) {
            return res.status(400).json({ message: "User not updated", error: true, success: false });
        }
        return res.status(200).json({ message: "User verified successfully", error: false, success: true });


    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}


export const userLogout = async (req, res) => {
    try {
        const userid = req.user.id;
        
        const cookieOptions = {
            expires : new Date(Date.now()),
            httpOnly : true,
            secure : true,
            sameSite : "none",
        }
        res.clearCookie("refreshToken", cookieOptions);
        res.clearCookie("accessToken", cookieOptions);

        const removeRefreshToken = await UserModel.findByIdAndUpdate(userid, {
            refresh_token : ""
        })

        return res.status(200).json({ message: "Logout successful", error: false, success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}


// upload avatar 
export const uploadAvatar = async (req, res) => {
    try {
        const userId = req.user.id;
        const image = req.file //multer

        const upload = await UserModel.findByIdAndUpdate(userId, {
            avatar : upload.url
        })
        return res.status(200).json({ message: "Avatar uploaded successfully", error: false, success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}

// update user detail

export const updateUserDetails = async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, email, mobile, password } = req.body;
        if (!name || !email || !mobile || !password) {
            return res.status(400).json({ message: "All fields are required", error: true, success: false });
        }
        let hashedPassword = "";
        if (password) {
            const salt = await bcrypt.genSalt(10);
            hashedPassword = await bcrypt.hash(password, salt);
        }

        const updateUser = await UserModel.updateOne({ _id: userId }, {
            ...(name && { name : name }),
            ...(email && { email : email }),
            ...(mobile && { mobile : mobile }),
            ...(password && { password : hashedPassword })
        })

        return res.status(200).json({ message: "User updated successfully", error: false, success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}


// forgot password not login

export const forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User not found", error: true, success: false });
        }

        const otp = generateOTP();

        const expiteTime = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        const updateUser = await UserModel.findByIdAndUpdate(user._id, {
            forgot_password_otp : otp,
            forgot_password_otp_expire : new Date(expiteTime).toISOString()
        })

        await sendEmail({
            sendTo : email,
            subject : 'Forgot Password from Binkit',
            html : forgotPasswordTemplate({ 
                name : user.name, 
                otp : otp 
            })
        })

        return res.status(200).json({ message: "OTP sent to your email", error: false, success: true });
    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}

// verify otp and reset password
export const verifyForgotPasswordOtp = async (req, res) => {
    try {
        const { email, otp} = req.body;
        if (!email || !otp) {
            return res.status(400).json({ message: "All fields are required", error: true, success: false });
        }

        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User not found", error: true, success: false });
        }
        const currentTime = new Date().toISOString();

        if(user.forgot_password_expiry < currentTime){
            return res.status(400).json({ message: "OTP expired", error: true, success: false });
        }
        if(user.forgot_password_otp !== otp){
            return res.status(400).json({ message: "Invalid OTP", error: true, success: false });
        }

        // if otp is not expired
        // otp === user.forgot_password_otp

        const updateUser = await UserModel.findByIdAndUpdate(user._id, {
            forgot_password_otp : "",
            forgot_password_otp_expire : ""
        })

        if (!updateUser) {
            return res.status(400).json({ message: "User not updated", error: true, success: false });
        }
        return res.status(200).json({ message: "OTP verified successfully", error: false, success: true });

    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}

// reset password

export const resetPassword = async (req, res) => {
    try {
        const { email, newPassword, confirmPassword } = req.body;
        if (!email || !newPassword || !confirmPassword) {
            return res.status(400).json({ message: "All fields are required", error: true, success: false });
        }
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: "Password not matched", error: true, success: false });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        const user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User not found", error: true, success: false });
        }

        const updateUser = await UserModel.findByIdAndUpdate(user._id, {
            password : hashedPassword
        })
        if (!updateUser) {
            return res.status(400).json({ message: "User not updated", error: true, success: false });
        }
        return res.status(200).json({ message: "Password reset successfully", error: false, success: true });

    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}


// refresh token controller

export const refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken || req?.headers?.authorization?.split(" ")[1];
        if (!refreshToken) {
            return res.status(400).json({ message: "Refresh token not found", error: true, success: false });
        }

        const verifyToken = await jwt.verify(refreshToken, process.env.JWT_SECRET);
        if (!verifyToken) {
            return res.status(400).json({ message: "Invalid refresh token", error: true, success: false });
        }

        const userId = verifyToken?.id;

        const newAccessToken = await generatedAccessToken(userId);

        const cookieOptions = {
            httpOnly : true,
            secure : true,
            sameSite : "none",
        }
        res.cookie("accessToken", newAccessToken, cookieOptions);

        return res.status(200).json({ message: "New access token generated", error: false, success: true,
             accessToken : newAccessToken });
    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}

// get login USer Details

export const userDetails = async (req, res) => {
    try {
        const userId = req.user.id;
        console.log(userId);

        const user = await UserModel.findById(userId).select("-password -refresh_token -verify_email -forgot_password_otp -forgot_password_otp_expire");
        if (!user) {
            return res.status(400).json({ message: "User not found", error: true, success: false });
        }
        return res.status(200).json({ message: "User details", error: false, success: true, user });
    } catch (error) {
        return res.status(500).json({ message: error.message, error: true, success: false });
    }
}