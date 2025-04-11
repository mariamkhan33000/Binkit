import express from 'express'
import { forgotPassword, refreshToken, resetPassword, updateUserDetails, uploadAvatar, userDetails, userLogin, userLogout, userRegister, verifyEmailController, verifyForgotPasswordOtp } from '../controllers/userController.js'
import auth from '../middleware/auth.js'
import uplaod from '../middleware/multer.js'

const router = express.Router()

router.post('/register', userRegister)
router.post('/login', userLogin)
router.post('/verify-email', auth, verifyEmailController)
router.get('/logout', auth, userLogout)
router.put('upload-avatar', auth, uplaod.single('avatar'), uploadAvatar)
router.put('/update-user', auth, updateUserDetails)
router.put('/forgot-password', auth, forgotPassword)
router.put('/verify-forgot-password-otp', verifyForgotPasswordOtp)
router.put('/reset-password', resetPassword)
router.post('/refresh-token', refreshToken)
router.get('user-details', auth, userDetails)



export default router