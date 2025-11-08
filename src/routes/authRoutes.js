import express from 'express';

import { verifyToken } from '../middlewares/authMiddleware.js';
import { register, verifyOtp, login, resendOtp, getMe, adminLogin } from '../controllers/authController.js';

const router = express.Router();

router.post('/register', register);
router.post('/verify', verifyOtp);
router.post('/login', login);
router.post('/resend-otp', resendOtp);

router.post('/admin-login', adminLogin);

router.get('/user/me', verifyToken, getMe);

export default router;


