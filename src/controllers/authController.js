import bcrypt from 'bcrypt';

import { getPool } from '../config/db.js';
import generateOtp from '../utils/generateOtp.js';
import { sendOtpEmail } from '../services/emailService.js';
import { generateToken } from '../utils/generateToken.js';
import { sanitizeUser, parseJsonArray } from '../utils/authHelpers.js';

const SALT_ROUNDS = 10;
const OTP_TTL_MINUTES = 5; // 5 minutes

// 1. Register a new user
export async function register(req, res) {
    try {
        const { name, email, password } = req.body || {};
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email and password are required' });
        }
        console.log(name, email, password);

        // Normalize the email
        const normalizedEmail = String(email).toLowerCase().trim();
        // Get the pool from the database
        const pool = getPool();

        // Get the user from the database
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ? LIMIT 1', [normalizedEmail]);
        const existing = rows[0];

        // Hash the password
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        // Generate the OTP
        const otp = generateOtp();
        // Set the expiration time for the OTP
        const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);

        // Check if the user already exists
        if (existing) {
            // Check if the user is already verified
            if (existing.is_verified) {
                return res.status(409).json({ error: 'Email is already registered and verified. Please log in.' });
            }
            // Update the user in the database with the new password and OTP
            await pool.execute(
                'UPDATE users SET name = ?, password_hash = ?, otp_code = ?, otp_expires_at = ?, updated_at = NOW() WHERE id = ?',
                [name, passwordHash, otp, expiresAt, existing.id]
            );
            // Send the OTP to the email with the new password and OTP
            await sendOtpEmail(normalizedEmail, name, otp);

            // Return the response
            return res.status(201).json({ message: 'Registration pending verification. OTP sent to email.' });
        }

        // Insert the user into the database with the new password, OTP, and expiration time
        await pool.execute(
            `INSERT INTO users (
            name, email, password_hash, is_verified,
            otp_code, otp_expires_at, role)
            VALUES (?, ?, ?, 0, ?, ?, ?)`,
            [name, normalizedEmail, passwordHash, otp, expiresAt, "admin"]
        );

        // Send the OTP to the email with the new password and OTP
        await sendOtpEmail(normalizedEmail, name, otp);

        // Return the response
        return res.status(201).json({ success: true, message: 'Registration successful. OTP sent to email.' });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ error: 'Failed to register user' });
    }
}

// 2. Login a user
export async function login(req, res) {
    try {
        const { email, password } = req.body || {};
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        const normalizedEmail = String(email).toLowerCase().trim();
        const pool = getPool();

        // Get the user from the database
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ? LIMIT 1', [normalizedEmail]);
        const user = rows[0];

        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (!user.is_verified) return res.status(403).json({ error: 'Please verify your email before logging in' });

        // Compare the password and the password hash
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

        const permissions = parseJsonArray(user.permissions);

        const token = generateToken({
            id: user.id,
            role: user.role,
            isSuperAdmin: user.is_super_admin,
            email: user.email,
            permissions
        });
        return res.json({ success: true, token, user: { ...sanitizeUser(user), permissions } });

    } catch (error) {
        return res.status(500).json({ error: 'Failed to login' });
    }
}

// 3. Login as an admin
export async function adminLogin(req, res) {
    try {
        const { email, password } = req.body || {};
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        const normalizedEmail = String(email).toLowerCase().trim();
        const pool = getPool();

        // Use users table with role admin or superadmin
        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE email = ? LIMIT 1',
            [normalizedEmail]
        );
        const admin = rows[0];
        if (!admin) return res.status(401).json({ error: 'Invalid credentials' });

        // Only allow admin or superadmin
        if (admin.role !== 'admin' && !admin.is_super_admin) {
            return res.status(403).json({ error: 'Not authorized as admin' });
        }

        // Compare password and Validate the password
        const valid = await bcrypt.compare(password, admin.password_hash);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

        const permissions = parseJsonArray(admin.permissions);

        const token = generateToken({
            id: admin.id,
            role: admin.role,
            isSuperAdmin: admin.is_super_admin,
            email: admin.email,
            permissions
        });

        // Return the response
        return res.json({ success: true, token, admin: { ...sanitizeUser(admin), permissions } });
    }
    catch (error) {
        // Return the error
        return res.status(500).json({ error: 'Failed to login' });
    }
}

// 4. Verify an OTP
export async function verifyOtp(req, res) {
    try {
        const { email, otp } = req.body || {};
        if (!email || !otp) {
            return res.status(400).json({ error: 'Email and OTP are required' });
        }

        // Normalize the email
        const normalizedEmail = String(email).toLowerCase().trim();
        // Get the pool from the database
        const pool = getPool();

        // Get the user from the database
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ? LIMIT 1', [normalizedEmail]);
        const user = rows[0];

        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.is_verified) return res.status(400).json({ error: 'User already verified' });

        // Check if the OTP is valid
        if (!user.otp_code || String(user.otp_code) !== String(otp)) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        // Check if the OTP has expired
        const now = new Date();
        const expiry = user.otp_expires_at ? new Date(user.otp_expires_at) : null;
        if (!expiry || now > expiry) {
            return res.status(400).json({ success: false, error: 'OTP has expired' });
        }

        // Update the user in the database with the new OTP
        await pool.execute(
            'UPDATE users SET is_verified = 1, otp_code = NULL, otp_expires_at = NULL, updated_at = NOW() WHERE id = ?',
            [user.id]
        );

        const permissions = parseJsonArray(user.permissions);

        const token = generateToken({
            id: user.id,
            role: user.role,
            isSuperAdmin: user.is_super_admin,
            email: user.email,
            permissions
        });

        // Return the response
        const updatedUser = {
            ...user,
            is_verified: 1,
            otp_code: null,
            otp_expires_at: null,
            permissions,
        };

        return res.json({ success: true, token, user: sanitizeUser(updatedUser) });
    } catch (error) {
        return res.status(500).json({ error: 'Failed to verify OTP' });
    }
}

// 5. Resend an OTP
export async function resendOtp(req, res) {
    try {
        const { email } = req.body || {};
        if (!email) return res.status(400).json({ error: 'Email is required' });


        const normalizedEmail = String(email).toLowerCase().trim();
        const pool = getPool();

        // Get the user from the database
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ? LIMIT 1', [normalizedEmail]);
        const user = rows[0];

        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.is_verified) return res.status(400).json({ error: 'User already verified' });

        // Generate the OTP
        const otp = generateOtp();
        const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);

        // Update the user in the database with the new OTP
        await pool.execute(
            'UPDATE users SET otp_code = ?, otp_expires_at = ?, updated_at = NOW() WHERE id = ?',
            [otp, expiresAt, user.id]
        );

        await sendOtpEmail(normalizedEmail, user.name, otp);
        return res.json({ success: true, message: 'OTP resent to email' });

    } catch (error) {
        return res.status(500).json({ error: 'Failed to resend OTP' });
    }
}

// 6. Get the current user
export async function getMe(req, res) {
    try {
        const userId = req.user && req.user.id;
        if (!userId) return res.status(401).json({ error: 'Unauthorized' });

        // Get the user from the database
        const pool = getPool();
        const [rows] = await pool.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [userId]);
        const user = rows[0];
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Return the response
        return res.json({ success: true, user: sanitizeUser(user) });
    } catch (error) {
        return res.status(500).json({ error: 'Failed to fetch user' });
    }
}

export default {
    register,
    verifyOtp,
    login,
    adminLogin,
    resendOtp,
    getMe,
};


