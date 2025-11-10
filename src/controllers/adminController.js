import bcrypt from 'bcrypt';
import { getPool } from '../config/db.js';
import { parseJsonArray, sanitizeUser } from '../utils/authHelpers.js';

const ALLOWED_ROLES = new Set(['user', 'admin', 'superadmin']);

function normalizeEmail(email = '') {
    return String(email).toLowerCase().trim();
}

function normalizeRole(role = 'admin') {
    const normalized = String(role).toLowerCase().trim();
    return ALLOWED_ROLES.has(normalized) ? normalized : 'admin';
}

function toPermissionsArray(value, isSuperAdmin) {
    if (isSuperAdmin) {
        return [];
    }
    const parsed = parseJsonArray(value);
    return Array.from(new Set(parsed));
}

function toPermissionsJson(value, isSuperAdmin) {
    const permissionsArray = toPermissionsArray(value, isSuperAdmin);
    return JSON.stringify(permissionsArray);
}

export const getAdmins = async (req, res) => {
    try {
        const pool = getPool();

        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE role = "admin" OR role = "superadmin" ORDER BY created_at DESC'
        );

        const admins = rows.map((admin) => {
            const sanitized = sanitizeUser(admin);
            return {
                ...sanitized,
                is_super_admin: admin.is_super_admin,
                permissions: toPermissionsArray(admin.permissions, admin.is_super_admin),
            };
        });

        return res.status(200).json({ success: true, data: admins });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

export const createAdmin = async (req, res) => {
    try {
        const pool = getPool();
        const { name, email, password, role = 'admin', permissions = [], isSuperAdmin } = req.body ?? {};

        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'Name, email and password are required' });
        }

        const normalizedEmail = normalizeEmail(email);
        const normalizedRole = normalizeRole(role);
        const isSuperAdminFlag = normalizedRole === 'superadmin' || Boolean(isSuperAdmin);

        const [existing] = await pool.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [normalizedEmail]);
        if (existing.length > 0) {
            return res.status(409).json({ success: false, message: 'Email is already in use' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const permissionsJson = toPermissionsJson(permissions, isSuperAdminFlag);

        const [result] = await pool.execute(`INSERT INTO users 
            (name, email, password_hash, role, permissions, is_super_admin, is_verified)
             VALUES (?, ?, ?, ?, CAST(? AS JSON), ?, 1);`,
            [name, normalizedEmail, passwordHash, normalizedRole, permissionsJson, isSuperAdminFlag ? 1 : 0]);

        if (result.affectedRows === 0) {
            return res.status(400).json({ success: false, message: 'Failed to create admin' });
        }

        const [createdRows] = await pool.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [result.insertId]);
        const createdAdmin = createdRows[0];

        return res.status(201).json({
            success: true,
            message: 'Admin created successfully',
            data: {
                ...sanitizeUser(createdAdmin),
                is_super_admin: createdAdmin.is_super_admin,
                permissions: toPermissionsArray(createdAdmin.permissions, createdAdmin.is_super_admin),
            }
        });
    }
    catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

export const updateAdmin = async (req, res) => {
    try {
        const pool = getPool();
        const { id } = req.params;
        const { name, email, password, role, permissions = [], isSuperAdmin } = req.body ?? {};

        if (!name || !email || !role) {
            return res.status(400).json({ success: false, message: 'Name, email and role are required' });
        }

        const normalizedEmail = normalizeEmail(email);
        const normalizedRole = normalizeRole(role);
        const isSuperAdminFlag = normalizedRole === 'superadmin' || Boolean(isSuperAdmin);
        const permissionsJson = toPermissionsJson(permissions, isSuperAdminFlag);

        const updateFields = [
            'name = ?',
            'email = ?',
            'role = ?',
            'permissions = CAST(? AS JSON)',
            'is_super_admin = ?',
            'updated_at = NOW()'
        ];

        const params = [
            name,
            normalizedEmail,
            normalizedRole,
            permissionsJson,
            isSuperAdminFlag ? 1 : 0,
        ];

        if (password && password.trim()) {
            const passwordHash = await bcrypt.hash(password, 10);
            updateFields.push('password_hash = ?');
            params.push(passwordHash);
        }

        params.push(id);

        const [result] = await pool.execute(
            `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?;`,
            params
        );

        if (result.affectedRows === 0) {
            return res.status(400).json({ success: false, message: 'Failed to update admin' });
        }

        const [updatedRows] = await pool.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [id]);
        const updatedAdmin = updatedRows[0];

        return res.status(200).json({
            success: true,
            message: 'Admin updated successfully',
            data: {
                ...sanitizeUser(updatedAdmin),
                is_super_admin: updatedAdmin.is_super_admin,
                permissions: toPermissionsArray(updatedAdmin.permissions, updatedAdmin.is_super_admin),
            }
        });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};
export const deleteAdmin = async (req, res) => {
    try {
        const pool = getPool();
        const { id } = req.params;
        if (req.user.id.toString() === id.toString()) {
            return res.status(400).json({ success: false, message: 'You cannot delete yourself' });
        }

        await pool.execute('DELETE FROM users WHERE id = ?', [id]);
        return res.status(200).json({ success: true, message: 'Admin deleted successfully' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};