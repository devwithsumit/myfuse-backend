import { getPool } from '../config/db.js';

export const getAdmins = async (req, res) => {
    try {
        const pool = getPool();

        const [admins] = await pool.execute('SELECT * FROM users WHERE role = "admin" OR role = "superadmin"');

        return res.status(200).json({ success: true, data: admins });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
}

export const deleteAdmin = async (req, res) => {
    try {
        const pool = getPool();
        const { id } = req.params;
        await pool.execute('DELETE FROM users WHERE id = ?', id);
        return res.status(200).json({ success: true, message: 'Admin deleted successfully' });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
}