export function sanitizeUser(row) {
    return {
        id: row.id,
        name: row.name,
        email: row.email,
        role: row.role,
        isSuperAdmin: !!row.is_super_admin,
        isVerified: !!row.is_verified,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}