export function parseJsonArray(value) {
    if (!value) return [];

    if (Array.isArray(value)) {
        return value;
    }

    if (typeof value === 'string') {
        try {
            const parsed = JSON.parse(value);
            if (Array.isArray(parsed)) return parsed;
        } catch (error) {
            return value
                .split(',')
                .map((item) => item.trim())
                .filter(Boolean);
        }
    }

    if (typeof value === 'object') {
        try {
            return Array.isArray(value)
                ? value
                : Object.values(value)
                    .map((item) => String(item).trim())
                    .filter(Boolean);
        } catch (error) {
            return [];
        }
    }

    return [];
}

export function sanitizeUser(row) {
    const permissions = parseJsonArray(row?.permissions);

    return {
        id: row.id,
        name: row.name,
        email: row.email,
        role: row.role,
        isSuperAdmin: !!row.is_super_admin,
        isVerified: !!row.is_verified,
        permissions,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    };
}