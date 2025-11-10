import jwt from 'jsonwebtoken';

function getTokenFromHeader(req) {
    const authHeader = req.headers.authorization || '';
    const [scheme, token] = authHeader.split(' ');
    if (scheme !== 'Bearer' || !token) return null;
    return token;
}

export function verifyToken(req, res, next) {
    const token = getTokenFromHeader(req);

    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET);

        req.user = payload; // { id, email, role, isSuperAdmin }
        return next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

export const requiredPermission = (requiredPermission) => {
    return (req, res, next) => {
        try {
            const token = getTokenFromHeader(req);
            if (!token) return res.status(401).json({ error: 'Unauthorized' });
            const payload = jwt.verify(token, process.env.JWT_SECRET);

            const user = payload; // should be populated by JWT auth middleware

            if (!user) return res.status(401).json({ message: "Unauthorized: user not found" });

            // Always allow superadmin
            if (user.isSuperAdmin) return next();

            // Check if user has the required permission
            if (user.permissions?.includes(requiredPermission)) {
                return next();
            }

            return res.status(403).json({
                message: `Forbidden: missing permission '${requiredPermission}'`
            });
        } catch (error) {
            console.error("Permission check failed:", error);
            return res.status(500).json({ message: "Internal server error" });
        }
    };
};



// export const allowRoles = (...roles) => {
//     return (req, res, next) => {

//         if (req.user?.isSuperAdmin) {
//             return next();
//         }

//         if (!roles.includes(req.user.role)) {
//             return res.status(403).json({ success: false, message: 'Access denied' });
//         }
//         next();
//     };
// };