import { Router } from 'express';
import { verifyToken, allowRoles } from '../middlewares/authMiddleware.js';
import { getAdmins, deleteAdmin } from '../controllers/adminController.js';

const router = Router();

// Example: GET /api/admin/test
router.get('/test', (req, res) => {
    res.status(200).json({ success: true, message: 'Admin route works!' });
});

router.delete("/:id", verifyToken, allowRoles('superadmin'), deleteAdmin);

router.get("/", verifyToken, allowRoles('admin', 'superadmin'), getAdmins);
// router.post("/", verifyToken, allowRoles('admin', 'superadmin'), createAdmin);
// router.put("/:id", verifyToken, allowRoles('admin', 'superadmin'), updateAdmin);
// router.delete("/:id", verifyToken, allowRoles('admin', 'superadmin'), deleteAdmin);
export default router;