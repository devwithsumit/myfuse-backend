import { Router } from 'express';
import { verifyToken, requiredPermission } from '../middlewares/authMiddleware.js';
import { getAdmins, deleteAdmin, createAdmin, updateAdmin } from '../controllers/adminController.js';

const router = Router();

router.use(verifyToken);
router.use(requiredPermission('settings'));

router.get('/test', (req, res) => {
    res.status(200).json({ success: true, message: 'Admin route works!' });
});

router.get("/", getAdmins);
router.post("/", createAdmin);
router.put("/:id", updateAdmin);
router.delete("/:id", deleteAdmin);

export default router;