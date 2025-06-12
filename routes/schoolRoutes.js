import express from 'express';
import { authenticateToken } from '../middleware/auth.js';
import {
  getAllSchools,
  getSchoolById,
  createSchool,
  updateSchool,
  deleteSchool,
} from '../controllers/schoolController.js';

const router = express.Router();

router.get('/', authenticateToken, getAllSchools);
router.get('/:id', authenticateToken, getSchoolById);
router.post('/', authenticateToken, createSchool);
router.put('/:id', authenticateToken, updateSchool);
router.delete('/:id', authenticateToken, deleteSchool);

export default router;