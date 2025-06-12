// routes/dataRoutes.js
import express from 'express';
import { getStudentMarksheet } from '../controllers/marksheetController.js';

const router = express.Router();

// Add this route for marksheet
router.get('/marksheet/:studentid', getStudentMarksheet);

export default router;
