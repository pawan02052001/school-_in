// routes/schools.js

import express from 'express';
import connectToDb from '../config/db.js'; // DB connection config

const router = express.Router();

// ✅ GET: Fetch all schools
router.get('/list', async (req, res) => {
  try {
    const pool = await connectToDb(); // Connect to default/common DB
    const result = await pool.request().query(`SELECT * FROM Schools`);
    res.json(result.recordset); // Send JSON response
  } catch (err) {
    console.error('Error fetching schools:', err);
    res.status(500).json({ error: 'Failed to fetch schools' });
  }
});

export default router;
