// routes/reportCard.js
import express from 'express';
import { verifyToken } from '../middleware/verifyToken.js';
const router = express.Router();

router.get('/:studentId', verifyToken, async (req, res) => {
  const studentId = req.params.studentId;
  const school = req.headers['school'];

  if (!school) {
    return res.status(400).json({ error: 'Missing school header.' });
  }

  try {
    const pool = await connectToDb(school);
    const result = await pool.request()
      .input('studentid', sql.VarChar, studentId)
      .query(`SELECT * FROM dbo.Exam_Bulk_Report WHERE studentid = @studentid`);

    res.json(result.recordset);
  } catch (err) {
    console.error("Report Card Fetch Error:", err.message);
    res.status(500).json({ error: 'Server error.' });
  }
});
