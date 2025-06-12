// controllers/marksheetController.js
import connectToDb from '../config/db.js';

export const getStudentMarksheet = async (req, res) => {
  const { studentid } = req.params;

  try {
    const pool = await connectToDb();
    const result = await pool.request().query(`
      SELECT 
        e.studentid,
        e.name_1 AS Subject,
        e.mark AS MarksObtained,
        e.maxmarks AS MaxMarks,
        (CAST(e.mark AS FLOAT) / NULLIF(CAST(e.maxmarks AS FLOAT), 0)) * 100 AS Percentage,
        CASE 
          WHEN (CAST(e.mark AS FLOAT) / NULLIF(CAST(e.maxmarks AS FLOAT), 0)) * 100 >= 90 THEN 'A+'
          WHEN (CAST(e.mark AS FLOAT) / NULLIF(CAST(e.maxmarks AS FLOAT), 0)) * 100 >= 75 THEN 'A'
          WHEN (CAST(e.mark AS FLOAT) / NULLIF(CAST(e.maxmarks AS FLOAT), 0)) * 100 >= 60 THEN 'B'
          WHEN (CAST(e.mark AS FLOAT) / NULLIF(CAST(e.maxmarks AS FLOAT), 0)) * 100 >= 45 THEN 'C'
          ELSE 'D'
        END AS Grade,
        e.name_2 AS Term,
        e.FAType
      FROM [dbo].[Exam_Bulk_Report] e
      WHERE e.studentid = '${studentid}'
    `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: `No report data found for student ID: ${studentid}` });
    }

    res.json(result.recordset);
  } catch (err) {
    console.error('❌ Marksheet fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch marksheet' });
  }
};
