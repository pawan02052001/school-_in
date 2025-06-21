import express from 'express';
import sql from 'mssql';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import connectToDb from '../config/db.js'; // dynamic connection helper

dotenv.config();
const router = express.Router();

// 🔐 LOGIN API
router.post('/login', async (req, res) => {
  const { UserName, Password } = req.body;
  const dbName = req.headers.school;

  if (!UserName || !Password) {
    return res.status(400).json({ error: 'Student ID and Password are required.' });
  }

  if (!dbName) {
    return res.status(400).json({ error: 'School header (database) is missing.' });
  }

  try {
    const pool = await connectToDb(dbName);
    const result = await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .query(`SELECT * FROM oxfordpsn.[User] WHERE UserName = @UserName AND IsActive = 1 AND IsDeleted = 0`);

    if (result.recordset.length === 0) {
      return res.status(401).json({ error: 'User not found or inactive.' });
    }

    const user = result.recordset[0];
    const isMatch = await bcrypt.compare(Password, user.Password);

    if (!isMatch) {
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    const token = jwt.sign(
      { userId: user.UserName, role: user.Role.toLowerCase() },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        UserName: user.UserName,
        Name: user.Name,
        Email: user.Email,
        Role: user.Role.toLowerCase(),
      },
    });

  } catch (err) {
    console.error("Login Error:", err.message);
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});


// ✅ NEW: GET ALL USERS
router.get('/users', async (req, res) => {
  const dbName = req.headers.school;

  if (!dbName) {
    return res.status(400).json({ error: 'Missing school header.' });
  }

  try {
    const pool = await connectToDb(dbName);
    const result = await pool.request()
      .query(`SELECT UserName, Name, Email, Role FROM oxfordpsn.[User] WHERE IsActive = 1 AND IsDeleted = 0`);
    
    res.json({ data: result.recordset });

  } catch (err) {
    console.error("Fetch Users Error:", err.message);
    res.status(500).json({ error: 'Server error while fetching users.' });
  }
});

export default router;
