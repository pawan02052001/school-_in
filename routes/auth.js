// routes/auth.js
import express from 'express';
import sql from 'mssql';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware to get school DB name from headers
const getSchoolDb = (req) => {
  const schoolDb = req.headers.school;
  if (!schoolDb) throw new Error('School header missing');
  return schoolDb;
};

// SIGNUP
router.post('/signup', async (req, res) => {
  const { UserName, Password, Email, Name, Role } = req.body;
  if (!UserName || !Password || !Email || !Name || !Role)
    return res.status(400).json({ error: 'All fields are required.' });

  try {
    const schoolDb = getSchoolDb(req);
    const pool = await connectToDb(schoolDb);

    const checkUser = await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .query(`SELECT * FROM oxfordpsn.[User] WHERE UserName = @UserName`);

    if (checkUser.recordset.length > 0)
      return res.status(409).json({ error: 'User already exists.' });

    const hashedPassword = await bcrypt.hash(Password, 10);

    await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .input('Password', sql.NVarChar, hashedPassword)
      .input('Email', sql.NVarChar, Email)
      .input('Name', sql.VarChar, Name)
      .input('Role', sql.VarChar, Role)
      .input('IsActive', sql.Bit, 1)
      .input('IsDeleted', sql.Bit, 0)
      .query(`
        INSERT INTO oxfordpsn.[User] 
        (UserName, Password, Email, Name, Role, IsActive, IsDeleted, CreatedAt)
        VALUES (@UserName, @Password, @Email, @Name, @Role, @IsActive, @IsDeleted, GETDATE())
      `);

    const token = jwt.sign(
      { userId: UserName, role: Role.toLowerCase() },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      message: 'Signup successful.',
      token,
      user: { UserName, Name, Email, Role: Role.toLowerCase() },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  const { UserName, Password } = req.body;
  if (!UserName || !Password)
    return res.status(400).json({ error: 'Student ID and password are required.' });

  try {
    const schoolDb = getSchoolDb(req);
    const pool = await connectToDb(schoolDb);

    const userResult = await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .query(`SELECT * FROM oxfordpsn.[User] WHERE UserName = @UserName AND IsActive = 1 AND IsDeleted = 0`);

    if (userResult.recordset.length === 0)
      return res.status(401).json({ error: 'User not found or inactive.' });

    const user = userResult.recordset[0];
    const passwordMatch = await bcrypt.compare(Password, user.Password);

    if (!passwordMatch)
      return res.status(401).json({ error: 'Incorrect password.' });

    const token = jwt.sign(
      { userId: user.UserName, role: user.Role.toLowerCase() },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Login successful.',
      token,
      user: {
        UserName: user.UserName,
        Name: user.Name,
        Email: user.Email,
        Role: user.Role.toLowerCase(),
      },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
