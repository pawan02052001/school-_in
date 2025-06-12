import express from 'express';
import sql from 'mssql';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import connectToDb from '../config/db.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Nodemailer setup for sending emails
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// SIGNUP (Auto-login after signup)
router.post('/signup', async (req, res) => {
  const { UserName, Password, Email, Name, Role } = req.body;

  if (!UserName || !Password || !Email || !Name || !Role) {
    console.log('Signup failed: Missing required fields', { UserName, Email, Name, Role });
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const pool = await connectToDb();
    console.log('Connected to database for signup');

    // Check if user already exists
    const checkUser = await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .query(`SELECT * FROM oxfordpsn.[User] WHERE UserName = @UserName`);

    if (checkUser.recordset.length > 0) {
      console.log('Signup failed: User already exists:', UserName);
      return res.status(409).json({ error: 'User already exists.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(Password, 10);

    // Insert new user into database
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

    // Generate JWT token for auto-login
    const token = jwt.sign(
      { userId: UserName, role: Role.toLowerCase() },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    console.log('Signup successful for:', UserName);
    res.status(201).json({
      message: 'Signup successful.',
      token,
      user: {
        UserName,
        Name,
        Email,
        Role: Role.toLowerCase(),
      },
    });
  } catch (err) {
    console.error('Signup error:', err.message, err.stack);
    res.status(500).json({ error: 'Signup process failed.', details: err.message });
  }
});

// FORGOT PASSWORD
router.post('/forgot-password', async (req, res) => {
  const { UserName } = req.body;

  if (!UserName) {
    console.log('Forgot Password failed: Missing UserName');
    return res.status(400).json({ error: 'Student ID is required.' });
  }

  try {
    const pool = await connectToDb();
    console.log('Connected to database for forgot password');

    const userResult = await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .query(`SELECT * FROM oxfordpsn.[User] WHERE UserName = @UserName AND IsActive = 1 AND IsDeleted = 0`);

    if (userResult.recordset.length === 0) {
      console.log('Forgot Password failed: User not found or inactive:', UserName);
      return res.status(404).json({ error: 'User not found or inactive.' });
    }

    const user = userResult.recordset[0];
    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(Date.now() + 3600000);

    await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .input('resetToken', sql.NVarChar, resetToken)
      .input('resetTokenExpiry', sql.DateTime, resetTokenExpiry)
      .query(`
        UPDATE oxfordpsn.[User]
        SET resetToken = @resetToken, resetTokenExpiry = @resetTokenExpiry
        WHERE UserName = @UserName
      `);

    const resetLink = `${process.env.FRONTEND_URL || 'http://your-frontend-url'}/reset-password?token=${resetToken}&username=${UserName}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.Email,
      subject: 'Password Reset Request',
      html: `
        <h3>Password Reset</h3>
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${resetLink}">Reset Password</a>
        <p>This link is valid for 1 hour.</p>
        <p>If you did not request this, please ignore this email.</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log('Password reset email sent to:', user.Email);
    res.status(200).json({ message: 'Password reset link sent to your registered email.' });
  } catch (err) {
    console.error('Forgot Password error:', err.message, err.stack);
    res.status(500).json({ error: 'Failed to process password reset.', details: err.message });
  }
});

// RESET PASSWORD
router.post('/reset-password', async (req, res) => {
  const { UserName, resetToken, newPassword } = req.body;

  if (!UserName || !resetToken || !newPassword) {
    console.log('Reset Password failed: Missing UserName, resetToken, or newPassword');
    return res.status(400).json({ error: 'Student ID, reset token, and new password are required.' });
  }

  try {
    const pool = await connectToDb();
    console.log('Connected to database for password reset');

    const userResult = await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .input('resetToken', sql.NVarChar, resetToken)
      .query(`
        SELECT * FROM oxfordpsn.[User] 
        WHERE UserName = @UserName 
        AND resetToken = @resetToken 
        AND resetTokenExpiry > GETDATE() 
        AND IsActive = 1 
        AND IsDeleted = 0
      `);

    if (userResult.recordset.length === 0) {
      console.log('Reset Password failed: Invalid or expired token for:', UserName);
      return res.status(400).json({ error: 'Invalid or expired reset token.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .input('Password', sql.NVarChar, hashedPassword)
      .input('resetToken', sql.NVarChar, null)
      .input('resetTokenExpiry', sql.DateTime, null)
      .query(`
        UPDATE oxfordpsn.[User] 
        SET Password = @Password, 
            resetToken = @resetToken, 
            resetTokenExpiry = @resetTokenExpiry
        WHERE UserName = @UserName
      `);

    console.log('Password reset successful for:', UserName);
    res.status(200).json({ message: 'Password reset successful.' });
  } catch (err) {
    console.error('Reset Password error:', err.message, err.stack);
    res.status(500).json({ error: 'Failed to reset password.', details: err.message });
  }
});

// LOGIN
router.post('/login', async (req, res) => {
  const { UserName, Password } = req.body;

  if (!UserName || !Password) {
    console.log('Login failed: Missing UserName or Password', { UserName });
    return res.status(400).json({ error: 'Student ID and password are required.' });
  }

  try {
    const pool = await connectToDb();
    console.log('Connected to database for login');

    const userResult = await pool.request()
      .input('UserName', sql.VarChar, UserName)
      .query(`SELECT * FROM oxfordpsn.[User] WHERE UserName = @UserName AND IsActive = 1 AND IsDeleted = 0`);

    if (userResult.recordset.length === 0) {
      console.log('Login failed: User not found or inactive:', UserName);
      return res.status(401).json({ error: 'User not found or inactive.' });
    }

    const user = userResult.recordset[0];
    console.log('Login attempt for:', UserName);

    if (!user.Password) {
      console.log('Login failed: No valid password found for:', UserName);
      return res.status(500).json({ error: 'No valid password found for user.' });
    }

    const passwordMatch = await bcrypt.compare(Password, user.Password);
    if (!passwordMatch) {
      console.log('Login failed: Password mismatch for:', UserName);
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    const token = jwt.sign(
      { userId: user.UserName, role: user.Role.toLowerCase() },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    console.log('Login successful, user:', {
      UserName: user.UserName,
      Role: user.Role,
    });

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
    console.error('Login error:', err.message, err.stack);
    res.status(500).json({ error: 'Login process failed.', details: err.message });
  }
});

// GET ALL USERS
router.get('/users', authenticateToken, async (req, res) => {
  console.log('GET /api/auth/users called, user:', req.user);
  try {
    const pool = await connectToDb();
    console.log('Database connected for users route');

    const result = await pool.request().query(`
      SELECT UserName, Name, Role 
      FROM oxfordpsn.[User] 
      WHERE IsActive = 1 AND IsDeleted = 0
    `);
    console.log('Users fetched:', result.recordset.length);
    res.status(200).json(result.recordset);
  } catch (err) {
    console.error('Error fetching users:', err.message, err.stack);
    res.status(500).json({ error: 'Failed to fetch users.', details: err.message });
  }
});

export default router;