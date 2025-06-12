import jwt from 'jsonwebtoken';

export const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  console.log('AuthenticateToken - Authorization Header:', authHeader);
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('AuthenticateToken - Error: Token required');
    return res.status(401).json({ error: 'Token required' });
  }

  try {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET not found in environment');
    }

    const decoded = jwt.verify(token, secret);
    console.log('AuthenticateToken - Decoded Token:', decoded);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('AuthenticateToken - Error:', err.message);
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};
