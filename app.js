import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import winston from 'winston';
import jwt from 'jsonwebtoken';
import authRoutes from './routes/auth.js';
import studentRoutes from './routes/student.js';
import dbMetaRoutes from './routes/dbMeta.js';
import connectToDb from './config/db.js';
import dataRoutes from './routes/dataRoutes.js';
import schoolsRoute from './routes/schools.js';


dotenv.config(); // Load environment variables

// Setup logger using winston
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console(),
  ],
});

const app = express();
const port = process.env.PORT || 3000;

// Trust proxy for Railway (single proxy)
app.set('trust proxy', 1);

// 🔐 Rate Limiting Middleware (Security)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 requests for sensitive endpoints
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' },
});

// Apply rate limiting to /api routes, but skip /health
app.use('/api', (req, res, next) => {
  if (req.path === '/health') return next(); // Skip rate limiting for health check
  if (req.path === '/auth/forgot-password') return sensitiveLimiter(req, res, next); // Stricter limit for forgot-password
  return generalLimiter(req, res, next);
});

// 🌐 Global Middleware
app.use(cors({
  origin: [
    'http://localhost:8081', // Local development
    'https://your-frontend-url', // Replace with your production frontend URL
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// Middleware to verify JWT token for protected routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    logger.error('Invalid token:', err.message);
    res.status(403).json({ error: 'Invalid token.' });
  }
};

// ✅ Health Check for Railway or Monitoring Tools
app.get('/health', async (req, res) => {
  try {
    const pool = await connectToDb();
    await pool.request().query('SELECT 1'); // Test DB connection
    res.status(200).json({ message: 'Server and database are healthy' }); 
  } catch (err) {
    logger.error('Health check failed:', err.message);
    res.status(503).json({ error: 'Database connection failed' });
  }
});

// 🚀 API Routes
app.use('/api/auth', authRoutes);
app.use('/api', studentRoutes);
app.use('/api/dbmeta', dbMetaRoutes);
// app.use('/api', apiRoutes); // Mount StudentMarksheetList.js routes
app.use('/api/schools', schoolsRoute); 

app.use('/api', dataRoutes);

// 🛡️ Secure Table Data API (whitelist + authentication)
app.get('/api/data/:schema/:tableName', authenticateToken, async (req, res) => {
  const { schema, tableName } = req.params;
  const allowedSchemas = ['dbo', 'oxfordpsn'];
  const allowedTables = ['schools', 'Exam_Bulk_Report', 'User', 'students'];

  // Validate schema and table name
  if (!allowedSchemas.includes(schema) || !allowedTables.includes(tableName)) {
    logger.warn(`Invalid schema or table access attempt: ${schema}.${tableName}`);
    return res.status(400).json({ error: 'Invalid schema or table name' });
  }

  try {
    const pool = await connectToDb();
    const query = `SELECT * FROM [${schema}].[${tableName}]`;
    const result = await pool.request().query(query);
    logger.info(`Data fetched successfully: ${schema}.${tableName}`);
    res.json(result.recordset);
  } catch (err) {
    logger.error(`Fetch Error (${schema}.${tableName}):`, err.message);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});

// 🛑 Global Error Handler
app.use((err, req, res, next) => {
  logger.error('Unhandled Error:', { message: err.message, stack: err.stack });
  // In production, don't expose error details to users
  res.status(500).json({ error: 'Something went wrong' });
});

// Retry logic for database connection
const connectWithRetry = async (retries = 5, delay = 5000) => {
  for (let i = 0; i < retries; i++) {
    try {
      const pool = await connectToDb();
      logger.info('Database connected successfully');
      return pool;
    } catch (err) {
      logger.error(`DB Connection Attempt ${i + 1} Failed:`, err.message);
      if (i === retries - 1) throw err; // If last retry fails, throw error
      logger.info(`Retrying in ${delay / 1000} seconds...`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
};

// ✅ Start server with DB connection retry
(async () => {
  try {
    await connectWithRetry();
    app.listen(port, '0.0.0.0', () => {
      logger.info(`🚀 Server running at http://localhost:${port}`);
    });
  } catch (err) {
    logger.error('Failed to start server:', err.message);
    process.exit(1);
  }
})();

// 💣 Crash protection
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', { message: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection:', { promise, reason });
  process.exit(1);
});