import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import winston from 'winston';
import jwt from 'jsonwebtoken';
import authRoutes from './routes/auth.js';
import dbMetaRoutes from './routes/dbMeta.js';
import connectToDb from './config/db.js';
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

app.set('trust proxy', 1); // Trust proxy for Railway

// 🔐 Rate Limiting Middleware
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

const sensitiveLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' },
});

// Apply rate limiting to /api routes
app.use('/api', (req, res, next) => {
  if (req.path === '/health') return next();
  if (req.path === '/auth/forgot-password') return sensitiveLimiter(req, res, next);
  return generalLimiter(req, res, next);
});

// 🌐 CORS + JSON
app.use(cors({
  origin: [
    'http://localhost:8081',
    'https://your-frontend-url', // ✅ Replace with your deployed frontend domain
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'school'], // ✅ ADDED: 'school' custom header
}));
app.use(express.json());

// ✅ 🏠 Default route for Railway (Fix for Not Found)
app.get('/', (req, res) => {
  res.send('🚀 Server is up and running!');
});

// ✅ Health Check
app.get('/health', async (req, res) => {
  try {
    const pool = await connectToDb();
    await pool.request().query('SELECT 1');
    res.status(200).json({ message: 'Server and database are healthy' });
  } catch (err) {
    logger.error('Health check failed:', err.message);
    res.status(503).json({ error: 'Database connection failed' });
  }
});

// 🔐 JWT Token Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

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

// 🚀 API Routes
app.use('/api/auth', authRoutes);
app.use('/api/dbmeta', dbMetaRoutes);
app.use('/api/schools', schoolsRoute);

// 🛡️ Secure Table Data API
app.get('/api/data/:schema/:tableName', authenticateToken, async (req, res) => {
  const { schema, tableName } = req.params;
  const allowedSchemas = ['dbo', 'oxfordpsn'];
  const allowedTables = ['schools', 'Exam_Bulk_Report', 'User', 'students'];

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

// 🔥 Global Error Handler
app.use((err, req, res, next) => {
  logger.error('Unhandled Error:', { message: err.message, stack: err.stack });
  res.status(500).json({ error: 'Something went wrong' });
});

// 🔄 DB Retry Logic
const connectWithRetry = async (retries = 5, delay = 5000) => {
  for (let i = 0; i < retries; i++) {
    try {
      const pool = await connectToDb();
      logger.info('Database connected successfully');
      return pool;
    } catch (err) {
      logger.error(`DB Connection Attempt ${i + 1} Failed:`, err.message);
      if (i === retries - 1) throw err;
      logger.info(`Retrying in ${delay / 1000} seconds...`);
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }
};

// 🚀 Start Server
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
