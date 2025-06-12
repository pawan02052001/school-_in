// db.js
import sql from 'mssql';
import dotenv from 'dotenv';
dotenv.config();

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: {
    encrypt: false,
    trustServerCertificate: true,
  },
};

// DEBUG: Log config to check if env variables are loaded properly
console.log('✅ Database config loaded:', {
  user: config.user,
  password: config.password ? '********' : undefined,
  server: config.server,
  database: config.database,
});

let poolPromise = null;

const connectToDb = async () => {
  if (poolPromise) return poolPromise;
  try {
    poolPromise = await sql.connect(config);
    console.log('✅ Connected to SQL Server');
    return poolPromise;
  } catch (err) {
    console.error('❌ Database connection failed:', err);
    throw err;
  }
};

export default connectToDb;
