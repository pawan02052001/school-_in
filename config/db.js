// config/db.js
import sql from 'mssql';
import dotenv from 'dotenv';
dotenv.config();

const baseConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  options: {
    encrypt: false,
    trustServerCertificate: true,
  },
};

const connectionCache = {};

const connectToDb = async (dbName) => {
  if (connectionCache[dbName]) return connectionCache[dbName];

  try {
    const config = {
      ...baseConfig,
      database: dbName,
    };

    const pool = await sql.connect(config);
    console.log(` Connected to DB: ${dbName}`);
    connectionCache[dbName] = pool;
    return pool;
  } catch (err) {
    console.error(` Failed to connect DB (${dbName}):`, err);
    throw err;
  }
};

export default connectToDb;
  