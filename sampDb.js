const mysql = require('mysql2');
require('dotenv').config();

const sampPool = mysql.createPool({
  host: process.env.SAMP_DB_HOST || '127.0.0.1',
  port: process.env.SAMP_DB_PORT || 3306,
  user: process.env.SAMP_DB_USER || 'root',
  password: process.env.SAMP_DB_PASSWORD || '',
  database: process.env.SAMP_DB_NAME || 'paraiso_dev',
  waitForConnections: true,
  connectionLimit: 15,
  queueLimit: 0,
  connectTimeout: 10000,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
});

sampPool.on('error', (err) => {
  console.error('⚠️ SA-MP MySQL Pool Error:', err.message);
});

sampPool.getConnection((err, conn) => {
  if (err) {
    console.error('Error connecting to SA-MP MySQL Pool: ' + err.message);
    return;
  }
  console.log('✅ SA-MP MySQL Pool Initialized! Connection Thread ID: ' + conn.threadId);
  conn.release();
});

// Graceful shutdown on nodemon restart (SIGUSR2)
process.once('SIGUSR2', () => {
  sampPool.end(() => {
    process.kill(process.pid, 'SIGUSR2');
  });
});

module.exports = sampPool;
