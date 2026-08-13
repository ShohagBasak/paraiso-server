const mysql = require('mysql2');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'paraiso_dev',
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 15,
  queueLimit: 0,
  connectTimeout: 10000
});

pool.on('error', (err) => {
  console.error('Main MySQL Pool Error:', err.message);
});

pool.getConnection((err, conn) => {
  if (err) {
    console.error('Error connecting to the database pool: ' + err.message);
    return;
  }
  console.log('MySQL Pool Initialized! ID: ' + conn.threadId);
  conn.release();
});

process.once('SIGUSR2', () => {
  pool.end(() => {
    process.kill(process.pid, 'SIGUSR2');
  });
});

module.exports = pool;
