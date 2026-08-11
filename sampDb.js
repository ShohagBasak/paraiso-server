const mysql = require('mysql2');
require('dotenv').config();

const sampPool = mysql.createPool({
  host: process.env.SAMP_DB_HOST || 'samp.pgaming.net',
  port: process.env.SAMP_DB_PORT || 3306,
  user: process.env.SAMP_DB_USER || 'ucp_dev',
  password: process.env.SAMP_DB_PASSWORD || '8Fpwftp8A(mbvE2x',
  database: process.env.SAMP_DB_NAME || 'paraiso_dev',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

sampPool.getConnection((err, conn) => {
  if (err) {
    console.error('❌ Error connecting to SA-MP MySQL Pool: ' + err.stack);
    return;
  }
  console.log('✅ SA-MP MySQL Pool Initialized! Connection Thread ID: ' + conn.threadId);
  conn.release();
});

module.exports = sampPool;
