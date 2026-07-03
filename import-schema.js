const fs = require('fs');
const mysql = require('mysql2');
require('dotenv').config();

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  multipleStatements: true
});

connection.connect((err) => {
  if (err) {
    console.error('Failed to connect to Aiven MySQL database:', err.message);
    process.exit(1);
  }
  console.log('Connected to Aiven MySQL database successfully!');
  
  const schemaSql = fs.readFileSync('schema.sql', 'utf8');
  connection.query(schemaSql, (err, results) => {
    if (err) {
      console.error('Error executing schema:', err.message);
    } else {
      console.log('✓ Database tables created successfully on Aiven!');
    }
    connection.end();
  });
});
