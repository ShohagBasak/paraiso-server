const db = require('./db');

console.log("Checking roster_sections table details...");

db.query("DESCRIBE roster_sections", (err, cols) => {
  if (err) {
    console.error("Error describing table:", err);
    process.exit(1);
  }
  console.log("Columns in roster_sections:");
  console.table(cols);

  db.query("SELECT * FROM roster_sections", (err2, rows) => {
    if (err2) {
      console.error("Error selecting rows:", err2);
      process.exit(1);
    }
    console.log("Rows in roster_sections:");
    console.table(rows);
    process.exit(0);
  });
});
