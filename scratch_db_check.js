const db = require('./db');

db.query("SELECT COUNT(*) as count FROM roster_sections", (err, res1) => {
  if (err) {
    console.error("Error checking roster_sections:", err.message);
  } else {
    console.log("roster_sections count:", res1[0].count);
  }

  db.query("SELECT COUNT(*) as count FROM roster_members", (err2, res2) => {
    if (err2) {
      console.error("Error checking roster_members:", err2.message);
    } else {
      console.log("roster_members count:", res2[0].count);
    }
    process.exit(0);
  });
});

