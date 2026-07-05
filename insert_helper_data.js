const db = require('./db');

const sqls = [
  "TRUNCATE TABLE helper_roster_sections",
  "TRUNCATE TABLE helper_roster_members",
  
  // Sections
  `INSERT INTO \`helper_roster_sections\` (\`name\`, \`sort_order\`, \`color\`, \`icon\`) VALUES
  ('Helper Management', 1, '#34d399', '👑'),
  ('Head Helper', 2, '#22c55e', '⭐'),
  ('Senior Helper', 3, '#a855f7', '🛡️'),
  ('Junior Helper', 4, '#f59e0b', '🌱')`,
  
  // Members
  `INSERT INTO \`helper_roster_members\` (\`section\`, \`section_order\`, \`title\`, \`name\`, \`country\`, \`sort_order\`, \`color\`, \`description\`) VALUES
  ('Helper Management', 1, 'Director of Helper Management', 'Sakura', 'ph', 1, '#34d399', ''),
  ('Helper Management', 1, 'Assistant Director of Helper Management', 'Andres', 'ph', 2, '#34d399', ''),
  
  ('Head Helper', 2, 'Head Helper', 'Zeus Salvaje', 'ph', 1, '#22c55e', ''),
  ('Head Helper', 2, 'Head Helper', 'Macaulay Coogan', 'us', 2, '#22c55e', ''),
  
  ('Senior Helper', 3, 'Senior Helper', 'Asher Hopkins', 'ph', 1, '#a855f7', ''),
  ('Senior Helper', 3, 'Senior Helper', 'Mike Flame', 'in', 2, '#a855f7', ''),
  ('Senior Helper', 3, 'Senior Helper', 'Mike Adriano', 'in', 3, '#a855f7', ''),
  ('Senior Helper', 3, 'Senior Helper', 'Ezio Drakos', 'cn', 4, '#a855f7', ''),
  ('Senior Helper', 3, 'Senior Helper', 'Lace Hancox', 'ph', 5, '#a855f7', ''),
  ('Senior Helper', 3, 'Senior Helper', 'Tik T. Talwar', 'ph', 6, '#a855f7', ''),
  
  ('Junior Helper', 4, 'Junior Helper', 'Cardo Dalisay', 'ph', 1, '#f59e0b', ''),
  ('Junior Helper', 4, 'Junior Helper', 'Seth Law Infirma', 'ph', 2, '#f59e0b', ''),
  ('Junior Helper', 4, 'Junior Helper', 'Kyoko Voiz Yugen', 'ph', 3, '#f59e0b', '')`
];

async function run() {
  for (const sql of sqls) {
    try {
      await new Promise((resolve, reject) => {
        db.query(sql, (err, res) => {
          if (err) reject(err);
          else resolve(res);
        });
      });
      console.log("Executed successfully:", sql.substring(0, 50) + "...");
    } catch (err) {
      console.error("Error executing query:", err);
      process.exit(1);
    }
  }
  console.log("Helper Roster seeded successfully!");
  process.exit(0);
}

run();
