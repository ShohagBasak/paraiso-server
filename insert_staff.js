const db = require('./db');

const sqls = [
  "TRUNCATE TABLE staff",
  `INSERT INTO \`staff\` (\`id\`, \`name\`, \`category\`, \`role\`, \`country\`, \`image_url\`, \`sort_order\`, \`created_at\`) VALUES
  (1, 'Brian', 'Management', 'Community Owner', 'us', 'https://i.ibb.co/PvqVdggQ/1.jpg', 0, '2026-07-01 15:54:23'),
  (2, 'Surreal ', 'Management', 'Community Manager', 'ph', 'https://i.ibb.co/vvgmzCLC/3.jpg', 1, '2026-07-01 15:59:52'),
  (4, 'Leamir', 'Assistant Management', 'Head Developer/Scripter', 'br', '', 2, '2026-07-03 14:16:43'),
  (6, 'Omarito', 'Head Admin', 'Director of Gang Management', 'eg', '', 3, '2026-07-03 14:23:54'),
  (7, 'Walty', 'Head Admin', 'Director of Admin Personnel', 'lb', 'https://i.ibb.co/KcJs6ZDT/41.jpg', 4, '2026-07-03 14:25:36'),
  (8, 'Sakura', 'Senior Admin', 'Director of Helper Management', 'ph', 'https://i.ibb.co/8k65mD8/16.png', 5, '2026-07-03 14:27:27'),
  (9, 'Andres', 'Senior Admin', 'Complaint Manager & Assistant Director of Helper Management ', 'ph', '', 6, '2026-07-03 14:29:09'),
  (10, 'Ivo', 'Senior Admin', 'Assistant Director of Gang Management', 'bg', 'https://i.ibb.co/PsgGbSCk/60.jpg', 7, '2026-07-03 14:31:55'),
  (12, 'Kloss', 'Senior Admin', 'Director of Faction Management', 'au', '', 8, '2026-07-03 14:35:21'),
  (13, 'Pharell', 'General Admin', '', 'ca', '', 9, '2026-07-03 14:35:56'),
  (14, 'Mofuman', 'General Admin', '', 'us', '', 10, '2026-07-03 14:36:25'),
  (15, 'Hataz', 'Junior Admin', '', 'ph', '', 11, '2026-07-03 14:37:06'),
  (16, 'Tyler', 'Junior Admin', '', 'ph', '', 12, '2026-07-03 14:37:28'),
  (17, 'Larz', 'Junior Admin', '', 'au', '', 13, '2026-07-03 14:38:01'),
  (19, 'itsneufox', 'Developers', 'Scripter', 'pt', '', 15, '2026-07-03 14:39:24'),
  (20, 'ToiletDuck', 'Developers', 'Scripter', 'ph', 'https://i.ibb.co/Mmx4xvL/toiletduck.png', 16, '2026-07-04 03:07:36'),
  (21, 'Leamir', 'Developers', 'Head Developer/Scripter', 'br', '', 14, '2026-07-04 03:08:14')`
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
  console.log("Database seeded successfully!");
  process.exit(0);
}

run();
