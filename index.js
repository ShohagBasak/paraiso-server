const express = require('express');
const db = require('./db');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "https://pgaming.net");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const isProduction = process.env.NODE_ENV === 'production' || (process.env.FRONTEND_URL && !process.env.FRONTEND_URL.includes('localhost'));
const cookieOptions = {
  httpOnly: true,
  secure: isProduction,
  sameSite: isProduction ? 'none' : 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000
};

app.use(express.json());
app.use(cookieParser());

// ─── verifyToken Middleware ────────────────────────────────
function verifyToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// ─── verifyAdmin Middleware ────────────────────────────────
function verifyAdmin(req, res, next) {
  verifyToken(req, res, () => {
    if (req.user?.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  });
}

// ─── GET /me ──────────────────────────────────────────────
app.get('/me', verifyToken, (req, res) => {
  const sql = "SELECT id, username, email, role FROM users WHERE id = ?";
  db.query(sql, [req.user.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'User not found' });
    res.json({ user: results[0] });
  });
});

// ─── POST /register ───────────────────────────────────────
app.post('/register', async (req, res) => {
  try {
    console.log("========== REGISTER HIT ==========");
    console.log("Body:", req.body);

    const { username, email, password } = req.body;

    const allowedDomain = "@gmail.com";

    if (!email.endsWith(allowedDomain)) {
      console.log("Invalid email domain");
      return res.status(403).json({
        message: "Only Gmail addresses are allowed!"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO users (username, email, password_hash)
      VALUES (?, ?, ?)
    `;

    db.query(sql, [username, email, hashedPassword], (err, result) => {

      if (err) {
        console.error("DATABASE ERROR:");
        console.error(err);

        return res.status(500).json({
          message: err.message
        });
      }

      const token = jwt.sign(
        {
          id: result.insertId,
          email,
          role: "user"
        },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      res.cookie("token", token, cookieOptions);

      console.log("User registered successfully:", email);

      res.status(201).json({
        user: {
          id: result.insertId,
          username,
          email,
          role: "user"
        }
      });
    });

  } catch (err) {
    console.error("REGISTER CRASH:");
    console.error(err);

    res.status(500).json({
      message: err.message
    });
  }
});

// ─── POST /login ──────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ message: "User not found" });
    const match = await bcrypt.compare(password, results[0].password_hash);
    if (!match) return res.status(401).json({ message: "Invalid password" });
    const { id, username, role } = results[0];
    const token = jwt.sign({ id, email, role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, cookieOptions);
    res.json({ user: { id, username, email, role } });
  });
});

// ─── POST /reset-password ─────────────────────────────────
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) return res.status(400).json({ message: 'Email and new password are required' });
  db.query("SELECT id FROM users WHERE email = ?", [email], async (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'No account found with this email' });
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.query("UPDATE users SET password_hash = ? WHERE email = ?", [hashedPassword, email], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to update password' });
      res.json({ message: 'Password updated successfully' });
    });
  });
});

// ─── POST /logout ─────────────────────────────────────────
app.post('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite
  });
  res.json({ message: 'Logged out successfully' });
});

// ════════════════════════════════════════════════════════════
// BANNER ENDPOINTS
// ════════════════════════════════════════════════════════════

app.get('/banners', (req, res) => {
  db.query("SELECT * FROM banner_slides ORDER BY sort_order ASC, id DESC", (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch banners' });
    res.json(results);
  });
});

// PUT /banners/reorder — update sort order (admin only)
app.put('/banners/reorder', verifyAdmin, (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders)) return res.status(400).json({ message: 'Invalid data' });

  if (orders.length === 0) return res.json({ message: 'Order updated' });

  let completed = 0;
  let hasError = false;

  orders.forEach((item) => {
    db.query("UPDATE banner_slides SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Failed to update order' });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Banners reordered successfully' });
      }
    });
  });
});

app.post('/banners', verifyAdmin, (req, res) => {
  const { title, subtitle, image_url, title_color, subtitle_color, title_size, subtitle_size } = req.body;
  
  // Find current maximum sort order to append new slide to the bottom
  db.query("SELECT MAX(sort_order) as maxOrder FROM banner_slides", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;
    
    db.query(
      "INSERT INTO banner_slides (title, subtitle, image_url, title_color, subtitle_color, title_size, subtitle_size, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        title || '', 
        subtitle || '', 
        image_url || '', 
        title_color || '#ffffff', 
        subtitle_color || '#cbd5e1', 
        title_size || 'text-3xl sm:text-5xl md:text-6xl', 
        subtitle_size || 'text-base sm:text-xl md:text-2xl',
        nextOrder
      ],
      (err, result) => {
        if (err) return res.status(500).json({ message: 'Failed to add banner: ' + err.message });
        res.status(201).json({ id: result.insertId, title, subtitle, image_url, title_color, subtitle_color, title_size, subtitle_size, sort_order: nextOrder });
      }
    );
  });
});

app.delete('/banners/:id', verifyAdmin, (req, res) => {
  db.query("DELETE FROM banner_slides WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete banner' });
    res.json({ message: 'Banner deleted' });
  });
});

// PUT /banners/:id — edit banner
app.put('/banners/:id', verifyAdmin, (req, res) => {
  const { title, subtitle, image_url, title_color, subtitle_color, title_size, subtitle_size } = req.body;
  db.query(
    "UPDATE banner_slides SET title = ?, subtitle = ?, image_url = ?, title_color = ?, subtitle_color = ?, title_size = ?, subtitle_size = ? WHERE id = ?",
    [
      title || '', 
      subtitle || '', 
      image_url || '', 
      title_color || '#ffffff', 
      subtitle_color || '#cbd5e1', 
      title_size || 'text-5xl', 
      subtitle_size || 'text-xl', 
      req.params.id
    ],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to update banner: ' + err.message });
      if (result.affectedRows === 0) return res.status(404).json({ message: 'Banner not found' });
      res.json({ 
        message: 'Banner updated successfully', 
        banner: { id: req.params.id, title, subtitle, image_url, title_color, subtitle_color, title_size, subtitle_size } 
      });
    }
  );
});


// ════════════════════════════════════════════════════════════
// USER MANAGEMENT ENDPOINTS
// ════════════════════════════════════════════════════════════

// GET /users — all users (admin only)
app.get('/users', verifyAdmin, (req, res) => {
  db.query("SELECT id, username, email, role FROM users ORDER BY id DESC", (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error: ' + err.message });
    }
    res.json(results);
  });
});

// PUT /users/:id/role — assign role (admin only)
app.put('/users/:id/role', verifyAdmin, (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ message: 'Invalid role. Must be "user" or "admin"' });
  }
  db.query("UPDATE users SET role = ? WHERE id = ?", [role, req.params.id], (err, result) => {
    if (err) return res.status(500).json({ message: 'Failed to update role' });
    if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
    res.json({ message: `Role updated to ${role}` });
  });
});

// ════════════════════════════════════════════════════════════
// ANNOUNCEMENT ENDPOINTS
// ════════════════════════════════════════════════════════════

app.get('/announcements', (req, res) => {
  db.query("SELECT * FROM announcements ORDER BY sort_order ASC, id DESC", (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch announcements' });
    res.json(results);
  });
});

// PUT /announcements/reorder — update announcement order (admin only)
app.put('/announcements/reorder', verifyAdmin, (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders)) return res.status(400).json({ message: 'Invalid data' });

  if (orders.length === 0) return res.json({ message: 'Order updated' });

  let completed = 0;
  let hasError = false;

  orders.forEach((item) => {
    db.query("UPDATE announcements SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Failed to update order' });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Announcements reordered successfully' });
      }
    });
  });
});

app.post('/announcements', verifyAdmin, (req, res) => {
  const { title, description, image_url, link, title_color, description_color, title_size, description_size } = req.body;
  if (!title) return res.status(400).json({ message: 'Title is required' });

  db.query("SELECT MAX(sort_order) as maxOrder FROM announcements", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;

    db.query(
      "INSERT INTO announcements (title, description, image_url, link, sort_order, title_color, description_color, title_size, description_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        title, 
        description || '', 
        image_url || '', 
        link || '', 
        nextOrder,
        title_color || '#ffffff',
        description_color || '#cbd5e1',
        title_size || 'text-xl md:text-2xl',
        description_size || 'text-sm'
      ],
      (err, result) => {
        if (err) return res.status(500).json({ message: 'Failed to add announcement: ' + err.message });
        res.status(201).json({ id: result.insertId, title, description, image_url, link, sort_order: nextOrder, title_color, description_color, title_size, description_size });
      }
    );
  });
});

app.delete('/announcements/:id', verifyAdmin, (req, res) => {
  db.query("DELETE FROM announcements WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete announcement' });
    res.json({ message: 'Announcement deleted' });
  });
});

// PUT /announcements/:id — edit announcement
app.put('/announcements/:id', verifyAdmin, (req, res) => {
  const { title, description, image_url, link, title_color, description_color, title_size, description_size } = req.body;
  if (!title) return res.status(400).json({ message: 'Title is required' });
  db.query(
    "UPDATE announcements SET title = ?, description = ?, image_url = ?, link = ?, title_color = ?, description_color = ?, title_size = ?, description_size = ? WHERE id = ?",
    [
      title, 
      description || '', 
      image_url || '', 
      link || '', 
      title_color || '#ffffff',
      description_color || '#cbd5e1',
      title_size || 'text-xl md:text-2xl',
      description_size || 'text-sm',
      req.params.id
    ],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to update announcement: ' + err.message });
      if (result.affectedRows === 0) return res.status(404).json({ message: 'Announcement not found' });
      res.json({ 
        message: 'Announcement updated successfully', 
        announcement: { id: req.params.id, title, description, image_url, link, title_color, description_color, title_size, description_size } 
      });
    }
  );
});


// ════════════════════════════════════════════════════════════
// STAFF ROSTER ENDPOINTS
// ════════════════════════════════════════════════════════════

// GET /staff — fetch all staff ordered by sort_order
app.get('/staff', (req, res) => {
  db.query("SELECT * FROM staff ORDER BY sort_order ASC, id ASC", (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch staff roster' });
    res.json(results);
  });
});

// POST /staff — add a new staff member (admin only)
app.post('/staff', verifyAdmin, (req, res) => {
  const { name, category, role, country, image_url } = req.body;
  if (!name || !category) return res.status(400).json({ message: 'Name and Category are required' });

  db.query("SELECT MAX(sort_order) as maxOrder FROM staff", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;

    db.query(
      "INSERT INTO staff (name, role, category, country, image_url, sort_order) VALUES (?, ?, ?, ?, ?, ?)",
      [name, role || '', category, country || '', image_url || '', nextOrder],
      (err, result) => {
        if (err) return res.status(500).json({ message: 'Failed to add staff member: ' + err.message });
        res.status(201).json({ id: result.insertId, name, category, role, country, image_url, sort_order: nextOrder });
      }
    );
  });
});

// DELETE /staff/:id — delete staff member (admin only)
app.delete('/staff/:id', verifyAdmin, (req, res) => {
  db.query("DELETE FROM staff WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete staff member' });
    res.json({ message: 'Staff member deleted' });
  });
});

// PUT /staff/:id — edit staff member (admin only)
app.put('/staff/:id', verifyAdmin, (req, res) => {
  const { name, category, role, country, image_url } = req.body;
  if (!name || !category) return res.status(400).json({ message: 'Name and Category are required' });

  db.query(
    "UPDATE staff SET name = ?, category = ?, role = ?, country = ?, image_url = ? WHERE id = ?",
    [name, category, role || '', country || '', image_url || '', req.params.id],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to update staff member: ' + err.message });
      if (result.affectedRows === 0) return res.status(404).json({ message: 'Staff member not found' });
      res.json({ message: 'Staff member updated successfully', staff: { id: req.params.id, name, category, role, country, image_url } });
    }
  );
});

// PUT /staff/reorder — bulk-update sorting sequence (admin only)
app.put('/staff/reorder', verifyAdmin, (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders)) return res.status(400).json({ message: 'Invalid data' });

  if (orders.length === 0) return res.json({ message: 'Order updated' });

  let completed = 0;
  let hasError = false;

  orders.forEach((item) => {
    db.query("UPDATE staff SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Failed to update staff order' });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Staff roster reordered successfully' });
      }
    });
  });
});


// ════════════════════════════════════════════════════════════
// STAFF ROLES / DEPARTMENTS ENDPOINTS
// ════════════════════════════════════════════════════════════

// GET /staff-roles — fetch all roles or seed default roles list
app.get('/staff-roles', (req, res) => {
  db.query("SELECT * FROM staff_roles ORDER BY sort_order ASC, id ASC", (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch staff roles: ' + err.message });
    
    if (results.length === 0) {
      const defaultRoles = [
        ['Management', '#ff2d2d', 'FaUserTie', 0],
        ['Assistant Management', '#ff2d2d', 'FaUserCog', 1],
        ['Head Admin', '#9B59B6', 'FaShieldAlt', 2],
        ['Senior Admin', '#F39C12', 'FaUserShield', 3],
        ['General Admin', '#F1C40F', 'FaUserShield', 4],
        ['Junior Admin', '#7ED321', 'FaUserShield', 5],
        ['Developers', '#1ABC9C', 'FaCode', 6]
      ];
      
      let completed = 0;
      let seedErr = false;
      defaultRoles.forEach((role) => {
        db.query("INSERT INTO staff_roles (name, color, icon_name, sort_order) VALUES (?, ?, ?, ?)", role, (e) => {
          if (e) seedErr = true;
          completed++;
          if (completed === defaultRoles.length) {
            if (seedErr) return res.status(500).json({ message: 'Failed to seed default staff roles' });
            db.query("SELECT * FROM staff_roles ORDER BY sort_order ASC, id ASC", (err2, seededResults) => {
              res.json(seededResults);
            });
          }
        });
      });
    } else {
      res.json(results);
    }
  });
});

// POST /staff-roles — create a new department/role (admin only)
app.post('/staff-roles', verifyAdmin, (req, res) => {
  const { name, color, icon_name } = req.body;
  if (!name) return res.status(400).json({ message: 'Role Name is required' });

  db.query("SELECT MAX(sort_order) as maxOrder FROM staff_roles", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;

    db.query(
      "INSERT INTO staff_roles (name, color, icon_name, sort_order) VALUES (?, ?, ?, ?)",
      [name, color || '#ffffff', icon_name || 'FaUserShield', nextOrder],
      (err, result) => {
        if (err) return res.status(500).json({ message: 'Failed to add role: ' + err.message });
        res.status(201).json({ id: result.insertId, name, color, icon_name, sort_order: nextOrder });
      }
    );
  });
});

// DELETE /staff-roles/:id — remove a department/role (admin only)
app.delete('/staff-roles/:id', verifyAdmin, (req, res) => {
  db.query("SELECT name FROM staff_roles WHERE id = ?", [req.params.id], (err, oldResult) => {
    if (err || oldResult.length === 0) return res.status(404).json({ message: 'Role not found' });
    const roleName = oldResult[0].name;

    db.query("DELETE FROM staff_roles WHERE id = ?", [req.params.id], (err) => {
      if (err) return res.status(500).json({ message: 'Failed to delete role' });
      
      // Update staff members in this category to be unassigned
      db.query("UPDATE staff SET category = '' WHERE category = ?", [roleName]);
      res.json({ message: 'Role deleted and staff unassigned' });
    });
  });
});

// PUT /staff-roles/:id — edit department name/color/icon (admin only)
app.put('/staff-roles/:id', verifyAdmin, (req, res) => {
  const { name, color, icon_name } = req.body;
  if (!name) return res.status(400).json({ message: 'Role Name is required' });

  db.query("SELECT name FROM staff_roles WHERE id = ?", [req.params.id], (err, oldResult) => {
    if (err || oldResult.length === 0) return res.status(404).json({ message: 'Role not found' });
    const oldName = oldResult[0].name;

    db.query(
      "UPDATE staff_roles SET name = ?, color = ?, icon_name = ? WHERE id = ?",
      [name, color || '#ffffff', icon_name || 'FaUserShield', req.params.id],
      (err, result) => {
        if (err) return res.status(500).json({ message: 'Failed to update role: ' + err.message });
        
        // Cascading update staff category name if name changed
        if (oldName !== name) {
          db.query("UPDATE staff SET category = ? WHERE category = ?", [name, oldName]);
        }
        
        res.json({ message: 'Role updated successfully', role: { id: req.params.id, name, color, icon_name } });
      }
    );
  });
});

// PUT /staff-roles/reorder — bulk update sorting of categories (admin only)
app.put('/staff-roles/reorder', verifyAdmin, (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders)) return res.status(400).json({ message: 'Invalid data' });

  let completed = 0;
  let hasError = false;

  if (orders.length === 0) return res.json({ message: 'Order updated' });

  orders.forEach((item) => {
    db.query("UPDATE staff_roles SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Failed to update role order' });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Role ordering updated successfully' });
      }
    });
  });
});


// ─── GOVERNMENT ROSTER ────────────────────────────────────

// Auto-add color column to roster_members table if missing
db.query("SHOW COLUMNS FROM roster_members LIKE 'color'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE roster_members ADD COLUMN color VARCHAR(50) DEFAULT NULL", (err2) => {
      if (err2) console.error("Error adding color column to roster_members:", err2);
      else console.log("Added color column to roster_members table.");
    });
  }
});

// GET /roster — public, returns all members grouped by section
app.get('/roster', (req, res) => {
  const sql = `
    SELECT m.*, s.color AS section_color, s.icon AS section_icon 
    FROM roster_members m 
    LEFT JOIN roster_sections s ON m.section = s.name 
    ORDER BY m.section_order ASC, m.sort_order ASC
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error', error: err });
    res.json(results);
  });
});

// POST /roster — admin only, add new member
app.post('/roster', verifyAdmin, (req, res) => {
  const { section, title, name, description, section_order, sort_order, color } = req.body;
  if (!section || !title) return res.status(400).json({ message: 'section and title are required' });
  const sql = "INSERT INTO roster_members (section, title, name, description, section_order, sort_order, color) VALUES (?, ?, ?, ?, ?, ?, ?)";
  db.query(sql, [section, title, name || 'Vacant', description || '', section_order || 0, sort_order || 0, color || null], (err, result) => {
    if (err) return res.status(500).json({ message: 'Failed to add roster member', error: err });
    res.json({ message: 'Member added', id: result.insertId });
  });
});

// PUT /roster/:id — admin only, update a member
app.put('/roster/:id', verifyAdmin, (req, res) => {
  const { section, title, name, description, section_order, sort_order, color } = req.body;
  const sql = "UPDATE roster_members SET section=?, title=?, name=?, description=?, section_order=?, sort_order=?, color=? WHERE id=?";
  db.query(sql, [section, title, name || 'Vacant', description || '', section_order || 0, sort_order || 0, color || null, req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to update member', error: err });
    res.json({ message: 'Member updated' });
  });
});

// DELETE /roster/:id — admin only
app.delete('/roster/:id', verifyAdmin, (req, res) => {
  db.query("DELETE FROM roster_members WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete member', error: err });
    res.json({ message: 'Member deleted' });
  });
});

// PUT /roster/reorder — admin only, bulk update sort_order
app.put('/roster/reorder', verifyAdmin, (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders) || orders.length === 0)
    return res.json({ message: 'Nothing to reorder' });

  let completed = 0;
  let hasError = false;
  orders.forEach(item => {
    db.query("UPDATE roster_members SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Reorder failed', error: err });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Roster order updated' });
      }
    });
  });
});


// GET /roster/sections — public (with auto-migration/seeding if empty)
app.get('/roster/sections', (req, res) => {
  const createTableSql = `
    CREATE TABLE IF NOT EXISTS roster_sections (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(100) NOT NULL UNIQUE,
      sort_order INT DEFAULT 0,
      color VARCHAR(50) DEFAULT NULL,
      icon VARCHAR(50) DEFAULT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `;
  
  db.query(createTableSql, (tableErr) => {
    if (tableErr) return res.status(500).json({ message: 'Failed to ensure roster_sections table', error: tableErr });

    // Double check color column exists (for upgrade compatibility)
    db.query("SHOW COLUMNS FROM roster_sections LIKE 'color'", (errCol, cols) => {
      if (!errCol && (!cols || cols.length === 0)) {
        db.query("ALTER TABLE roster_sections ADD COLUMN color VARCHAR(50) DEFAULT NULL");
      }
    });

    // Double check icon column exists
    db.query("SHOW COLUMNS FROM roster_sections LIKE 'icon'", (errIcon, cols) => {
      if (!errIcon && (!cols || cols.length === 0)) {
        db.query("ALTER TABLE roster_sections ADD COLUMN icon VARCHAR(50) DEFAULT NULL");
      }
    });

    db.query("SELECT * FROM roster_sections ORDER BY sort_order ASC", (err, results) => {
      if (err) return res.status(500).json({ message: 'DB error', error: err });
      
      if (results && results.length > 0) {
        return res.json(results);
      }

      // Table is empty, auto-migrate sections from existing roster_members or seed default preset groups
      db.query("SELECT DISTINCT section FROM roster_members WHERE section IS NOT NULL AND section != ''", (err2, memberSecs) => {
        if (err2) return res.status(500).json({ message: 'Failed to fetch members', error: err2 });

        let uniqueNames = memberSecs.map(r => r.section);
        if (uniqueNames.length === 0) {
          // Seed default preset groups if database is fully empty
          uniqueNames = ['FEDERAL GOVERNMENT', 'LAW ENFORCEMENT & EMERGENCY SERVICES', 'AGENCIES'];
        }

        let completed = 0;
        uniqueNames.forEach((name, idx) => {
          let defaultColor = null;
          let defaultIcon = null;
          if (name === 'FEDERAL GOVERNMENT') { defaultColor = '#ef4444'; defaultIcon = '🏛️'; }
          else if (name === 'LAW ENFORCEMENT & EMERGENCY SERVICES') { defaultColor = '#3b82f6'; defaultIcon = '🛡️'; }
          else if (name === 'AGENCIES') { defaultColor = '#a855f7'; defaultIcon = '📡'; }

          db.query("INSERT IGNORE INTO roster_sections (name, sort_order, color, icon) VALUES (?, ?, ?, ?)", [name, idx + 1, defaultColor, defaultIcon], (err3) => {
            completed++;
            if (completed === uniqueNames.length) {
              // Retrieve newly inserted sections and return
              db.query("SELECT * FROM roster_sections ORDER BY sort_order ASC", (err4, finalResults) => {
                if (err4) return res.status(500).json({ message: 'DB error', error: err4 });
                res.json(finalResults);
              });
            }
          });
        });
      });
    });
  });
});

// POST /roster/sections — admin only
app.post('/roster/sections', verifyAdmin, (req, res) => {
  const { name, sort_order, color, icon } = req.body;
  if (!name) return res.status(400).json({ message: 'Section name is required' });
  const sql = "INSERT INTO roster_sections (name, sort_order, color, icon) VALUES (?, ?, ?, ?)";
  db.query(sql, [name, sort_order || 0, color || null, icon || null], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ message: 'Section name already exists' });
      }
      return res.status(500).json({ message: 'Failed to create section', error: err });
    }
    res.json({ message: 'Section created', id: result.insertId });
  });
});

// PUT /roster/sections/:id — admin only
app.put('/roster/sections/:id', verifyAdmin, (req, res) => {
  const { name, sort_order, color, icon } = req.body;
  if (!name) return res.status(400).json({ message: 'Section name is required' });

  db.query("SELECT name FROM roster_sections WHERE id = ?", [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'Section not found' });
    const oldName = results[0].name;

    db.query("UPDATE roster_sections SET name = ?, sort_order = ?, color = ?, icon = ? WHERE id = ?", [name, sort_order || 0, color || null, icon || null, req.params.id], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to update section', error: err2 });

      // Cascade name & order updates to existing members
      db.query("UPDATE roster_members SET section = ?, section_order = ? WHERE section = ?", [name, sort_order || 0, oldName], (err3) => {
        res.json({ message: 'Section updated successfully' });
      });
    });
  });
});

// DELETE /roster/sections/:id — admin only
app.delete('/roster/sections/:id', verifyAdmin, (req, res) => {
  db.query("SELECT name FROM roster_sections WHERE id = ?", [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'Section not found' });
    const sectionName = results[0].name;

    db.query("DELETE FROM roster_sections WHERE id = ?", [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to delete section', error: err2 });

      // Delete all roster members assigned to this section
      db.query("DELETE FROM roster_members WHERE section = ?", [sectionName], (err3) => {
        res.json({ message: 'Section and its members deleted' });
      });
    });
  });
});

// PUT /roster/sections/reorder — admin only
app.put('/roster/sections/reorder', verifyAdmin, (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders) || orders.length === 0)
    return res.json({ message: 'Nothing to reorder' });

  let completed = 0;
  let hasError = false;
  orders.forEach(item => {
    db.query("UPDATE roster_sections SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Reorder failed', error: err });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        // Also update section_order on members of those sections
        db.query("SELECT id, name, sort_order FROM roster_sections", (err2, sections) => {
          if (!err2) {
            sections.forEach(sec => {
              db.query("UPDATE roster_members SET section_order = ? WHERE section = ?", [sec.sort_order, sec.name]);
            });
          }
        });
        res.json({ message: 'Sections reorder completed' });
      }
    });
  });
});


// ════════════ GOVT CHAIN OF COMMAND API ════════════

const defaultChainOfCommandData = `The Government of Paraiso
Structure • Leadership • Accountability


Introduction

The Government of Paraiso serves as the executive authority responsible for maintaining structure, organization, and oversight across the community.

Instead of having one person manage every department, responsibilities are divided between executive offices and specialized management teams.


Executive Leadership

President
The highest-ranking official within the Government of Paraiso. The President sets the overall vision of the community and has final authority over major decisions, appointments, and policies.

Vice President
The second-highest executive official. The Vice President assists the President with government operations and acts on behalf of the President when necessary.


Executive Departments

Secretary of Defense
Oversees all law enforcement and emergency service departments.

Reports Under Secretary of Defense:

Admin Personnel
• Helper Management

Faction Management
• Paraiso Police Department
• Federal Bureau of Investigation
• Paraiso Fire & Medical Department
• National Guard
• San Andreas News


Admin Personnel assists the Secretary of Defense in keeping Government employees on the right track. This includes professionalism, honor & loyalty. Aswel as issuing any punishments if any Government employees break the rules and or laws. Faction Management assists faction leaders, monitors activity, reviews department performance, and reports directly to the Secretary of Defense.


Secretary of State
Oversees all civilian and criminal organizations operating throughout Paraiso.

Reports Under Secretary of State:

Gang Management
• All Official Criminal Organizations

Civilian Management
• Paraiso News
• Taxi Services
• Future Civilian Organizations

Gang Management works with gang leaders, their applications, and reports directly to the Secretary of State.


Governor of Economic & Development
Oversees the economic development of Paraiso, including businesses, commercial enterprises, and economic affairs.

Reports Under Governor:

Business Management
• Business Applications
• Ownership Transfers
• Commercial Disputes
• Business Owner Support

Business Management handles the daily business process while the Governor oversees the overall economy and commercial growth of Paraiso.


Governor of City Relations
Oversees the City relations of Paraiso, including complaints, appeals, and city helper organisations.

Reports Under Governor:

Community Management
• Ban Appeals
• Warning Appeals
• Complaints

Helper Management
• Helper Applications
• Helper Complaints

Community Management handles the daily community issues and appeals. Helper Management handles the daily tasks and management of all Helper employees, while the Governor oversees the overall relations between the Government & Citizens.


Why This System Exists

This government system is built around delegation and accountability.

Each executive position oversees a specific area of the server:

Secretary of Defense
→ Government factions and emergency services.

Secretary of State
→ Gangs, civilian factions, and community organizations.

Governor
→ Businesses, economy, and commercial affairs.

This allows every faction, gang, civilian organization, and business to receive proper leadership without one person having to manage everything directly.



Brian Gutierrez

President of the United States of Paraiso

Office of the President`;

// GET /roster/chain-of-command — public
app.get('/roster/chain-of-command', (req, res) => {
  const createTableSql = `
    CREATE TABLE IF NOT EXISTS page_contents (
      page_key VARCHAR(100) PRIMARY KEY,
      content LONGTEXT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
  `;
  db.query(createTableSql, (err) => {
    if (err) return res.status(500).json({ message: 'Failed to ensure page_contents table', error: err });

    db.query("SELECT content FROM page_contents WHERE page_key = 'govt-chain-of-command'", (err2, results) => {
      if (err2) return res.status(500).json({ message: 'DB error', error: err2 });

      if (results && results.length > 0) {
        return res.json({ content: results[0].content });
      }

      // Seed default content
      db.query("INSERT INTO page_contents (page_key, content) VALUES ('govt-chain-of-command', ?)", [defaultChainOfCommandData], (err3) => {
        if (err3) return res.status(500).json({ message: 'Failed to seed default content', error: err3 });
        res.json({ content: defaultChainOfCommandData });
      });
    });
  });
});

// PUT /roster/chain-of-command — admin only
app.put('/roster/chain-of-command', verifyAdmin, (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ message: 'Content is required' });

  const sql = `
    INSERT INTO page_contents (page_key, content) 
    VALUES ('govt-chain-of-command', ?) 
    ON DUPLICATE KEY UPDATE content = ?
  `;
  db.query(sql, [content, content], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to save chain of command data', error: err });
    res.json({ message: 'Chain of command updated successfully' });
  });
});


// ─── GET / ────────────────────────────────────────────────
app.get('/', (req, res) => res.send('Server is running and working perfectly!'));

app.listen(5000, () => console.log("Server is running on port 5000"));
