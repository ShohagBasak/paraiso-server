const express = require('express');
const db = require('./db');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL
].filter(Boolean).map(url => url.replace(/\/$/, ''));

app.use(cors({ 
  origin: allowedOrigins, 
  credentials: true 
}));

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
  const { username, email, password } = req.body;
  const allowedDomain = "@gmail.com";
  if (!email.endsWith(allowedDomain)) {
    return res.status(403).json({ message: "Only Gmail addresses are allowed!" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const sql = "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)";
  db.query(sql, [username, email, hashedPassword], (err, result) => {
    if (err) return res.status(500).json({ message: "Registration failed. Email may already exist." });
    const token = jwt.sign({ id: result.insertId, email, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, cookieOptions);
    res.status(201).json({ user: { id: result.insertId, username, email, role: 'user' } });
  });
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


// ─── GET / ────────────────────────────────────────────────
app.get('/', (req, res) => res.send('Server is running and working perfectly!'));

app.listen(5000, () => console.log("Server is running on port 5000"));
