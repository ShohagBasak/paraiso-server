const express = require('express');
const db = require('./db');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
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

app.use(express.json({ limit: '10mb' })); // increase size limit for base64 uploads
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ─── Initialize Permissions Table & Auto-promote Master Admin ───
db.query(`
  CREATE TABLE IF NOT EXISTS admin_permissions (
    user_id INT NOT NULL,
    permission_key VARCHAR(100) NOT NULL,
    PRIMARY KEY (user_id, permission_key),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`, (err) => {
  if (err) console.error("Error creating admin_permissions table:", err);
  else {
    console.log("Verified admin_permissions table exists.");
    // Auto-promote: If there is no user with role 'master', promote the first admin or user with lowest ID
    db.query("SELECT 1 FROM users WHERE role = 'master'", (err2, masterResults) => {
      if (!err2 && (!masterResults || masterResults.length === 0)) {
        db.query("SELECT id FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1", (err3, adminResults) => {
          let targetUserId = null;
          if (!err3 && adminResults && adminResults.length > 0) {
            targetUserId = adminResults[0].id;
          } else {
            db.query("SELECT id FROM users ORDER BY id ASC LIMIT 1", (err4, userResults) => {
              if (!err4 && userResults && userResults.length > 0) {
                targetUserId = userResults[0].id;
                db.query("UPDATE users SET role = 'master' WHERE id = ?", [targetUserId], (err5) => {
                  if (!err5) console.log(`Auto-promoted user ID ${targetUserId} to 'master' role.`);
                });
              }
            });
          }
          if (targetUserId && !err3 && adminResults && adminResults.length > 0) {
            db.query("UPDATE users SET role = 'master' WHERE id = ?", [targetUserId], (err5) => {
              if (!err5) console.log(`Auto-promoted user ID ${targetUserId} to 'master' role.`);
            });
          }
        });
      }
    });
  }
});

// ─── verifyToken Middleware ────────────────────────────────
function verifyToken(req, res, next) {
  let token = req.cookies.token;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }
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
    if (req.user?.role !== 'admin' && req.user?.role !== 'master') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    next();
  });
}

// ─── verifyMaster Middleware ───────────────────────────────
function verifyMaster(req, res, next) {
  verifyToken(req, res, () => {
    if (req.user?.role !== 'master') {
      return res.status(403).json({ message: 'Master Admin access required' });
    }
    next();
  });
}

// ─── verifyPermission Middleware ───────────────────────────
function verifyPermission(permissionKey) {
  return (req, res, next) => {
    verifyToken(req, res, () => {
      if (req.user?.role === 'master') {
        return next();
      }
      if (req.user?.role === 'admin') {
        db.query(
          "SELECT 1 FROM admin_permissions WHERE user_id = ? AND permission_key = ?",
          [req.user.id, permissionKey],
          (err, results) => {
            if (!err && results && results.length > 0) {
              return next();
            }
            return res.status(403).json({ 
              message: `Access denied. You do not have permission to manage this section (${permissionKey}).` 
            });
          }
        );
      } else {
        return res.status(403).json({ message: 'Admin access required' });
      }
    });
  };
}

// ─── GET /me ──────────────────────────────────────────────
app.get('/me', verifyToken, (req, res) => {
  const sql = "SELECT id, username, email, role FROM users WHERE id = ?";
  db.query(sql, [req.user.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'User not found' });
    const user = results[0];
    
    db.query("SELECT permission_key FROM admin_permissions WHERE user_id = ?", [user.id], (err2, permResults) => {
      user.permissions = !err2 && permResults ? permResults.map(p => p.permission_key) : [];
      res.json({ user });
    });
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
          message: "Registration failed. Email may already exist."
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
        token,
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
    
    db.query("SELECT permission_key FROM admin_permissions WHERE user_id = ?", [id], (err2, permResults) => {
      const permissions = !err2 && permResults ? permResults.map(p => p.permission_key) : [];
      res.json({ 
        token,
        user: { id, username, email, role, permissions } 
      });
    });
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
// PUT /banners/reorder — update sort order (admin only with permission)
app.put('/banners/reorder', verifyPermission('banners'), (req, res) => {
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

app.post('/banners', verifyPermission('banners'), (req, res) => {
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

app.delete('/banners/:id', verifyPermission('banners'), (req, res) => {
  db.query("DELETE FROM banner_slides WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete banner' });
    res.json({ message: 'Banner deleted' });
  });
});

// PUT /banners/:id — edit banner
app.put('/banners/:id', verifyPermission('banners'), (req, res) => {
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

// GET /users — all users (master admin only)
app.get('/users', verifyMaster, (req, res) => {
  db.query("SELECT id, username, email, role FROM users ORDER BY id ASC", (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error: ' + err.message });
    }
    res.json(results);
  });
});

// PUT /users/:id/role — assign role (master admin only)
app.put('/users/:id/role', verifyMaster, (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin', 'master'].includes(role)) {
    return res.status(400).json({ message: 'Invalid role. Must be "user", "admin", or "master"' });
  }
  db.query("UPDATE users SET role = ? WHERE id = ?", [role, req.params.id], (err, result) => {
    if (err) return res.status(500).json({ message: 'Failed to update role' });
    if (result.affectedRows === 0) return res.status(404).json({ message: 'User not found' });
    
    // If upgraded to master, clear individual permissions table as master has all implicitly
    if (role === 'master' || role === 'user') {
      db.query("DELETE FROM admin_permissions WHERE user_id = ?", [req.params.id]);
    } else if (role === 'admin') {
      // Auto-assign all permissions by default for sub-admins
      const allPerms = ['banners', 'announcements', 'staff', 'roster', 'helper-roster', 'faqs'];
      db.query("DELETE FROM admin_permissions WHERE user_id = ?", [req.params.id], (errClear) => {
        if (!errClear) {
          const values = allPerms.map(p => [req.params.id, p]);
          db.query("INSERT INTO admin_permissions (user_id, permission_key) VALUES ?", [values]);
        }
      });
    }
    
    res.json({ message: `Role updated to ${role}` });
  });
});

// GET /users/:id/permissions — fetch permissions (master admin only)
app.get('/users/:id/permissions', verifyMaster, (req, res) => {
  db.query("SELECT permission_key FROM admin_permissions WHERE user_id = ?", [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch permissions' });
    res.json(results.map(r => r.permission_key));
  });
});

// PUT /users/:id/permissions — update permissions (master admin only)
app.put('/users/:id/permissions', verifyMaster, (req, res) => {
  const { permissions } = req.body;
  if (!Array.isArray(permissions)) {
    return res.status(400).json({ message: 'Permissions must be an array of keys.' });
  }
  
  db.query("DELETE FROM admin_permissions WHERE user_id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to clear old permissions' });
    
    if (permissions.length === 0) {
      return res.json({ message: 'Permissions updated successfully' });
    }
    
    const values = permissions.map(p => [req.params.id, p]);
    db.query("INSERT INTO admin_permissions (user_id, permission_key) VALUES ?", [values], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to save permissions' });
      res.json({ message: 'Permissions updated successfully' });
    });
  });
});

// DELETE /users/bulk — delete multiple users (master admin only)
app.delete('/users/bulk', verifyMaster, (req, res) => {
  const { userIds } = req.body;
  if (!Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).json({ message: 'User IDs are required' });
  }

  // Filter out the current admin's ID to prevent self-deletion
  const targetIds = userIds.map(id => parseInt(id)).filter(id => id !== parseInt(req.user.id));
  if (targetIds.length === 0) {
    return res.status(400).json({ message: 'No valid user accounts to delete.' });
  }

  db.query("DELETE FROM users WHERE id IN (?)", [targetIds], (err, result) => {
    if (err) {
      console.error("Bulk delete user error:", err);
      return res.status(500).json({ message: 'Failed to delete users' });
    }
    res.json({ message: `${result.affectedRows} users deleted successfully` });
  });
});

// DELETE /users/:id — delete user (master admin only)
app.delete('/users/:id', verifyMaster, (req, res) => {
  const targetId = req.params.id;

  // Prevent admins from deleting themselves
  if (parseInt(targetId) === parseInt(req.user.id)) {
    return res.status(400).json({ message: 'You cannot delete your own admin account.' });
  }

  db.query("DELETE FROM users WHERE id = ?", [targetId], (err, result) => {
    if (err) {
      console.error("Delete user error:", err);
      return res.status(500).json({ message: 'Failed to delete user' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
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

// PUT /announcements/reorder — update announcement order (admin only with permission)
app.put('/announcements/reorder', verifyPermission('announcements'), (req, res) => {
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

app.post('/announcements', verifyPermission('announcements'), (req, res) => {
  const { title, description, image_url, link, title_color, description_color, title_size, description_size, image_shape } = req.body;
  if (!title) return res.status(400).json({ message: 'Title is required' });
 
  db.query("SELECT MAX(sort_order) as maxOrder FROM announcements", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;
 
    db.query(
      "INSERT INTO announcements (title, description, image_url, link, sort_order, title_color, description_color, title_size, description_size, image_shape) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [
        title, 
        description || '', 
        image_url || '', 
        link || '', 
        nextOrder,
        title_color || '#ffffff',
        description_color || '#cbd5e1',
        title_size || 'text-xl md:text-2xl',
        description_size || 'text-sm',
        image_shape || 'rectangle'
      ],
      (errInsert, result) => {
        if (errInsert) return res.status(500).json({ message: 'Failed to add announcement: ' + errInsert.message });
        res.status(201).json({ id: result.insertId, title, description, image_url, link, sort_order: nextOrder, title_color, description_color, title_size, description_size, image_shape });
      }
    );
  });
});
 
app.delete('/announcements/:id', verifyPermission('announcements'), (req, res) => {
  db.query("DELETE FROM announcements WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete announcement' });
    res.json({ message: 'Announcement deleted' });
  });
});
 
// PUT /announcements/:id — edit announcement
app.put('/announcements/:id', verifyPermission('announcements'), (req, res) => {
  const { title, description, image_url, link, title_color, description_color, title_size, description_size, image_shape } = req.body;
  if (!title) return res.status(400).json({ message: 'Title is required' });
  db.query(
    "UPDATE announcements SET title = ?, description = ?, image_url = ?, link = ?, title_color = ?, description_color = ?, title_size = ?, description_size = ?, image_shape = ? WHERE id = ?",
    [
      title, 
      description || '', 
      image_url || '', 
      link || '', 
      title_color || '#ffffff',
      description_color || '#cbd5e1',
      title_size || 'text-xl md:text-2xl',
      description_size || 'text-sm',
      image_shape || 'rectangle',
      req.params.id
    ],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to update announcement: ' + err.message });
      if (result.affectedRows === 0) return res.status(404).json({ message: 'Announcement not found' });
      res.json({ 
        message: 'Announcement updated successfully', 
        announcement: { id: req.params.id, title, description, image_url, link, title_color, description_color, title_size, description_size, image_shape } 
      });
    }
  );
});


// ════════════════════════════════════════════════════════════
// STAFF ROSTER ENDPOINTS
// ════════════════════════════════════════════════════════════

// Auto-add color column to staff table if missing
db.query("SHOW COLUMNS FROM staff LIKE 'color'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE staff ADD COLUMN color VARCHAR(50) DEFAULT NULL", (err2) => {
      if (err2) console.error("Error adding color column to staff table:", err2);
      else console.log("Added color column to staff table.");
    });
  }
});

// Auto-add name_color column to staff table if missing
db.query("SHOW COLUMNS FROM staff LIKE 'name_color'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE staff ADD COLUMN name_color VARCHAR(50) DEFAULT NULL", (err2) => {
      if (err2) console.error("Error adding name_color column to staff table:", err2);
      else console.log("Added name_color column to staff table.");
    });
  }
});

// GET /staff — fetch all staff ordered by sort_order
app.get('/staff', (req, res) => {
  db.query("SELECT * FROM staff ORDER BY sort_order ASC, id ASC", (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch staff roster' });
    res.json(results);
  });
});

// POST /staff — add a new staff member (admin only)
// POST /staff — add a new staff member (admin only with permission)
app.post('/staff', verifyPermission('staff'), (req, res) => {
  const { name, category, role, country, image_url, color, name_color } = req.body;
  if (!name || !category) return res.status(400).json({ message: 'Name and Category are required' });

  db.query("SELECT MAX(sort_order) as maxOrder FROM staff", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;

    db.query(
      "INSERT INTO staff (name, role, category, country, image_url, sort_order, color, name_color) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [name, role || '', category, country || '', image_url || '', nextOrder, color || null, name_color || null],
      (err, result) => {
        if (err) return res.status(500).json({ message: 'Failed to add staff member: ' + err.message });
        res.status(201).json({ id: result.insertId, name, category, role, country, image_url, sort_order: nextOrder, color, name_color });
      }
    );
  });
});

// DELETE /staff/:id — delete staff member (admin only with permission)
app.delete('/staff/:id', verifyPermission('staff'), (req, res) => {
  db.query("DELETE FROM staff WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete staff member' });
    res.json({ message: 'Staff member deleted' });
  });
});

// PUT /staff/reorder — bulk-update sorting sequence (admin only with permission)
app.put('/staff/reorder', verifyPermission('staff'), (req, res) => {
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

// PUT /staff/:id — edit staff member (admin only with permission)
app.put('/staff/:id', verifyPermission('staff'), (req, res) => {
  const { name, category, role, country, image_url, color, name_color } = req.body;
  if (!name || !category) return res.status(400).json({ message: 'Name and Category are required' });

  db.query(
    "UPDATE staff SET name = ?, category = ?, role = ?, country = ?, image_url = ?, color = ?, name_color = ? WHERE id = ?",
    [name, category, role || '', country || '', image_url || '', color || null, name_color || null, req.params.id],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to update staff member: ' + err.message });
      if (result.affectedRows === 0) return res.status(404).json({ message: 'Staff member not found' });
      res.json({ message: 'Staff member updated successfully', staff: { id: req.params.id, name, category, role, country, image_url, color, name_color } });
    }
  );
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

// POST /staff-roles — create a new department/role (admin only with permission)
app.post('/staff-roles', verifyPermission('staff'), (req, res) => {
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

// DELETE /staff-roles/:id — remove a department/role (admin only with permission)
app.delete('/staff-roles/:id', verifyPermission('staff'), (req, res) => {
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

// PUT /staff-roles/reorder — bulk update sorting of categories (admin only with permission)
app.put('/staff-roles/reorder', verifyPermission('staff'), (req, res) => {
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

// PUT /staff-roles/:id — edit department name/color/icon (admin only with permission)
app.put('/staff-roles/:id', verifyPermission('staff'), (req, res) => {
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

// Auto-add name_color column to roster_members table if missing
db.query("SHOW COLUMNS FROM roster_members LIKE 'name_color'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE roster_members ADD COLUMN name_color VARCHAR(50) DEFAULT NULL", (err2) => {
      if (err2) console.error("Error adding name_color column to roster_members:", err2);
      else console.log("Added name_color column to roster_members table.");
    });
  }
});

// Auto-add section_order column to roster_members table if missing
db.query("SHOW COLUMNS FROM roster_members LIKE 'section_order'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE roster_members ADD COLUMN section_order INT DEFAULT 0", (err2) => {
      if (err2) console.error("Error adding section_order column to roster_members:", err2);
      else console.log("Added section_order column to roster_members table.");
    });
  }
});

// Auto-add sort_order column to roster_members table if missing
db.query("SHOW COLUMNS FROM roster_members LIKE 'sort_order'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE roster_members ADD COLUMN sort_order INT DEFAULT 0", (err2) => {
      if (err2) console.error("Error adding sort_order column to roster_members:", err2);
      else console.log("Added sort_order column to roster_members table.");
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

// POST /roster — admin only with permission, add new member
app.post('/roster', verifyPermission('roster'), (req, res) => {
  const { section, title, name, description, section_order, sort_order, color, name_color } = req.body;
  if (!section || !title) return res.status(400).json({ message: 'section and title are required' });
  const sql = "INSERT INTO roster_members (section, title, name, description, section_order, sort_order, color, name_color) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  db.query(sql, [section, title, name || 'Vacant', description || '', section_order || 0, sort_order || 0, color || null, name_color || null], (err, result) => {
    if (err) return res.status(500).json({ message: 'Failed to add roster member', error: err });
    res.json({ message: 'Member added', id: result.insertId });
  });
});

// PUT /roster/reorder — admin only with permission, bulk update sort_order
app.put('/roster/reorder', verifyPermission('roster'), (req, res) => {
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

// PUT /roster/:id — admin only with permission, update a member
app.put('/roster/:id', verifyPermission('roster'), (req, res) => {
  const { section, title, name, description, section_order, sort_order, color, name_color } = req.body;
  const sql = "UPDATE roster_members SET section=?, title=?, name=?, description=?, section_order=?, sort_order=?, color=?, name_color=? WHERE id=?";
  db.query(sql, [section, title, name || 'Vacant', description || '', section_order || 0, sort_order || 0, color || null, name_color || null, req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to update member', error: err });
    res.json({ message: 'Member updated' });
  });
});

// DELETE /roster/:id — admin only with permission
app.delete('/roster/:id', verifyPermission('roster'), (req, res) => {
  db.query("DELETE FROM roster_members WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete member', error: err });
    res.json({ message: 'Member deleted' });
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

    // Double check sort_order column exists
    db.query("SHOW COLUMNS FROM roster_sections LIKE 'sort_order'", (errSort, cols) => {
      if (!errSort && (!cols || cols.length === 0)) {
        db.query("ALTER TABLE roster_sections ADD COLUMN sort_order INT DEFAULT 0");
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

// POST /roster/sections — admin only with permission
app.post('/roster/sections', verifyPermission('roster'), (req, res) => {
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

// PUT /roster/sections/reorder — admin only with permission
app.put('/roster/sections/reorder', verifyPermission('roster'), (req, res) => {
  const { orders } = req.body;
  console.log("Roster sections reorder request received. Orders payload:", orders);
  
  if (!Array.isArray(orders) || orders.length === 0)
    return res.json({ message: 'Nothing to reorder' });

  let completed = 0;
  let hasError = false;
  
  orders.forEach(item => {
    db.query("UPDATE roster_sections SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err, results) => {
      if (err) {
        console.error(`Error updating roster_sections sort_order for ID ${item.id}:`, err);
        if (!hasError) {
          hasError = true;
          return res.status(500).json({ message: 'Reorder failed', error: err.message });
        }
      }
      
      if (!hasError) {
        completed++;
        if (completed === orders.length) {
          // Also update section_order on members of those sections
          db.query("SELECT id, name, sort_order FROM roster_sections", (err2, sections) => {
            if (err2) {
              console.error("Error fetching roster_sections for cascade:", err2);
            } else {
              sections.forEach(sec => {
                db.query("UPDATE roster_members SET section_order = ? WHERE section = ?", [sec.sort_order, sec.name], (err3) => {
                  if (err3) console.error(`Error updating section_order for member section '${sec.name}':`, err3);
                });
              });
            }
          });
          console.log("Roster sections reordered successfully");
          res.json({ message: 'Sections reorder completed' });
        }
      }
    });
  });
});

// PUT /roster/sections/:id — admin only with permission
app.put('/roster/sections/:id', verifyPermission('roster'), (req, res) => {
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

// DELETE /roster/sections/:id — admin only with permission
app.delete('/roster/sections/:id', verifyPermission('roster'), (req, res) => {
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

// PUT /roster/chain-of-command — admin only with permission
app.put('/roster/chain-of-command', verifyPermission('roster'), (req, res) => {
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


// ════════════ HELPER ROSTER API ════════════

// Auto-create helper_roster_members table
db.query(`
  CREATE TABLE IF NOT EXISTS helper_roster_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    section VARCHAR(100) NOT NULL,
    section_order INT DEFAULT 0,
    title VARCHAR(255) NOT NULL,
    name VARCHAR(255) DEFAULT 'Vacant',
    description TEXT,
    sort_order INT DEFAULT 0,
    color VARCHAR(50) DEFAULT NULL,
    country VARCHAR(10) DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => { if (err) console.error('Error creating helper_roster_members:', err); });

// Auto-add country column to helper_roster_members table if missing
db.query("SHOW COLUMNS FROM helper_roster_members LIKE 'country'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE helper_roster_members ADD COLUMN country VARCHAR(10) DEFAULT ''", (err2) => {
      if (err2) console.error("Error adding country column to helper_roster_members:", err2);
      else console.log("Added country column to helper_roster_members table.");
    });
  }
});

// Auto-add name_color column to helper_roster_members table if missing
db.query("SHOW COLUMNS FROM helper_roster_members LIKE 'name_color'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE helper_roster_members ADD COLUMN name_color VARCHAR(50) DEFAULT NULL", (err2) => {
      if (err2) console.error("Error adding name_color column to helper_roster_members:", err2);
      else console.log("Added name_color column to helper_roster_members table.");
    });
  }
});

// Auto-add image_shape column to announcements table if missing
db.query("SHOW COLUMNS FROM announcements LIKE 'image_shape'", (err, results) => {
  if (!err && (!results || results.length === 0)) {
    db.query("ALTER TABLE announcements ADD COLUMN image_shape VARCHAR(50) DEFAULT 'rectangle'", (err2) => {
      if (err2) console.error("Error adding image_shape column to announcements:", err2);
      else console.log("Added image_shape column to announcements table.");
    });
  }
});

// Auto-create helper_roster_sections table
db.query(`
  CREATE TABLE IF NOT EXISTS helper_roster_sections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    sort_order INT DEFAULT 0,
    color VARCHAR(50) DEFAULT NULL,
    icon VARCHAR(50) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => { if (err) console.error('Error creating helper_roster_sections:', err); });

// GET /helper-roster — public
app.get('/helper-roster', (req, res) => {
  const sql = `
    SELECT m.*, s.color AS section_color, s.icon AS section_icon
    FROM helper_roster_members m
    LEFT JOIN helper_roster_sections s ON m.section = s.name
    ORDER BY m.section_order ASC, m.sort_order ASC
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error', error: err });
    res.json(results);
  });
});

// POST /helper-roster — admin only with permission
app.post('/helper-roster', verifyPermission('helper-roster'), (req, res) => {
  const { section, title, name, description, section_order, sort_order, color, country, name_color } = req.body;
  if (!section || !title) return res.status(400).json({ message: 'section and title are required' });
  const sql = "INSERT INTO helper_roster_members (section, title, name, description, section_order, sort_order, color, country, name_color) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
  db.query(sql, [section, title, name || 'Vacant', description || '', section_order || 0, sort_order || 0, color || null, country || '', name_color || null], (err, result) => {
    if (err) return res.status(500).json({ message: 'Failed to add helper roster member', error: err });
    res.json({ message: 'Member added', id: result.insertId });
  });
});

// PUT /helper-roster/reorder — admin only with permission
app.put('/helper-roster/reorder', verifyPermission('helper-roster'), (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders) || orders.length === 0)
    return res.json({ message: 'Nothing to reorder' });

  let completed = 0;
  let hasError = false;
  orders.forEach(item => {
    db.query("UPDATE helper_roster_members SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Reorder failed', error: err });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Helper roster order updated' });
      }
    });
  });
});

// PUT /helper-roster/:id — admin only with permission
app.put('/helper-roster/:id', verifyPermission('helper-roster'), (req, res) => {
  const { section, title, name, description, section_order, sort_order, color, country, name_color } = req.body;
  const sql = "UPDATE helper_roster_members SET section=?, title=?, name=?, description=?, section_order=?, sort_order=?, color=?, country=?, name_color=? WHERE id=?";
  db.query(sql, [section, title, name || 'Vacant', description || '', section_order || 0, sort_order || 0, color || null, country || '', name_color || null, req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to update member', error: err });
    res.json({ message: 'Member updated' });
  });
});

// DELETE /helper-roster/:id — admin only with permission
app.delete('/helper-roster/:id', verifyPermission('helper-roster'), (req, res) => {
  db.query("DELETE FROM helper_roster_members WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete member', error: err });
    res.json({ message: 'Member deleted' });
  });
});

// GET /helper-roster/sections — public
app.get('/helper-roster/sections', (req, res) => {
  db.query("SELECT * FROM helper_roster_sections ORDER BY sort_order ASC", (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error', error: err });
    res.json(results || []);
  });
});

// POST /helper-roster/sections — admin only with permission
app.post('/helper-roster/sections', verifyPermission('helper-roster'), (req, res) => {
  const { name, sort_order, color, icon } = req.body;
  if (!name) return res.status(400).json({ message: 'Section name is required' });
  const sql = "INSERT INTO helper_roster_sections (name, sort_order, color, icon) VALUES (?, ?, ?, ?)";
  db.query(sql, [name, sort_order || 0, color || null, icon || null], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ message: 'Section name already exists' });
      return res.status(500).json({ message: 'Failed to create section', error: err });
    }
    res.json({ message: 'Section created', id: result.insertId });
  });
});

// PUT /helper-roster/sections/reorder — admin only with permission
app.put('/helper-roster/sections/reorder', verifyPermission('helper-roster'), (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders) || orders.length === 0)
    return res.json({ message: 'Nothing to reorder' });

  let completed = 0;
  let hasError = false;
  orders.forEach(item => {
    db.query("UPDATE helper_roster_sections SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Reorder failed', error: err.message });
      }
      if (!hasError) {
        completed++;
        if (completed === orders.length) {
          // Cascade section_order to members
          db.query("SELECT id, name, sort_order FROM helper_roster_sections", (err2, sections) => {
            if (!err2 && sections) {
              sections.forEach(sec => {
                db.query("UPDATE helper_roster_members SET section_order = ? WHERE section = ?", [sec.sort_order, sec.name]);
              });
            }
          });
          res.json({ message: 'Sections reorder completed' });
        }
      }
    });
  });
});

// PUT /helper-roster/sections/:id — admin only with permission
app.put('/helper-roster/sections/:id', verifyPermission('helper-roster'), (req, res) => {
  const { name, sort_order, color, icon } = req.body;
  if (!name) return res.status(400).json({ message: 'Section name is required' });

  db.query("SELECT name FROM helper_roster_sections WHERE id = ?", [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'Section not found' });
    const oldName = results[0].name;

    db.query("UPDATE helper_roster_sections SET name = ?, sort_order = ?, color = ?, icon = ? WHERE id = ?",
      [name, sort_order || 0, color || null, icon || null, req.params.id], (err2) => {
        if (err2) return res.status(500).json({ message: 'Failed to update section', error: err2 });
        // Cascade name + order updates to existing members
        db.query("UPDATE helper_roster_members SET section = ?, section_order = ? WHERE section = ?",
          [name, sort_order || 0, oldName], () => {
            res.json({ message: 'Section updated successfully' });
          });
      });
  });
});

// DELETE /helper-roster/sections/:id — admin only with permission
app.delete('/helper-roster/sections/:id', verifyPermission('helper-roster'), (req, res) => {
  db.query("SELECT name FROM helper_roster_sections WHERE id = ?", [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'Section not found' });
    const sectionName = results[0].name;
    db.query("DELETE FROM helper_roster_sections WHERE id = ?", [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to delete section', error: err2 });
      db.query("DELETE FROM helper_roster_members WHERE section = ?", [sectionName], () => {
        res.json({ message: 'Section and its members deleted' });
      });
    });
  });
});


// ════════════ FAQ API ════════════

// Auto-create faqs table if missing and seed defaults
db.query(`
  CREATE TABLE IF NOT EXISTS faqs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) {
    console.error('Error creating faqs table:', err);
  } else {
    db.query("SELECT COUNT(*) as count FROM faqs", (errCount, results) => {
      if (!errCount && results && results[0].count === 0) {
        const defaultFaqs = [
          [
            "When is Paraiso Gaming launching?",
            "Paraiso Gaming is expected to launch within the next 2–3 weeks. Our team is currently completing final testing and polishing every system to deliver the best possible experience at launch. Be sure to join our Discord and Forums to stay up to date with announcements, development updates, giveaways, and the official launch date.",
            0
          ],
          [
            "Can I transfer my stats if I come from Horizon Roleplay?",
            "Yes. We are honoring many Horizon Roleplay players. Eligible players may qualify for equivalent statistics, faction ranks, leadership positions, and exclusive rewards. Every transfer request is reviewed individually by our management team.",
            1
          ],
          [
            "How do I get started on Paraiso Gaming?",
            "Simply create your character and begin your journey. Whether you want to join law enforcement, emergency services, become a business owner, criminal, lawyer, journalist, or simply live as a civilian, Paraiso Gaming offers countless opportunities to create your own story.",
            2
          ],
          [
            "Is Paraiso Gaming beginner-friendly?",
            "Absolutely. Whether you’re new to SA-MP roleplay or a longtime veteran, our staff and community are here to help. We provide guides, tutorials, and active support to ensure every player has an enjoyable experience from day one.",
            3
          ],
          [
            "What makes Paraiso Gaming different?",
            "Paraiso Gaming is built around immersive roleplay, fair administration, balanced gameplay, and a player-first philosophy. Our goal is to create a long-lasting community where your decisions, achievements, and roleplay truly matter.",
            4
          ]
        ];

        let seeded = 0;
        defaultFaqs.forEach((faq) => {
          db.query("INSERT INTO faqs (question, answer, sort_order) VALUES (?, ?, ?)", faq, (errInsert) => {
            if (!errInsert) seeded++;
            if (seeded === defaultFaqs.length) {
              console.log("Successfully seeded default FAQs in DB.");
            }
          });
        });
      }
    });
  }
});

// GET /faqs — public
app.get('/faqs', (req, res) => {
  db.query("SELECT * FROM faqs ORDER BY sort_order ASC, id ASC", (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch FAQs' });
    res.json(results);
  });
});

// POST /faqs — admin only with permission
app.post('/faqs', verifyPermission('faqs'), (req, res) => {
  const { question, answer } = req.body;
  if (!question || !answer) return res.status(400).json({ message: 'Question and Answer are required' });

  db.query("SELECT MAX(sort_order) as maxOrder FROM faqs", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;

    db.query(
      "INSERT INTO faqs (question, answer, sort_order) VALUES (?, ?, ?)",
      [question, answer, nextOrder],
      (err, result) => {
        if (err) return res.status(500).json({ message: 'Failed to create FAQ: ' + err.message });
        res.status(201).json({ id: result.insertId, question, answer, sort_order: nextOrder });
      }
    );
  });
});

// PUT /faqs/reorder — admin only with permission
app.put('/faqs/reorder', verifyPermission('faqs'), (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders) || orders.length === 0)
    return res.json({ message: 'Nothing to reorder' });

  let completed = 0;
  let hasError = false;
  orders.forEach(item => {
    db.query("UPDATE faqs SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Reorder failed', error: err.message });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'FAQs reordered successfully' });
      }
    });
  });
});

// PUT /faqs/:id — admin only with permission
app.put('/faqs/:id', verifyPermission('faqs'), (req, res) => {
  const { question, answer } = req.body;
  if (!question || !answer) return res.status(400).json({ message: 'Question and Answer are required' });

  db.query("UPDATE faqs SET question = ?, answer = ? WHERE id = ?", [question, answer, req.params.id], (err, result) => {
    if (err) return res.status(500).json({ message: 'Failed to update FAQ: ' + err.message });
    res.json({ message: 'FAQ updated successfully' });
  });
});

// DELETE /faqs/:id — admin only with permission
app.delete('/faqs/:id', verifyPermission('faqs'), (req, res) => {
  db.query("DELETE FROM faqs WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete FAQ' });
    res.json({ message: 'FAQ deleted' });
  });
});


// ════════════ CHAIN OF COMMAND API ════════════

// Drop old chain_of_command table if it contains the obsolete 'category' column to migrate gracefully
db.query("SHOW COLUMNS FROM chain_of_command LIKE 'category'", (err, columns) => {
  if (!err && columns && columns.length > 0) {
    console.log("Migrating chain_of_command to new schema (dropping old table first)...");
    db.query("DROP TABLE IF EXISTS chain_of_command", (errDrop) => {
      if (errDrop) console.error("Failed to drop old table:", errDrop);
      initializeCoCTables();
    });
  } else {
    initializeCoCTables();
  }
});

function initializeCoCTables() {
  // 1. Create traditional tables first (for fallback/backwards-compatibility if any)
  db.query(`
    CREATE TABLE IF NOT EXISTS coc_categories (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255) NOT NULL UNIQUE,
      sort_order INT DEFAULT 0
    )
  `, (errCat) => {
    if (!errCat) {
      db.query(`
        CREATE TABLE IF NOT EXISTS chain_of_command (
          id INT AUTO_INCREMENT PRIMARY KEY,
          category_id INT NOT NULL,
          layout VARCHAR(50) DEFAULT 'detailed',
          title VARCHAR(255) NOT NULL,
          subtitle VARCHAR(255) DEFAULT NULL,
          description TEXT DEFAULT NULL,
          reports TEXT DEFAULT NULL,
          reports_title VARCHAR(255) DEFAULT NULL,
          footer TEXT DEFAULT NULL,
          color VARCHAR(50) DEFAULT '#22d3ee',
          sort_order INT DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (category_id) REFERENCES coc_categories(id) ON DELETE CASCADE
        )
      `, (errCoc) => {
        if (!errCoc) {
          seedCoC();
        }
      });
    }
  });

  // 2. Create the new block-based Chain of Command table
  db.query(`
    CREATE TABLE IF NOT EXISTS chain_of_command_blocks (
      id INT AUTO_INCREMENT PRIMARY KEY,
      type VARCHAR(50) NOT NULL,
      content JSON NOT NULL,
      sort_order INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `, (errBlocks) => {
    if (errBlocks) {
      console.error('Error creating chain_of_command_blocks table:', errBlocks);
    } else {
      seedCoCBlocks();
    }
  });
}

function seedCoCBlocks() {
  db.query("SELECT COUNT(*) as count FROM chain_of_command_blocks", (err, results) => {
    if (err || !results || results[0].count > 0) return;

    console.log("Seeding default Chain of Command blocks...");
    const defaultBlocks = [
      {
        type: 'text',
        content: JSON.stringify({
          text: "ISSUED BY THE OFFICE OF THE PRESIDENT",
          type: "paragraph",
          color: "#22d3ee",
          alignment: "center",
          bold: true,
          italic: false,
          underline: false,
          strikethrough: false
        })
      },
      {
        type: 'image',
        content: JSON.stringify({
          url: "https://i.imgur.com/YfVF1d0.png",
          alt: "The Great Seal of the United States of Paraiso",
          size: "md",
          alignment: "center"
        })
      },
      {
        type: 'text',
        content: JSON.stringify({
          text: "BRIAN GUTIERREZ",
          type: "title",
          color: "#c9a84c",
          alignment: "center",
          bold: true,
          italic: false,
          underline: false,
          strikethrough: false
        })
      },
      {
        type: 'text',
        content: JSON.stringify({
          text: "PRESIDENT OF THE UNITED STATES OF PARAISO",
          type: "subtitle",
          color: "#fbbf24",
          alignment: "center",
          bold: true,
          italic: false,
          underline: false,
          strikethrough: false
        })
      },
      {
        type: 'text',
        content: JSON.stringify({
          text: "OFFICE OF THE PRESIDENT\nGOVERNMENT OF PARAISO",
          type: "paragraph",
          color: "#64748b",
          alignment: "center",
          bold: true,
          italic: false,
          underline: false,
          strikethrough: false
        })
      },
      {
        type: 'half_box',
        content: JSON.stringify({
          color: "#22d3ee",
          width: "full",
          lines: [
            { text: "INTRODUCTION", type: "title", bold: true, alignment: "left", color: "#22d3ee" },
            { text: "The Government of Paraiso serves as the executive authority responsible for maintaining structure, organization, and oversight across the community.", type: "paragraph", alignment: "left", color: "#cbd5e1" },
            { text: "Instead of having one person manage every department, responsibilities are divided between executive offices and specialized management teams.", type: "paragraph", alignment: "left", color: "#94a3b8" }
          ]
        })
      },
      {
        type: 'title_strokes',
        content: JSON.stringify({
          text: "EXECUTIVE LEADERSHIP",
          color: "#c9a84c"
        })
      },
      {
        type: 'half_box',
        content: JSON.stringify({
          color: "#c9a84c",
          width: "half",
          lines: [
            { text: "PRESIDENT", type: "title", bold: true, alignment: "left", color: "#c9a84c" },
            { text: "The highest-ranking official within the Government of Paraiso. The President sets the overall vision of the community and has final authority over major decisions, appointments, and policies.", type: "paragraph", alignment: "left", color: "#cbd5e1" }
          ]
        })
      },
      {
        type: 'half_box',
        content: JSON.stringify({
          color: "#94a3b8",
          width: "half",
          lines: [
            { text: "VICE PRESIDENT", type: "title", bold: true, alignment: "left", color: "#94a3b8" },
            { text: "The second-highest executive official. The Vice President assists the President with government operations and acts on behalf of the President when necessary.", type: "paragraph", alignment: "left", color: "#cbd5e1" }
          ]
        })
      },
      {
        type: 'title_strokes',
        content: JSON.stringify({
          text: "EXECUTIVE DEPARTMENTS",
          color: "#22d3ee"
        })
      },
      {
        type: 'hybrid_box',
        content: JSON.stringify({
          color: "#22d3ee",
          title: "SECRETARY OF DEFENSE",
          subtitle: "Oversees all law enforcement and emergency service departments.",
          columns_title: "REPORTS UNDER SECRETARY OF DEFENSE:",
          sub_boxes: [
            {
              title: "ADMIN PERSONNEL",
              items: ["Helper Management"]
            },
            {
              title: "FACTION MANAGEMENT",
              items: ["Paraiso Police Department", "Federal Bureau of Investigation", "Paraiso Fire & Medical Department", "National Guard", "San Andreas News"]
            }
          ],
          footer: "Admin Personnel assists the Secretary of Defense in keeping Government employees on the right track. This includes professionalism, honor & loyalty. Aswel as issuing any punishments if any Government employees break the rules and or laws. Faction Management assists faction leaders, monitors activity, reviews department performance, and reports directly to the Secretary of Defense."
        })
      },
      {
        type: 'hybrid_box',
        content: JSON.stringify({
          color: "#22d3ee",
          title: "SECRETARY OF STATE",
          subtitle: "Oversees all civilian and criminal organizations operating throughout Paraiso.",
          columns_title: "REPORTS UNDER SECRETARY OF STATE:",
          sub_boxes: [
            {
              title: "GANG MANAGEMENT",
              items: ["All Official Criminal Organizations"]
            },
            {
              title: "CIVILIAN MANAGEMENT",
              items: ["Paraiso News", "Taxi Services", "Future Civilian Organizations"]
            }
          ],
          footer: "Gang Management works with gang leaders, their applications, and reports directly to the Secretary of State."
        })
      },
      {
        type: 'title_strokes',
        content: JSON.stringify({
          text: "WHY THIS SYSTEM EXISTS",
          color: "#c9a84c"
        })
      },
      {
        type: 'text',
        content: JSON.stringify({
          text: "Each executive position oversees a specific area of the server:",
          type: "subtitle",
          color: "#cbd5e1",
          alignment: "left",
          bold: true,
          italic: false,
          underline: false,
          strikethrough: false
        })
      },
      {
        type: 'half_box',
        content: JSON.stringify({
          color: "#c9a84c",
          width: "full",
          lines: [
            { text: "PRESIDENT", type: "title", bold: true, color: "#c9a84c" },
            { text: "→ The highest-ranking official within the Government of Paraiso. The President sets the overall vision of the community and has final authority over major decisions, appointments, and policies.", type: "paragraph", color: "#94a3b8" }
          ]
        })
      },
      {
        type: 'half_box',
        content: JSON.stringify({
          color: "#94a3b8",
          width: "full",
          lines: [
            { text: "VICE PRESIDENT", type: "title", bold: true, color: "#94a3b8" },
            { text: "→ The second-highest executive official. The Vice President assists the President with government operations and acts on behalf of the President when necessary.", type: "paragraph", color: "#94a3b8" }
          ]
        })
      },
      {
        type: 'half_box',
        content: JSON.stringify({
          color: "#22d3ee",
          width: "full",
          lines: [
            { text: "SECRETARY OF DEFENSE", type: "title", bold: true, color: "#22d3ee" },
            { text: "→ Government factions and emergency services.", type: "paragraph", color: "#94a3b8" }
          ]
        })
      },
      {
        type: 'half_box',
        content: JSON.stringify({
          color: "#fbbf24",
          width: "full",
          lines: [
            { text: "SECRETARY OF STATE", type: "title", bold: true, color: "#fbbf24" },
            { text: "→ All criminal organizations.", type: "paragraph", color: "#94a3b8" }
          ]
        })
      },
      {
        type: 'half_box',
        content: JSON.stringify({
          color: "#10b981",
          width: "full",
          lines: [
            { text: "GOVERNOR", type: "title", bold: true, color: "#10b981" },
            { text: "→ Businesses, economy, and commercial affairs.", type: "paragraph", color: "#94a3b8" }
          ]
        })
      },
      {
        type: 'text',
        content: JSON.stringify({
          text: "This allows every faction, gang, and business organizations to receive proper leadership without one person having to manage everything directly.",
          type: "paragraph",
          color: "#94a3b8",
          alignment: "left",
          bold: false,
          italic: true,
          underline: false,
          strikethrough: false
        })
      },
      {
        type: 'signature',
        content: JSON.stringify({
          name: "Brian Gutierrez",
          role: "President of the United States of Paraiso",
          office: "Office of the President",
          color: "#fbbf24"
        })
      }
    ];

    const values = defaultBlocks.map((b, index) => [b.type, b.content, index]);
    db.query("INSERT INTO chain_of_command_blocks (type, content, sort_order) VALUES ?", [values], (errInsert) => {
      if (errInsert) {
        console.error("Failed to seed chain_of_command_blocks:", errInsert);
      } else {
        console.log("Seeded chain_of_command_blocks successfully.");
      }
    });
  });
}

function seedCoC() {
  db.query("SELECT COUNT(*) as count FROM coc_categories", (err, catResults) => {
    if (!err && catResults && catResults[0].count === 0) {
      db.query("INSERT INTO coc_categories (id, name, sort_order) VALUES (1, 'Executive Leadership', 0), (2, 'Executive Departments', 1)", (errSeedCat) => {
        if (errSeedCat) {
          console.error("Failed to seed categories:", errSeedCat);
          return;
        }
        console.log("Seeded default Chain of Command categories.");
        seedCards();
      });
    } else {
      seedCards();
    }
  });
}

function seedCards() {
  db.query("SELECT COUNT(*) as count FROM chain_of_command", (err, cardsResults) => {
    if (!err && cardsResults && cardsResults[0].count === 0) {
      const defaultCoC = [
        [
          1,
          'simple',
          'President',
          null,
          'The highest-ranking official within the Government of Paraiso. The President sets the overall vision of the community and has final authority over major decisions, appointments, and policies.',
          null,
          null,
          '#c9a84c',
          0
        ],
        [
          1,
          'simple',
          'Vice President',
          null,
          'The second-highest executive official. The Vice President assists the President with government operations and acts on behalf of the President when necessary.',
          null,
          null,
          '#94a3b8',
          1
        ],
        [
          2,
          'detailed',
          'Secretary of Defense',
          'Oversees all law enforcement and emergency service departments.',
          null,
          JSON.stringify([
            {
              "group_title": "Admin Personnel",
              "items": ["Helper Management"]
            },
            {
              "group_title": "Faction Management",
              "items": ["Paraiso Police Department", "Federal Bureau of Investigation", "Paraiso Fire & Medical Department", "National Guard", "San Andreas News"]
            }
          ]),
          'Admin Personnel assists the Secretary of Defense in keeping Government employees on the right track. This includes professionalism, honor & loyalty. Aswel as issuing any punishments if any Government employees break the rules and or laws. Faction Management assists faction leaders, monitors activity, reviews department performance, and reports directly to the Secretary of Defense.',
          '#22d3ee',
          0
        ],
        [
          2,
          'detailed',
          'Secretary of State',
          'Oversees all civilian and criminal organizations operating throughout Paraiso.',
          null,
          JSON.stringify([
            {
              "group_title": "Gang Management",
              "items": ["All Official Criminal Organizations"]
            },
            {
              "group_title": "Civilian Management",
              "items": ["Paraiso News", "Taxi Services", "Future Civilian Organizations"]
            }
          ]),
          'Gang Management works with gang leaders, their applications, and reports directly to the Secretary of State.',
          '#22d3ee',
          1
        ],
        [
          2,
          'detailed',
          'Governor of Economic & Development',
          'Oversees the economic development of Paraiso, including businesses, commercial enterprises, and economic affairs.',
          null,
          JSON.stringify([
            {
              "group_title": "Business Management",
              "items": ["Business Applications", "Ownership Transfers", "Commercial Disputes", "Business Owner Support"]
            }
          ]),
          'Business Management handles the daily business process while the Governor oversees the overall economy and commercial growth of Paraiso.',
          '#22d3ee',
          2
        ],
        [
          2,
          'detailed',
          'Governor of City Relations',
          'Oversees the City relations of Paraiso, including complaints, appeals, and city helper organisations.',
          null,
          JSON.stringify([
            {
              "group_title": "Community Management",
              "items": ["Ban Appeals", "Warning Appeals", "Complaints"]
            },
            {
              "group_title": "Helper Management",
              "items": ["Helper Applications", "Helper Complaints"]
            }
          ]),
          'Community Management handles the daily community issues and appeals. Helper Management handles the daily tasks and management of all Helper employees, while the Governor oversees the overall relations between the Government & Citizens.',
          '#22d3ee',
          3
        ]
      ];

      let seeded = 0;
      defaultCoC.forEach((item) => {
        db.query(
          "INSERT INTO chain_of_command (category_id, layout, title, subtitle, description, reports, footer, color, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
          item,
          (errInsert) => {
            if (!errInsert) seeded++;
            if (seeded === defaultCoC.length) {
              console.log("Successfully seeded default Chain of Command cards.");
            }
          }
        );
      });
    }
  });
}

// GET /chain-of-command/categories
app.get('/chain-of-command/categories', (req, res) => {
  db.query("SELECT * FROM coc_categories ORDER BY sort_order ASC, id ASC", (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch categories' });
    res.json(results);
  });
});

// POST /chain-of-command/categories
app.post('/chain-of-command/categories', verifyPermission('coc'), (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ message: 'Category name is required' });

  db.query("SELECT MAX(sort_order) as maxOrder FROM coc_categories", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;
    db.query("INSERT INTO coc_categories (name, sort_order) VALUES (?, ?)", [name.trim(), nextOrder], (errInsert, result) => {
      if (errInsert) {
        if (errInsert.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ message: 'A category with this name already exists' });
        }
        return res.status(500).json({ message: 'Failed to create category: ' + errInsert.message });
      }
      res.status(201).json({ id: result.insertId, name: name.trim(), sort_order: nextOrder });
    });
  });
});

// PUT /chain-of-command/categories/reorder
app.put('/chain-of-command/categories/reorder', verifyPermission('coc'), (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders) || orders.length === 0)
    return res.json({ message: 'Nothing to reorder' });

  let completed = 0;
  let hasError = false;
  orders.forEach(item => {
    db.query("UPDATE coc_categories SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Reorder failed', error: err.message });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Categories reordered successfully' });
      }
    });
  });
});

// PUT /chain-of-command/categories/:id
app.put('/chain-of-command/categories/:id', verifyPermission('coc'), (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ message: 'Category name is required' });

  db.query("UPDATE coc_categories SET name = ? WHERE id = ?", [name.trim(), req.params.id], (err) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ message: 'A category with this name already exists' });
      }
      return res.status(500).json({ message: 'Failed to update category: ' + err.message });
    }
    res.json({ message: 'Category renamed successfully' });
  });
});

// DELETE /chain-of-command/categories/:id
app.delete('/chain-of-command/categories/:id', verifyPermission('coc'), (req, res) => {
  db.query("DELETE FROM coc_categories WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete category: ' + err.message });
    res.json({ message: 'Category and all associated cards deleted' });
  });
});

// GET /chain-of-command — public (joined with category name)
app.get('/chain-of-command', (req, res) => {
  db.query(`
    SELECT coc.*, cat.name as category_name, cat.sort_order as cat_sort_order
    FROM chain_of_command coc
    JOIN coc_categories cat ON coc.category_id = cat.id
    ORDER BY cat.sort_order ASC, cat.id ASC, coc.sort_order ASC, coc.id ASC
  `, (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch Chain of Command entries' });
    res.json(results);
  });
});

// POST /chain-of-command — admin only with permission
app.post('/chain-of-command', verifyPermission('coc'), (req, res) => {
  const { category_id, layout, title, subtitle, description, reports, reports_title, footer, color } = req.body;
  if (!category_id || !title) return res.status(400).json({ message: 'Category and Title are required' });

  db.query("SELECT MAX(sort_order) as maxOrder FROM chain_of_command WHERE category_id = ?", [category_id], (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;

    db.query(
      "INSERT INTO chain_of_command (category_id, layout, title, subtitle, description, reports, reports_title, footer, color, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [category_id, layout || 'detailed', title, subtitle, description, reports ? JSON.stringify(reports) : null, reports_title || null, footer, color || '#22d3ee', nextOrder],
      (errInsert, result) => {
        if (errInsert) return res.status(500).json({ message: 'Failed to create CoC entry: ' + errInsert.message });
        res.status(201).json({ id: result.insertId, category_id, layout, title, subtitle, description, reports, reports_title, footer, color, sort_order: nextOrder });
      }
    );
  });
});

// PUT /chain-of-command/reorder — admin only with permission
app.put('/chain-of-command/reorder', verifyPermission('coc'), (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders) || orders.length === 0)
    return res.json({ message: 'Nothing to reorder' });

  let completed = 0;
  let hasError = false;
  orders.forEach(item => {
    db.query("UPDATE chain_of_command SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Reorder failed', error: err.message });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Chain of Command entries reordered successfully' });
      }
    });
  });
});

// PUT /chain-of-command/:id — admin only with permission
app.put('/chain-of-command/:id', verifyPermission('coc'), (req, res) => {
  const { category_id, layout, title, subtitle, description, reports, reports_title, footer, color } = req.body;
  if (!category_id || !title) return res.status(400).json({ message: 'Category and Title are required' });

  db.query(
    "UPDATE chain_of_command SET category_id = ?, layout = ?, title = ?, subtitle = ?, description = ?, reports = ?, reports_title = ?, footer = ?, color = ? WHERE id = ?",
    [category_id, layout, title, subtitle, description, reports ? JSON.stringify(reports) : null, reports_title || null, footer, color, req.params.id],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to update CoC entry: ' + err.message });
      res.json({ message: 'Chain of Command entry updated successfully' });
    }
  );
});

// DELETE /chain-of-command/:id — admin only with permission
app.delete('/chain-of-command/:id', verifyPermission('coc'), (req, res) => {
  db.query("DELETE FROM chain_of_command WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete CoC entry' });
    res.json({ message: 'Chain of Command entry deleted' });
  });
});


// ════════════════════════════════════════════════════════════
// BLOCK-BASED CHAIN OF COMMAND ENDPOINTS
// ════════════════════════════════════════════════════════════

// GET /chain-of-command/blocks — fetch all blocks
app.get('/chain-of-command/blocks', (req, res) => {
  db.query("SELECT * FROM chain_of_command_blocks ORDER BY sort_order ASC", (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Database error: ' + err.message });
    }
    // Parse JSON contents
    const parsed = results.map(row => {
      let content = row.content;
      if (typeof content === 'string') {
        try {
          content = JSON.parse(content);
        } catch (e) {
          // ignore
        }
      }
      return { ...row, content };
    });
    res.json(parsed);
  });
});

// POST /chain-of-command/blocks — add a block (admin only with permission)
app.post('/chain-of-command/blocks', verifyPermission('coc'), (req, res) => {
  const { type, content } = req.body;
  if (!type || !content) return res.status(400).json({ message: 'Type and Content are required' });

  // Get max sort order
  db.query("SELECT MAX(sort_order) as maxOrder FROM chain_of_command_blocks", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0].maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;
    
    db.query(
      "INSERT INTO chain_of_command_blocks (type, content, sort_order) VALUES (?, ?, ?)",
      [type, typeof content === 'string' ? content : JSON.stringify(content), nextOrder],
      (errInsert, result) => {
        if (errInsert) return res.status(500).json({ message: 'Failed to create block: ' + errInsert.message });
        res.json({ id: result.insertId, message: 'Block created successfully' });
      }
    );
  });
});

// PUT /chain-of-command/blocks/reorder — reorder blocks (admin only with permission)
app.put('/chain-of-command/blocks/reorder', verifyPermission('coc'), (req, res) => {
  const { orders } = req.body; // array of { id, sort_order }
  if (!Array.isArray(orders)) return res.status(400).json({ message: 'Orders list is required' });

  let completed = 0;
  let hasError = false;

  orders.forEach(item => {
    db.query("UPDATE chain_of_command_blocks SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) {
        hasError = true;
        return res.status(500).json({ message: 'Reorder failed', error: err.message });
      }
      completed++;
      if (completed === orders.length && !hasError) {
        res.json({ message: 'Blocks reordered successfully' });
      }
    });
  });
});

// PUT /chain-of-command/blocks/:id — update a block (admin only with permission)
app.put('/chain-of-command/blocks/:id', verifyPermission('coc'), (req, res) => {
  const { type, content } = req.body;
  if (!type || !content) return res.status(400).json({ message: 'Type and Content are required' });

  db.query(
    "UPDATE chain_of_command_blocks SET type = ?, content = ? WHERE id = ?",
    [type, typeof content === 'string' ? content : JSON.stringify(content), req.params.id],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to update block: ' + err.message });
      res.json({ message: 'Block updated successfully' });
    }
  );
});

// DELETE /chain-of-command/blocks/:id — delete a block (admin only with permission)
app.delete('/chain-of-command/blocks/:id', verifyPermission('coc'), (req, res) => {
  db.query("DELETE FROM chain_of_command_blocks WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete block' });
    res.json({ message: 'Block deleted successfully' });
  });
});

// POST /upload — base64 image upload route (admin only)
app.post('/upload', verifyAdmin, (req, res) => {
  const { image } = req.body; // base64 string
  if (!image) return res.status(400).json({ message: 'No image data provided' });

  // Remove header
  const matches = image.match(/^data:image\/([A-Za-z-+\/]+);base64,(.+)$/);
  if (!matches || matches.length !== 3) {
    return res.status(400).json({ message: 'Invalid base64 image format' });
  }

  const ext = matches[1];
  const dataBuffer = Buffer.from(matches[2], 'base64');
  const filename = `img_${Date.now()}.${ext === 'jpeg' ? 'jpg' : ext}`;
  const uploadDir = path.join(__dirname, 'uploads');

  if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
  }

  fs.writeFile(path.join(uploadDir, filename), dataBuffer, (err) => {
    if (err) {
      console.error('File write error:', err);
      return res.status(500).json({ message: 'Failed to save image' });
    }
    const url = `${req.protocol}://${req.get('host')}/uploads/${filename}`;
    res.json({ url });
  });
});


// ─── GET / ────────────────────────────────────────────────
app.get('/', (req, res) => res.send('Server is running and working perfectly!'));

app.listen(5000, () => console.log("Server is running on port 5000"));
