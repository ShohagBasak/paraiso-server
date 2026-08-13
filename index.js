const express = require('express');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const db = require('./db');
const sampDb = require('./sampDb');
const whirlpoolHelper = require('./whirlpool');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
require('dotenv').config(); // Reload env variables
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const dns = require('dns');

process.on('uncaughtException', (err) => {
  console.error('⚠️ Uncaught Exception in server process:', err.message);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('⚠️ Unhandled Rejection at:', promise, 'reason:', reason);
});

if (dns.setDefaultResultOrder) {
  dns.setDefaultResultOrder('ipv4first');
}

// ─── Native HTTPS POST Helper (Version-agnostic fallback for fetch) ───
function httpsPost(urlStr, headers, bodyData) {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(urlStr);
      const options = {
        method: 'POST',
        hostname: url.hostname,
        path: url.pathname + url.search,
        headers: headers
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            status: res.statusCode,
            json: async () => {
              try {
                return JSON.parse(data);
              } catch {
                return { message: data };
              }
            },
            text: async () => data
          });
        });
      });

      req.on('error', (err) => reject(err));
      if (bodyData) req.write(bodyData);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);

// ─── Security Headers Middleware (Anti-XSS, Clickjacking, MIME-Sniffing Protection) ───
app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ─── Rate Limiter for Registration & OTP ───
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per 15 minutes
  message: { message: "Too many registration attempts from this IP. Please try again after 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Highscores API Rate Limiter ───
const highscoresLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 30, 
  message: { error: "Too Many Requests", message: "Highscores API rate limit exceeded. Please wait 1 minute." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Nodemailer Transporter ───
const getTransporter = () => {
  if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    const cleanUser = process.env.EMAIL_USER.trim();
    const cleanPass = process.env.EMAIL_PASS.trim();
    const isGmail = cleanUser.endsWith('@gmail.com');
    
    // Default to smtp.zoho.com for custom domain/zoho and port 587 (STARTTLS works best on Render)
    const host = process.env.EMAIL_HOST || (isGmail ? 'smtp.gmail.com' : 'smtp.zoho.com');
    const port = parseInt(process.env.EMAIL_PORT, 10) || 587;
    const secure = port === 465;

    return nodemailer.createTransport({
      host: host,
      port: port,
      secure: secure,
      auth: {
        user: cleanUser,
        pass: cleanPass
      },
      tls: {
        rejectUnauthorized: false
      },
      connectionTimeout: 10000, // 10 seconds timeout
      greetingTimeout: 10000,
      socketTimeout: 15000
    });
  }
  return null;
};

const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL
].filter(Boolean).map(url => url.replace(/\/$/, ''));

const FRONTEND_BASE_URL = (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');

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

// ─── Initialize Allowed Registration Emails Table ─────────────
db.query(`
  CREATE TABLE IF NOT EXISTS allowed_registration_emails (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(150) NOT NULL UNIQUE,
    added_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
  )
`, (err) => {
  if (err) console.error("Error creating allowed_registration_emails table:", err);
});

// ─── Initialize Email OTPs Table ─────────────────────────────
db.query(`
  CREATE TABLE IF NOT EXISTS email_otps (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(10) NOT NULL,
    type VARCHAR(30) DEFAULT 'registration',
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX (email)
  )
`, (err) => {
  if (err) console.error("Error creating email_otps table:", err);
  else {
    db.query("SHOW COLUMNS FROM email_otps LIKE 'type'", (err2, rows) => {
      if (!err2 && rows && rows.length === 0) {
        db.query("ALTER TABLE email_otps ADD COLUMN type VARCHAR(30) DEFAULT 'registration'", () => {});
      }
    });
  }
});

// ─── Initialize Page Contents Table ───────────────────────
db.query(`
  CREATE TABLE IF NOT EXISTS page_contents (
    page_key VARCHAR(100) PRIMARY KEY,
    content LONGTEXT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) console.error("Error creating page_contents table:", err);
});

// ─── Initialize Donate Categories Table ───────────────────
db.query(`
  CREATE TABLE IF NOT EXISTS donate_categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`, (err) => {
  if (err) console.error("Error creating donate_categories table:", err);
});

// ─── Initialize Donate Items Table ────────────────────────
db.query(`
  CREATE TABLE IF NOT EXISTS donate_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    image_url TEXT,
    price DECIMAL(10,2) DEFAULT 0.00,
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES donate_categories(id) ON DELETE CASCADE
  )
`, (err) => {
  if (err) console.error("Error creating donate_items table:", err);
});

// ─── Initialize Purchase Tickets Table ────────────────────
db.query(`
  CREATE TABLE IF NOT EXISTS purchase_tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    item_id INT NOT NULL,
    ingame_name VARCHAR(255) DEFAULT '',
    discord_username VARCHAR(255) DEFAULT '',
    quantity INT DEFAULT 1,
    status ENUM('open','claimed','closed') DEFAULT 'open',
    assigned_admin_id INT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES donate_items(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_admin_id) REFERENCES users(id) ON DELETE SET NULL
  )
`, (err) => {
  if (err) console.error("Error creating purchase_tickets table:", err);
  else {
    // Auto-alter table to ensure new columns exist for existing databases
    db.query("ALTER TABLE purchase_tickets ADD COLUMN IF NOT EXISTS ingame_name VARCHAR(255) DEFAULT ''", () => {});
    db.query("ALTER TABLE purchase_tickets ADD COLUMN IF NOT EXISTS discord_username VARCHAR(255) DEFAULT ''", () => {});
    db.query("ALTER TABLE purchase_tickets ADD COLUMN IF NOT EXISTS quantity INT DEFAULT 1", () => {});
  }
});

// ─── Initialize Ticket Messages Table ─────────────────────
db.query(`
  CREATE TABLE IF NOT EXISTS ticket_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    sender_id INT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES purchase_tickets(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
  )
`, (err) => {
  if (err) console.error("Error creating ticket_messages table:", err);
});

// ─── Initialize Ticket Items Table (Multiple items per ticket) ───
db.query(`
  CREATE TABLE IF NOT EXISTS ticket_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ticket_id INT NOT NULL,
    item_id INT NOT NULL,
    quantity INT DEFAULT 1,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES purchase_tickets(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES donate_items(id) ON DELETE CASCADE
  )
`, (err) => {
  if (err) console.error("Error creating ticket_items table:", err);
});

// ─── Initialize Notifications Table ───────────────────────
db.query(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT,
    link VARCHAR(255) DEFAULT '',
    is_read TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`, (err) => {
  if (err) console.error("Error creating notifications table:", err);
  else {
    db.query("DELETE FROM notifications WHERE title LIKE 'New Staff Reply%'", (delErr) => {
      if (!delErr) console.log("Cleaned existing staff reply notifications.");
    });
    // Cleanup any orphaned ticket notifications where ticket no longer exists
    db.query(
      `DELETE FROM notifications 
       WHERE (link LIKE '%id=%' OR link LIKE '%/my-tickets/%' OR title LIKE '%Ticket #%')
       AND NOT EXISTS (
         SELECT 1 FROM purchase_tickets t 
         WHERE notifications.link REGEXP CONCAT('[?&]id=', t.id, '([&]|$)')
            OR notifications.link REGEXP CONCAT('/my-tickets/', t.id, '(/|$)')
            OR notifications.title REGEXP CONCAT('#', t.id, '([^0-9]|$)')
       )`,
      (delErr) => {
        if (!delErr) console.log("Cleaned notifications for deleted tickets.");
      }
    );
  }
});

// ─── Helper to Create & Send Notification (In-App + Email) ───
const createAndSendNotification = ({ userId, title, message, link, emailSubject, emailHtml, skipInApp = false }) => {
  if (!userId) return;

  if (!skipInApp) {
    db.query(
      "INSERT INTO notifications (user_id, title, message, link) VALUES (?, ?, ?, ?)",
      [userId, title, message, link || ''],
      (err, result) => {
        if (err) {
          console.error("Error inserting notification:", err);
        } else if (global.io) {
          const notifData = {
            id: result.insertId,
            user_id: userId,
            title,
            message,
            link: link || '',
            is_read: 0,
            created_at: new Date().toISOString()
          };
          global.io.to(`user-${userId}`).emit('new-notification', notifData);
        }
      }
    );
  }

  // Async Email dispatch via HTTP API (Brevo / Resend) or Nodemailer SMTP fallback
  if (emailSubject && emailHtml) {
    db.query("SELECT email FROM users WHERE id = ?", [userId], async (err2, uRows) => {
      if (!err2 && uRows && uRows.length > 0 && uRows[0].email) {
        const toEmail = uRows[0].email;

        // 1. Try Brevo HTTP API (Port 443 - Never blocked on Render)
        if (process.env.BREVO_API_KEY) {
          try {
            const res = await httpsPost(
              'https://api.brevo.com/v3/smtp/email',
              {
                'accept': 'application/json',
                'api-key': process.env.BREVO_API_KEY.trim(),
                'content-type': 'application/json'
              },
              JSON.stringify({
                sender: { name: "Paraiso Gaming Support", email: (process.env.EMAIL_USER || "noreply@paraisogaming.com").trim() },
                to: [{ email: toEmail }],
                subject: emailSubject,
                htmlContent: emailHtml
              })
            );
            if (res.ok) {
              console.log("Notification Email sent via Brevo API to", toEmail);
              return;
            } else {
              const errBody = await res.json();
              console.error("Brevo API Delivery Error:", res.status, JSON.stringify(errBody));
            }
          } catch (e) {
            console.error("Notification Email via Brevo error:", e.message);
          }
        }

        // 2. Try Resend HTTP API (Port 443 - Never blocked on Render)
        if (process.env.RESEND_API_KEY) {
          try {
            const res = await httpsPost(
              'https://api.resend.com/emails',
              {
                'Authorization': `Bearer ${process.env.RESEND_API_KEY.trim()}`,
                'Content-Type': 'application/json'
              },
              JSON.stringify({
                from: process.env.EMAIL_FROM || 'Paraiso Gaming <onboarding@resend.dev>',
                to: toEmail,
                subject: emailSubject,
                html: emailHtml
              })
            );
            if (res.ok) {
              console.log("Notification Email sent via Resend API to", toEmail);
              return;
            } else {
              const errBody = await res.json();
              console.error("Resend API Delivery Error:", res.status, JSON.stringify(errBody));
            }
          } catch (e) {
            console.error("Notification Email via Resend error:", e.message);
          }
        }

        // 3. Fallback to Nodemailer SMTP
        const transporter = getTransporter();
        if (transporter && process.env.EMAIL_USER) {
          const mailOptions = {
            from: `"Paraiso Gaming Support" <${process.env.EMAIL_USER.trim()}>`,
            to: toEmail,
            subject: emailSubject,
            html: emailHtml
          };
          transporter.sendMail(mailOptions, (mailErr) => {
            if (mailErr) console.error("Notification Email delivery error:", mailErr.message);
          });
        }
      }
    });
  }
};

const notifyAllAdmins = ({ title, message, link, emailSubject, emailHtml }) => {
  db.query(`
    SELECT DISTINCT u.id 
    FROM users u 
    LEFT JOIN admin_permissions p ON p.user_id = u.id 
    WHERE u.role = 'master' OR (u.role = 'admin' AND p.permission_key = 'tickets')
  `, (err, admins) => {
    if (!err && admins && admins.length > 0) {
      admins.forEach(admin => {
        createAndSendNotification({
          userId: admin.id,
          title,
          message,
          link,
          emailSubject,
          emailHtml
        });
      });
    }
  });
};


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
    db.query("SELECT role FROM users WHERE id = ?", [req.user.id], (err, userRows) => {
      const currentRole = (userRows && userRows.length > 0) ? userRows[0].role : req.user.role;
      if (currentRole !== 'admin' && currentRole !== 'master') {
        return res.status(403).json({ message: 'Admin access required' });
      }
      req.user.role = currentRole;
      next();
    });
  });
}

// ─── verifyMaster Middleware ───────────────────────────────
function verifyMaster(req, res, next) {
  verifyToken(req, res, () => {
    db.query("SELECT role FROM users WHERE id = ?", [req.user.id], (err, userRows) => {
      const currentRole = (userRows && userRows.length > 0) ? userRows[0].role : req.user.role;
      if (currentRole !== 'master') {
        return res.status(403).json({ message: 'Master Admin access required' });
      }
      req.user.role = currentRole;
      next();
    });
  });
}

// ─── verifyPermission Middleware ───────────────────────────
function verifyPermission(permissionKey) {
  return (req, res, next) => {
    verifyToken(req, res, () => {
      db.query("SELECT role FROM users WHERE id = ?", [req.user.id], (err, userRows) => {
        if (err || !userRows || userRows.length === 0) {
          return res.status(403).json({ message: 'Access denied' });
        }
        const currentRole = userRows[0].role;
        req.user.role = currentRole;

        if (currentRole === 'master') {
          return next();
        }
        if (currentRole === 'admin') {
          if (permissionKey === 'tickets') {
            return next(); // All Admins have access to Tickets
          }
          db.query(
            "SELECT 1 FROM admin_permissions WHERE user_id = ? AND permission_key = ?",
            [req.user.id, permissionKey],
            (err2, results) => {
              if (!err2 && results && results.length > 0) {
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

// ─── POST /register (Master Admin only — creates new users) ───
app.post('/register', verifyMaster, async (req, res) => {
  try {
    // console.log("========== REGISTER HIT (Master Admin) ==========");
    // console.log("Body:", req.body);

    const { username, email, password, role: newRole, permissions } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "Username, email, and password are required." });
    }

    // ─── Check email whitelist ───
    const [whitelistRows] = await db.promise().query(
      "SELECT id FROM allowed_registration_emails WHERE email = ?",
      [email]
    );
    if (!whitelistRows || whitelistRows.length === 0) {
      return res.status(403).json({
        message: `This email is not whitelisted. Please add "${email}" to the allowed list first.`
      });
    }

    const assignedRole = ['admin', 'master', 'user'].includes(newRole) ? newRole : 'admin';
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = `INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`;

    db.query(sql, [username, email, hashedPassword, assignedRole], async (err, result) => {
      if (err) {
        console.error("DATABASE ERROR:", err);
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: "An account with this email already exists." });
        }
        return res.status(500).json({ message: "Registration failed. Please try again." });
      }

      const newUserId = result.insertId;

      // ─── Save permissions if role is admin and permissions provided ───
      const validPermKeys = ['banners', 'announcements', 'staff', 'roster', 'helper-roster', 'faqs', 'coc', 'donate', 'tickets'];
      const permsToSave = Array.isArray(permissions)
        ? permissions.filter(p => validPermKeys.includes(p))
        : [];

      if (assignedRole === 'admin' && permsToSave.length > 0) {
        const permValues = permsToSave.map(p => [newUserId, p]);
        db.query(
          "INSERT IGNORE INTO admin_permissions (user_id, permission_key) VALUES ?",
          [permValues],
          (permErr) => {
            if (permErr) console.error("Failed to save permissions:", permErr);
          }
        );
      }

      // Remove email from whitelist after successful registration
      db.query("DELETE FROM allowed_registration_emails WHERE email = ?", [email], (delErr) => {
        if (delErr) console.error("Failed to remove email from whitelist after registration:", delErr);
      });

      // console.log(`User registered by master admin: ${email} (role: ${assignedRole}, perms: ${permsToSave.join(', ') || 'none'})`);

      res.status(201).json({
        message: `User "${username}" created successfully with role "${assignedRole}".`,
        user: {
          id: newUserId,
          username,
          email,
          role: assignedRole,
          permissions: permsToSave
        }
      });
    });

  } catch (err) {
    console.error("REGISTER CRASH:", err);
    res.status(500).json({ message: err.message });
  }
});


// ─── GET /allowed-emails ───────────────────────────────────
app.get('/allowed-emails', verifyMaster, (req, res) => {
  db.query(
    "SELECT id, email, added_by, created_at FROM allowed_registration_emails ORDER BY created_at DESC",
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Failed to fetch allowed emails' });
      res.json(results);
    }
  );
});

// ─── POST /allowed-emails ──────────────────────────────────
app.post('/allowed-emails', verifyMaster, (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ message: 'A valid email address is required.' });
  }
  db.query(
    "INSERT INTO allowed_registration_emails (email, added_by) VALUES (?, ?)",
    [email.toLowerCase().trim(), req.user.id],
    (err, result) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: 'This email is already in the whitelist.' });
        }
        return res.status(500).json({ message: 'Failed to add email to whitelist.' });
      }
      res.status(201).json({
        message: `Email "${email}" added to whitelist.`,
        id: result.insertId,
        email: email.toLowerCase().trim()
      });
    }
  );
});

// ─── DELETE /allowed-emails/:id ───────────────────────────
app.delete('/allowed-emails/:id', verifyMaster, (req, res) => {
  const { id } = req.params;
  db.query(
    "DELETE FROM allowed_registration_emails WHERE id = ?",
    [id],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to remove email from whitelist.' });
      if (result.affectedRows === 0) return res.status(404).json({ message: 'Email not found in whitelist.' });
      res.json({ message: 'Email removed from whitelist.' });
    }
  );
});

// ─── HELPER: Send Email (SMTP / Brevo / Resend) ───
const sendEmailHelper = async ({ to, subject, description, otp, expiryMinutes = 15 }) => {
  const htmlContent = `
    <div style="font-family: Arial, sans-serif; background: #080d13; color: #fff; padding: 30px; border-radius: 16px; max-width: 480px; margin: 0 auto; border: 1px solid #1e293b;">
      <h2 style="color: #06b6d4; text-transform: uppercase; margin-bottom: 8px;">Paraiso Gaming</h2>
      <p style="color: #94a3b8; font-size: 14px;">${description}</p>
      <div style="background: #0d1117; padding: 18px; border-radius: 12px; text-align: center; margin: 20px 0; border: 1px solid #334155;">
        <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #38bdf8;">${otp}</span>
      </div>
      <p style="color: #64748b; font-size: 12px;">This code will expire in ${expiryMinutes} minutes. If you did not request this code, please ignore this email.</p>
    </div>
  `;

  if (process.env.BREVO_API_KEY) {
    try {
      const res = await httpsPost(
        'https://api.brevo.com/v3/smtp/email',
        {
          'accept': 'application/json',
          'api-key': process.env.BREVO_API_KEY.trim(),
          'content-type': 'application/json'
        },
        JSON.stringify({
          sender: { name: "Paraiso Gaming", email: process.env.EMAIL_USER || "noreply@paraisogaming.com" },
          to: [{ email: to }],
          subject,
          htmlContent
        })
      );
      if (!res.ok) throw new Error('Brevo API error');
      return { success: true };
    } catch (err) {
      console.error("Brevo Email error:", err);
      return { success: false, error: err.message };
    }
  }

  if (process.env.RESEND_API_KEY) {
    try {
      const res = await httpsPost(
        'https://api.resend.com/emails',
        {
          'Authorization': `Bearer ${process.env.RESEND_API_KEY.trim()}`,
          'Content-Type': 'application/json'
        },
        JSON.stringify({
          from: process.env.EMAIL_USER || 'onboarding@resend.dev',
          to,
          subject,
          html: htmlContent
        })
      );
      if (!res.ok) throw new Error('Resend API error');
      return { success: true };
    } catch (err) {
      console.error("Resend Email error:", err);
      return { success: false, error: err.message };
    }
  }

  const transporter = getTransporter();
  if (!transporter) return { success: false, error: 'Email system not configured.' };

  try {
    await transporter.sendMail({
      from: `"Paraiso Gaming" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html: htmlContent
    });
    return { success: true };
  } catch (err) {
    console.error("SMTP Email error:", err);
    return { success: false, error: err.message };
  }
};

// ─── POST /send-otp (Send 6-digit registration OTP to email) ───
app.post('/send-otp', registerLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ message: 'Valid email address is required.' });
    }
    const cleanEmail = email.toLowerCase().trim();

    const existingUsers = await new Promise((resolve, reject) => {
      db.query("SELECT id FROM users WHERE email = ?", [cleanEmail], (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });

    if (existingUsers.length > 0) {
      return res.status(409).json({ message: 'An account with this email already exists.' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await new Promise((resolve) => {
      db.query("DELETE FROM email_otps WHERE email = ?", [cleanEmail], () => resolve());
    });

    await new Promise((resolve, reject) => {
      db.query(
        "INSERT INTO email_otps (email, otp, expires_at, type) VALUES (?, ?, ?, 'registration')",
        [cleanEmail, otp, expiresAt],
        (err) => {
          if (err) {
            db.query("INSERT INTO email_otps (email, otp, expires_at) VALUES (?, ?, ?)", [cleanEmail, otp, expiresAt], (err2) => {
              if (err2) reject(err2);
              else resolve();
            });
          } else {
            resolve();
          }
        }
      );
    });

    if (process.env.DEV_MODE === 'true') {
      console.log(`[DEV_MODE] Registration OTP for ${cleanEmail} is: ${otp}`);
      return res.json({ message: `[DEV_MODE Active] OTP code is: ${otp}`, devOtp: otp });
    }

    const emailSent = await sendEmailHelper({
      to: cleanEmail,
      subject: 'Your Paraiso Gaming Registration OTP Code',
      description: 'Use the following OTP code to complete your registration:',
      otp: otp,
      expiryMinutes: 10
    });

    if (emailSent.success) {
      res.json({ message: 'OTP code sent to your email.' });
    } else {
      res.status(500).json({ message: emailSent.error || 'Failed to send OTP email.' });
    }
  } catch (err) {
    console.error("SEND OTP ERROR:", err);
    res.status(500).json({ message: err.message || 'Server error sending OTP.' });
  }
});

// ─── POST /forgot-password (Request 6-digit password reset OTP) ───
app.post('/forgot-password', registerLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@')) {
      return res.status(400).json({ message: 'Valid email address is required.' });
    }
    const cleanEmail = email.toLowerCase().trim();

    const userRows = await new Promise((resolve, reject) => {
      db.query("SELECT id, username FROM users WHERE email = ?", [cleanEmail], (err, rows) => {
        if (err) reject(err);
        else resolve(rows || []);
      });
    });

    if (userRows.length === 0) {
      return res.status(404).json({ message: 'No account found with this email address.' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await new Promise((resolve) => {
      db.query("DELETE FROM email_otps WHERE email = ?", [cleanEmail], () => resolve());
    });

    await new Promise((resolve, reject) => {
      db.query(
        "INSERT INTO email_otps (email, otp, expires_at, type) VALUES (?, ?, ?, 'password_reset')",
        [cleanEmail, otp, expiresAt],
        (err) => {
          if (err) {
            db.query("INSERT INTO email_otps (email, otp, expires_at) VALUES (?, ?, ?)", [cleanEmail, otp, expiresAt], (err2) => {
              if (err2) reject(err2);
              else resolve();
            });
          } else {
            resolve();
          }
        }
      );
    });

    if (process.env.DEV_MODE === 'true') {
      console.log(`[DEV_MODE] Password Reset OTP for ${cleanEmail} is: ${otp}`);
      return res.json({ message: `[DEV_MODE] Reset code is: ${otp}`, devOtp: otp });
    }

    const emailSent = await sendEmailHelper({
      to: cleanEmail,
      subject: '🔒 Password Reset Code - Paraiso Gaming',
      description: `Hello <strong>${userRows[0].username}</strong>,<br/>Use the following 6-digit OTP code to reset your password:`,
      otp: otp,
      expiryMinutes: 15
    });

    if (emailSent.success) {
      res.json({ message: 'Password reset code sent to your email.' });
    } else {
      res.status(500).json({ message: emailSent.error || 'Failed to send reset email.' });
    }
  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    res.status(500).json({ message: err.message || 'Server error processing request.' });
  }
});

// ─── POST /reset-password (Verify OTP and update user password) ───
app.post('/reset-password', registerLimiter, async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: 'Email, OTP reset code, and new password are required.' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'New password must be at least 6 characters.' });
    }

    const cleanEmail = email.toLowerCase().trim();
    const cleanOtp = otp.toString().trim();

    const results = await new Promise((resolve, reject) => {
      db.query(
        "SELECT id FROM email_otps WHERE email = ? AND otp = ? AND expires_at > NOW()",
        [cleanEmail, cleanOtp],
        (err, rows) => {
          if (err) reject(err);
          else resolve(rows || []);
        }
      );
    });

    if (!results || results.length === 0) {
      const fallbackRows = await new Promise((resolve) => {
        db.query("SELECT id FROM email_otps WHERE email = ? AND otp = ?", [cleanEmail, cleanOtp], (err, rows) => {
          resolve(rows || []);
        });
      });

      if (fallbackRows.length === 0) {
        return res.status(400).json({ message: 'Invalid 6-digit OTP code.' });
      } else {
        return res.status(400).json({ message: 'OTP code has expired. Please request a new code.' });
      }
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await new Promise((resolve, reject) => {
      db.query("UPDATE users SET password_hash = ? WHERE email = ?", [hashedPassword, cleanEmail], (err, result) => {
        if (err) {
          db.query("UPDATE users SET password = ? WHERE email = ?", [hashedPassword, cleanEmail], (err2, result2) => {
            if (err2) reject(err2);
            else resolve(result2);
          });
        } else {
          resolve(result);
        }
      });
    });

    db.query("DELETE FROM email_otps WHERE email = ?", [cleanEmail], () => {});

    res.json({ message: 'Password updated successfully! You can now log in.' });
  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err);
    res.status(500).json({ message: err.message || 'Server error resetting password.' });
  }
});

// ─── POST /public-register (Public — community user registration with OTP & Turnstile) ───
app.post('/public-register', registerLimiter, async (req, res) => {
  try {
    const { username, email, password, otp, turnstileToken } = req.body;
    if (!username || !email || !password || !otp) {
      return res.status(400).json({ message: "Username, email, password, and OTP code are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    const cleanEmail = email.toLowerCase().trim();

    // ── Turnstile Verification (if secret key configured) ──
    if (process.env.TURNSTILE_SECRET_KEY && turnstileToken) {
      try {
        const verifyRes = await httpsPost(
          'https://challenges.cloudflare.com/turnstile/v0/siteverify',
          { 'Content-Type': 'application/x-www-form-urlencoded' },
          new URLSearchParams({
            secret: process.env.TURNSTILE_SECRET_KEY,
            response: turnstileToken
          }).toString()
        );
        const verifyData = await verifyRes.json();
        if (!verifyData.success) {
          return res.status(400).json({ message: "Turnstile captcha verification failed. Please try again." });
        }
      } catch (tsErr) {
        console.error("Turnstile error:", tsErr);
      }
    }

    // ── Verify OTP ──
    db.query(
      "SELECT * FROM email_otps WHERE email = ? AND otp = ? AND expires_at > NOW() ORDER BY id DESC LIMIT 1",
      [cleanEmail, otp.trim()],
      async (otpErr, otpResults) => {
        try {
          if (otpErr) {
            console.error("OTP DB Select Error:", otpErr);
            return res.status(500).json({ message: "Database error during registration verification." });
          }
          if (!otpResults || otpResults.length === 0) {
            return res.status(400).json({ message: "Invalid or expired OTP code. Please request a new code." });
          }

          const hashedPassword = await bcrypt.hash(password, 10);
          const sql = `INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')`;

          db.query(sql, [username.trim(), cleanEmail, hashedPassword], (err, result) => {
            try {
              if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                  return res.status(409).json({ message: "An account with this email already exists." });
                }
                console.error("User INSERT error:", err);
                return res.status(500).json({ message: "Registration failed. Please try again." });
              }

              if (!result) {
                console.error("User INSERT result is undefined");
                return res.status(500).json({ message: "Registration failed: no database response." });
              }
              const newUserId = result.insertId;

              // Clear used OTP
              db.query("DELETE FROM email_otps WHERE email = ?", [cleanEmail], () => {});

              if (!process.env.JWT_SECRET) {
                console.error("JWT_SECRET is missing from environment variables!");
                return res.status(500).json({ message: "Server configuration error: JWT_SECRET not set on host." });
              }

              const token = jwt.sign({ id: newUserId, email: cleanEmail, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '7d' });
              res.cookie('token', token, cookieOptions);
              res.status(201).json({
                message: 'Registration successful!',
                token,
                user: { id: newUserId, username: username.trim(), email: cleanEmail, role: 'user', permissions: [] }
              });
            } catch (innerErr) {
              console.error("Error inside INSERT callback:", innerErr);
              res.status(500).json({ message: `Internal server error: ${innerErr.message}` });
            }
          });
        } catch (callbackErr) {
          console.error("Error inside SELECT OTP callback:", callbackErr);
          res.status(500).json({ message: `Internal server error: ${callbackErr.message}` });
        }
      }
    );
  } catch (err) {
    console.error("PUBLIC REGISTER CRASH:", err);
    res.status(500).json({ message: err.message });
  }
});

// ─── POST /login ──────────────────────────────────────────
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], async (err, results) => {
    try {
      if (err) {
        console.error("Login SELECT error:", err);
        return res.status(500).json({ message: "Database error during login." });
      }
      if (!results || results.length === 0) {
        return res.status(400).json({ message: "User not found" });
      }
      const match = await bcrypt.compare(password, results[0].password_hash);
      if (!match) return res.status(401).json({ message: "Invalid password" });
      const { id, username, role } = results[0];

      if (!process.env.JWT_SECRET) {
        console.error("JWT_SECRET is missing from environment variables!");
        return res.status(500).json({ message: "Server configuration error: JWT_SECRET not set on host." });
      }

      const token = jwt.sign({ id, email, role }, process.env.JWT_SECRET, { expiresIn: '7d' });
      res.cookie('token', token, cookieOptions);
      
      db.query("SELECT permission_key FROM admin_permissions WHERE user_id = ?", [id], (err2, permResults) => {
        try {
          const permissions = !err2 && permResults ? permResults.map(p => p.permission_key) : [];
          res.json({ 
            token,
            user: { id, username, email, role, permissions } 
          });
        } catch (innerErr) {
          console.error("Error inside admin_permissions SELECT callback:", innerErr);
          res.status(500).json({ message: `Internal server error: ${innerErr.message}` });
        }
      });
    } catch (callbackErr) {
      console.error("Error inside login callback:", callbackErr);
      res.status(500).json({ message: `Internal server error: ${callbackErr.message}` });
    }
  });
});

// ─── POST /reset-password (Master Admin only) ─────────────
app.post('/reset-password', verifyMaster, async (req, res) => {
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

//  POST /logout 
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
      const allPerms = ['settings', 'banners', 'announcements', 'staff', 'roster', 'helper-roster', 'faqs', 'coc', 'donate', 'tickets'];
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

// PUT /page-settings/govt-header — admin only with permission
app.put('/page-settings/govt-header', verifyPermission('roster'), (req, res) => {
  const { image_url, title, subtitle, title_color, subtitle_color, footer_quote } = req.body;
  const content = JSON.stringify({ image_url, title, subtitle, title_color, subtitle_color, footer_quote });

  // First delete all rows with this key to avoid duplicates
  db.query("DELETE FROM page_contents WHERE page_key = 'govt-roster-header'", (err) => {
    if (err) return res.status(500).json({ message: 'Failed to clean old header settings', error: err });

    // Then insert the new configuration
    db.query("INSERT INTO page_contents (page_key, content) VALUES ('govt-roster-header', ?)", [content], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to save header settings', error: err2 });
      res.json({ message: 'Government Roster header updated successfully' });
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


// GET /page-settings/govt-header — public
app.get('/page-settings/govt-header', (req, res) => {
  const defaultHeader = JSON.stringify({
    image_url: 'https://i.imgur.com/YfVF1d0.png',
    title: 'THE UNITED STATES OF PARAISO',
    subtitle: 'Official Government Directory',
    title_color: '#c9a84c',
    subtitle_color: '#b9bbbe',
    footer_quote: 'One Nation. One Government. One Paraiso.'
  });

  // Fetch the latest config based on update time to ignore old defaults
  db.query("SELECT content FROM page_contents WHERE page_key = 'govt-roster-header' ORDER BY updated_at DESC", (err, results) => {
    if (err) return res.status(500).json({ message: 'DB error', error: err });
    
    if (results && results.length > 0) {
      try {
        return res.json(JSON.parse(results[0].content));
      } catch {
        return res.json(JSON.parse(defaultHeader));
      }
    }

    // Seed default if database is empty
    db.query("INSERT INTO page_contents (page_key, content) VALUES ('govt-roster-header', ?)", [defaultHeader], (err2) => {
      if (err2) console.error("Error inserting default header:", err2);
      return res.json(JSON.parse(defaultHeader));
    });
  });
});

// ─── Server Info (Server IP, Discord URL & Status) ────────────────
app.get('/server-info', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const defaultInfo = {
    server_ip: 'Coming Soon...',
    discord_url: 'https://discord.gg/7AsJaG3KSV',
    status: 'online'
  };

  db.query("SELECT content FROM page_contents WHERE page_key = 'server-info' ORDER BY updated_at DESC LIMIT 1", (err, results) => {
    if (err) return res.json(defaultInfo);
    if (results && results.length > 0 && results[0].content) {
      try {
        const parsed = JSON.parse(results[0].content);
        return res.json({
          server_ip: parsed.server_ip || 'Coming Soon...',
          discord_url: parsed.discord_url || 'https://discord.gg/7AsJaG3KSV',
          status: parsed.status || 'online'
        });
      } catch {
        return res.json(defaultInfo);
      }
    }
    return res.json(defaultInfo);
  });
});

app.put('/server-info', verifyPermission('settings'), (req, res) => {

  const { server_ip, discord_url, status } = req.body;
  const infoJson = JSON.stringify({
    server_ip: server_ip || 'Coming Soon...',
    discord_url: discord_url || 'https://discord.gg/7AsJaG3KSV',
    status: status || 'online'
  });

  const createTableSql = `
    CREATE TABLE IF NOT EXISTS page_contents (
      page_key VARCHAR(100) PRIMARY KEY,
      content LONGTEXT NULL,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    );
  `;

  db.query(createTableSql, (err) => {
    if (err) {
      console.error("Error creating page_contents table in PUT /server-info:", err);
      return res.status(500).json({ message: 'Database error ensuring page_contents table', error: err });
    }

    // Clean existing duplicates & insert latest info
    db.query("DELETE FROM page_contents WHERE page_key = 'server-info'", (delErr) => {
      db.query("INSERT INTO page_contents (page_key, content) VALUES ('server-info', ?)", [infoJson], (err2) => {
        if (err2) {
          console.error("Error updating server info in DB:", err2);
          return res.status(500).json({ message: 'Failed to save server info', error: err2 });
        }
        res.json({ message: 'Server info updated successfully', server_ip, discord_url, status });
      });
    });
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
          url: "https://imgur.com/y9chPQI.png",
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


// ════════════════════════════════════════════════════════════
// DONATE CATEGORIES ENDPOINTS
// ════════════════════════════════════════════════════════════

// GET /donate-categories — public: list all categories with item counts
app.get('/donate-categories', (req, res) => {
  db.query(
    `SELECT c.*, COUNT(i.id) as item_count 
     FROM donate_categories c 
     LEFT JOIN donate_items i ON i.category_id = c.id AND i.is_active = 1
     GROUP BY c.id 
     ORDER BY c.sort_order ASC, c.id ASC`,
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Failed to fetch categories' });
      res.json(results);
    }
  );
});

// POST /donate-categories — admin: create category
app.post('/donate-categories', verifyPermission('donate'), (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ message: 'Category name is required' });
  db.query("SELECT MAX(sort_order) as maxOrder FROM donate_categories", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;
    db.query("INSERT INTO donate_categories (name, sort_order) VALUES (?, ?)", [name, nextOrder], (err2, result) => {
      if (err2) return res.status(500).json({ message: 'Failed to create category' });
      res.status(201).json({ message: 'Category created', id: result.insertId, name, sort_order: nextOrder });
    });
  });
});

// PUT /donate-categories/:id — admin: update category
app.put('/donate-categories/:id', verifyPermission('donate'), (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ message: 'Category name is required' });
  db.query("UPDATE donate_categories SET name = ? WHERE id = ?", [name, req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to update category' });
    res.json({ message: 'Category updated' });
  });
});

// DELETE /donate-categories/:id — admin: delete category
app.delete('/donate-categories/:id', verifyPermission('donate'), (req, res) => {
  db.query("DELETE FROM donate_categories WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete category' });
    res.json({ message: 'Category deleted' });
  });
});

// PUT /donate-categories/reorder — admin: reorder categories
app.put('/donate-categories-reorder', verifyPermission('donate'), (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders)) return res.status(400).json({ message: 'Invalid data' });
  if (orders.length === 0) return res.json({ message: 'Order updated' });
  let completed = 0;
  let hasError = false;
  orders.forEach((item) => {
    db.query("UPDATE donate_categories SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) { hasError = true; return res.status(500).json({ message: 'Failed to update order' }); }
      completed++;
      if (completed === orders.length && !hasError) res.json({ message: 'Categories reordered' });
    });
  });
});

// ════════════════════════════════════════════════════════════
// DONATE ITEMS ENDPOINTS
// ════════════════════════════════════════════════════════════

// GET /donate-items — public: list items (optional ?category_id= filter)
app.get('/donate-items', (req, res) => {
  const { category_id } = req.query;
  let sql = `SELECT i.*, c.name as category_name 
             FROM donate_items i 
             LEFT JOIN donate_categories c ON c.id = i.category_id 
             WHERE i.is_active = 1`;
  const params = [];
  if (category_id) {
    sql += ' AND i.category_id = ?';
    params.push(category_id);
  }
  sql += ' ORDER BY i.sort_order ASC, i.id DESC';
  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json({ message: 'Failed to fetch items' });
    res.json(results);
  });
});

// GET /donate-items/all — admin: list ALL items including inactive
app.get('/donate-items/all', verifyPermission('donate'), (req, res) => {
  db.query(
    `SELECT i.*, c.name as category_name 
     FROM donate_items i 
     LEFT JOIN donate_categories c ON c.id = i.category_id 
     ORDER BY i.sort_order ASC, i.id DESC`,
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Failed to fetch items' });
      res.json(results);
    }
  );
});

// GET /donate-items/:id — public: single item
app.get('/donate-items/:id', (req, res) => {
  db.query(
    `SELECT i.*, c.name as category_name 
     FROM donate_items i 
     LEFT JOIN donate_categories c ON c.id = i.category_id 
     WHERE i.id = ?`,
    [req.params.id],
    (err, results) => {
      if (err || results.length === 0) return res.status(404).json({ message: 'Item not found' });
      res.json(results[0]);
    }
  );
});

// Auto migrations for renewal_price & order_type
db.query("SHOW COLUMNS FROM donate_items LIKE 'renewal_price'", (err, rows) => {
  if (!err && rows && rows.length === 0) {
    db.query("ALTER TABLE donate_items ADD COLUMN renewal_price DECIMAL(10,2) DEFAULT NULL", (err2) => {
      if (!err2) console.log("Added renewal_price column to donate_items table.");
    });
  }
});
db.query("SHOW COLUMNS FROM purchase_tickets LIKE 'order_type'", (err, rows) => {
  if (!err && rows && rows.length === 0) {
    db.query("ALTER TABLE purchase_tickets ADD COLUMN order_type VARCHAR(20) DEFAULT 'new'", (err2) => {
      if (!err2) console.log("Added order_type column to purchase_tickets table.");
    });
  }
});
db.query("SHOW COLUMNS FROM email_otps LIKE 'type'", (err, rows) => {
  if (!err && rows && rows.length === 0) {
    db.query("ALTER TABLE email_otps ADD COLUMN type VARCHAR(30) DEFAULT 'registration'", (err2) => {
      if (!err2) console.log("Added type column to email_otps table.");
    });
  }
});

// POST /donate-items — admin: create item
app.post('/donate-items', verifyPermission('donate'), (req, res) => {
  const { category_id, name, description, image_url, price } = req.body;
  if (!category_id || !name) return res.status(400).json({ message: 'Category and name are required' });
  db.query("SELECT MAX(sort_order) as maxOrder FROM donate_items", (err, orderResult) => {
    const nextOrder = (orderResult && orderResult[0]?.maxOrder !== null) ? orderResult[0].maxOrder + 1 : 0;
    db.query(
      "INSERT INTO donate_items (category_id, name, description, image_url, price, sort_order) VALUES (?, ?, ?, ?, ?, ?)",
      [category_id, name, description || '', image_url || '', price || 0, nextOrder],
      (err2, result) => {
        if (err2) return res.status(500).json({ message: 'Failed to create item' });
        res.status(201).json({ message: 'Item created', id: result.insertId });
      }
    );
  });
});

// PUT /donate-items/:id — admin: update item
app.put('/donate-items/:id', verifyPermission('donate'), (req, res) => {
  const { category_id, name, description, image_url, price, is_active } = req.body;
  db.query(
    `UPDATE donate_items SET 
      category_id = COALESCE(?, category_id),
      name = COALESCE(?, name),
      description = COALESCE(?, description),
      image_url = COALESCE(?, image_url),
      price = COALESCE(?, price),
      is_active = COALESCE(?, is_active)
    WHERE id = ?`,
    [category_id, name, description, image_url, price, is_active, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ message: 'Failed to update item' });
      res.json({ message: 'Item updated' });
    }
  );
});

// DELETE /donate-items/:id — admin: delete item
app.delete('/donate-items/:id', verifyPermission('donate'), (req, res) => {
  db.query("DELETE FROM donate_items WHERE id = ?", [req.params.id], (err) => {
    if (err) return res.status(500).json({ message: 'Failed to delete item' });
    res.json({ message: 'Item deleted' });
  });
});

// PUT /donate-items-reorder — admin: reorder items
app.put('/donate-items-reorder', verifyPermission('donate'), (req, res) => {
  const { orders } = req.body;
  if (!Array.isArray(orders)) return res.status(400).json({ message: 'Invalid data' });
  if (orders.length === 0) return res.json({ message: 'Order updated' });
  let completed = 0;
  let hasError = false;
  orders.forEach((item) => {
    db.query("UPDATE donate_items SET sort_order = ? WHERE id = ?", [item.sort_order, item.id], (err) => {
      if (err && !hasError) { hasError = true; return res.status(500).json({ message: 'Failed to update order' }); }
      completed++;
      if (completed === orders.length && !hasError) res.json({ message: 'Items reordered' });
    });
  });
});


// PURCHASE TICKETS ENDPOINTS


// POST /tickets — authenticated user: create ticket
app.post('/tickets', verifyToken, (req, res) => {
  const { item_id, ingame_name, discord_username, quantity } = req.body;
  if (!item_id) return res.status(400).json({ message: 'Item ID is required' });
  if (!ingame_name || !ingame_name.trim()) return res.status(400).json({ message: 'Ingame Name is required' });
  if (!discord_username || !discord_username.trim()) return res.status(400).json({ message: 'Discord Username is required' });

  const qty = Math.max(1, parseInt(quantity) || 1);

  // Verify item exists
  db.query("SELECT id, name, price FROM donate_items WHERE id = ? AND is_active = 1", [item_id], (err, items) => {
    if (err || items.length === 0) return res.status(404).json({ message: 'Item not found or inactive' });

    const item = items[0];
    const unitPrice = parseFloat(item.price);
    const totalPrice = (unitPrice * qty).toFixed(2);

    db.query(
      "INSERT INTO purchase_tickets (user_id, item_id, ingame_name, discord_username, quantity) VALUES (?, ?, ?, ?, ?)",
      [req.user.id, item_id, ingame_name.trim(), discord_username.trim(), qty],
      (err2, result) => {
        if (err2) return res.status(500).json({ message: 'Failed to create ticket' });
        const ticketId = result.insertId;

        const autoMsg = `🛒 Purchase Request Details:\n• Ingame Name: ${ingame_name.trim()}\n• Discord Username: ${discord_username.trim()}\n• Item: ${item.name}\n• Unit Price: $${unitPrice.toFixed(2)}\n• Quantity: ${qty}\n• Total Price: $${totalPrice}`;

        db.query(
          "INSERT INTO ticket_messages (ticket_id, sender_id, message) VALUES (?, ?, ?)",
          [ticketId, req.user.id, autoMsg],
          () => {} // fire and forget
        );

        // Also insert first item into ticket_items table
        db.query(
          "INSERT INTO ticket_items (ticket_id, item_id, quantity) VALUES (?, ?, ?)",
          [ticketId, item_id, qty],
          () => {} // fire and forget
        );

        // Notify admins via Socket.IO
        if (global.io) {
          global.io.to('admin-tickets').emit('new-ticket', { id: ticketId, item: item, user_id: req.user.id });
        }

        // Send Email & In-App Notification to User
        createAndSendNotification({
          userId: req.user.id,
          title: 'Ticket Created Successfully',
          message: `Your purchase ticket for "${item.name}" has been created (#${ticketId}).`,
          link: `/my-tickets/${ticketId}`,
          emailSubject: `[Paraiso Gaming] Ticket #${ticketId} Opened - ${item.name}`,
          emailHtml: `
            <div style="font-family: Arial, sans-serif; background-color: #080d13; color: #ffffff; padding: 24px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
              <h2 style="color: #06b6d4; margin-top: 0;">Paraiso Gaming Support</h2>
              <p style="color: #cbd5e1;">Hello,</p>
              <p style="color: #cbd5e1;">Your purchase ticket for <strong>${item.name}</strong> (x${qty}) has been opened successfully.</p>
              <p style="color: #cbd5e1;">Ticket ID: <strong style="color: #06b6d4;">#${ticketId}</strong></p>
              <div style="margin-top: 24px; text-align: center;">
                <a href="${FRONTEND_BASE_URL}/my-tickets/${ticketId}" style="background-color: #06b6d4; color: #000000; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
                  View Ticket & Chat
                </a>
              </div>
              <p style="margin-top: 24px; color: #64748b; font-size: 12px; text-align: center;">Our staff team will review your request shortly.</p>
            </div>
          `
        });

        // Send Email & In-App Notification to All Eligible Admins (with tickets permission)
        notifyAllAdmins({
          title: `New Ticket #${ticketId}`,
          message: `New ticket created for "${item.name}" by ${ingame_name.trim()}`,
          link: `/dashboard/tickets?id=${ticketId}`,
          emailSubject: `[Paraiso Gaming Admin] New Ticket #${ticketId} - ${item.name}`,
          emailHtml: `
            <div style="font-family: Arial, sans-serif; background-color: #080d13; color: #ffffff; padding: 24px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
              <h2 style="color: #06b6d4; margin-top: 0;">New Ticket Created</h2>
              <p style="color: #cbd5e1;">A new purchase ticket has been submitted on Paraiso Gaming.</p>
              <p style="color: #cbd5e1;"><strong>Ticket ID:</strong> #${ticketId}</p>
              <p style="color: #cbd5e1;"><strong>Item:</strong> ${item.name} (x${qty})</p>
              <p style="color: #cbd5e1;"><strong>Ingame Name:</strong> ${ingame_name.trim()}</p>
              <p style="color: #cbd5e1;"><strong>Discord:</strong> ${discord_username.trim()}</p>
              <div style="margin-top: 24px; text-align: center;">
                <a href="${FRONTEND_BASE_URL}/dashboard/tickets?id=${ticketId}" style="background-color: #06b6d4; color: #000000; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
                  Open Admin Dashboard
                </a>
              </div>
            </div>
          `
        });

        res.status(201).json({ message: 'Ticket created', id: ticketId });
      }
    );
  });
});

// POST /tickets/:id/items — authenticated user: add another item to existing ticket
app.post('/tickets/:id/items', verifyToken, (req, res) => {
  const { item_id, quantity } = req.body;
  if (!item_id) return res.status(400).json({ message: 'Item ID is required' });
  const qty = Math.max(1, parseInt(quantity) || 1);

  // Verify ticket exists and user owns it
  db.query("SELECT * FROM purchase_tickets WHERE id = ?", [req.params.id], (err, tickets) => {
    if (err || tickets.length === 0) return res.status(404).json({ message: 'Ticket not found' });
    const ticket = tickets[0];

    if (ticket.user_id !== req.user.id) {
      return res.status(403).json({ message: 'You can only add items to your own tickets' });
    }
    if (ticket.status === 'closed') {
      return res.status(400).json({ message: 'Cannot add items to a closed ticket' });
    }

    // Verify item exists and is active
    db.query("SELECT id, name, price FROM donate_items WHERE id = ? AND is_active = 1", [item_id], (err2, items) => {
      if (err2 || items.length === 0) return res.status(404).json({ message: 'Item not found or inactive' });
      const item = items[0];
      const unitPrice = parseFloat(item.price);
      const totalPrice = (unitPrice * qty).toFixed(2);

      // Insert into ticket_items
      db.query(
        "INSERT INTO ticket_items (ticket_id, item_id, quantity) VALUES (?, ?, ?)",
        [req.params.id, item_id, qty],
        (err3, result) => {
          if (err3) return res.status(500).json({ message: 'Failed to add item' });

          // Auto-message in ticket chat
          const autoMsg = `➕ New Item Added to Ticket:\n• Item: ${item.name}\n• Unit Price: $${unitPrice.toFixed(2)}\n• Quantity: ${qty}\n• Subtotal: $${totalPrice}`;
          db.query(
            "INSERT INTO ticket_messages (ticket_id, sender_id, message) VALUES (?, ?, ?)",
            [req.params.id, req.user.id, autoMsg],
            (msgErr, msgResult) => {
              // Broadcast new message via socket
              if (!msgErr && global.io) {
                db.query("SELECT username, role FROM users WHERE id = ?", [req.user.id], (uErr, uRes) => {
                  const senderName = (!uErr && uRes && uRes.length > 0) ? uRes[0].username : 'Unknown';
                  const senderRole = (!uErr && uRes && uRes.length > 0) ? uRes[0].role : 'user';
                  global.io.to(`ticket-${req.params.id}`).emit('new-message', {
                    id: msgResult.insertId,
                    ticket_id: parseInt(req.params.id),
                    sender_id: req.user.id,
                    sender_name: senderName,
                    sender_role: senderRole,
                    message: autoMsg,
                    created_at: new Date().toISOString()
                  });
                });
              }
            }
          );

          // Emit socket event for item added
          if (global.io) {
            global.io.to(`ticket-${req.params.id}`).emit('ticket-item-added', {
              ticketId: parseInt(req.params.id),
              item: { ...item, quantity: qty }
            });
            global.io.to('admin-tickets').emit('ticket-item-added', {
              ticketId: parseInt(req.params.id),
              item: { ...item, quantity: qty }
            });
          }

          // Notify assigned admin or all admins
          const notifData = {
            title: `Item Added to Ticket #${req.params.id}`,
            message: `"${item.name}" (x${qty}) was added to Ticket #${req.params.id}`,
            link: `/dashboard/tickets?id=${req.params.id}`,
            emailSubject: `[Paraiso Gaming Admin] Item Added to Ticket #${req.params.id}`,
            emailHtml: `
              <div style="font-family: Arial, sans-serif; background-color: #080d13; color: #ffffff; padding: 24px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
                <h2 style="color: #06b6d4; margin-top: 0;">Item Added to Ticket</h2>
                <p style="color: #cbd5e1;">A new item has been added to <strong>Ticket #${req.params.id}</strong>.</p>
                <p style="color: #cbd5e1;"><strong>Item:</strong> ${item.name} (x${qty})</p>
                <p style="color: #cbd5e1;"><strong>Subtotal:</strong> $${totalPrice}</p>
                <div style="margin-top: 24px; text-align: center;">
                  <a href="${FRONTEND_BASE_URL}/dashboard/tickets?id=${req.params.id}" style="background-color: #06b6d4; color: #000000; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">View Ticket</a>
                </div>
              </div>
            `
          };

          if (ticket.assigned_admin_id) {
            createAndSendNotification({ userId: ticket.assigned_admin_id, ...notifData });
          } else {
            notifyAllAdmins(notifData);
          }

          res.status(201).json({ message: 'Item added to ticket', id: result.insertId, item_name: item.name });
        }
      );
    });
  });
});

// PUT /tickets/:ticketId/items/:itemId — edit item quantity or item in ticket
app.put('/tickets/:ticketId/items/:itemId', verifyToken, (req, res) => {
  const { quantity, item_id } = req.body;
  const newQty = Math.max(1, parseInt(quantity) || 1);
  const ticketId = req.params.ticketId;
  const ticketItemId = req.params.itemId;

  db.query("SELECT * FROM purchase_tickets WHERE id = ?", [ticketId], (err, tickets) => {
    if (err || tickets.length === 0) return res.status(404).json({ message: 'Ticket not found' });
    const ticket = tickets[0];
    const isOwner = ticket.user_id === req.user.id;
    const isAdmin = req.user.role === 'admin' || req.user.role === 'master';

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ message: 'Access denied' });
    }
    if (ticket.status === 'closed') {
      return res.status(400).json({ message: 'Cannot modify items on a closed ticket' });
    }

    db.query("SELECT ti.*, di.name as old_name FROM ticket_items ti LEFT JOIN donate_items di ON di.id = ti.item_id WHERE ti.id = ? AND ti.ticket_id = ?", [ticketItemId, ticketId], (err2, tiRows) => {
      if (err2 || tiRows.length === 0) return res.status(404).json({ message: 'Ticket item not found' });
      const currentTi = tiRows[0];
      const targetItemId = item_id ? parseInt(item_id) : currentTi.item_id;

      db.query("SELECT id, name, price FROM donate_items WHERE id = ?", [targetItemId], (err3, diRows) => {
        if (err3 || diRows.length === 0) return res.status(404).json({ message: 'Store item not found' });
        const newItem = diRows[0];

        db.query(
          "UPDATE ticket_items SET item_id = ?, quantity = ? WHERE id = ?",
          [targetItemId, newQty, ticketItemId],
          (err4) => {
            if (err4) return res.status(500).json({ message: 'Failed to update ticket item' });

            const autoMsg = `✏️ Ticket Item Updated:\n• Item: ${newItem.name}\n• Quantity: ${newQty}\n• Subtotal: $${(parseFloat(newItem.price) * newQty).toFixed(2)}`;
            const msgPattern = `✏️ Ticket Item Updated:\n• Item: ${newItem.name}%`;

            db.query(
              "SELECT id FROM ticket_messages WHERE ticket_id = ? AND message LIKE ? ORDER BY id DESC LIMIT 1",
              [ticketId, msgPattern],
              (findErr, findRows) => {
                if (!findErr && findRows && findRows.length > 0) {
                  const existingMsgId = findRows[0].id;
                  db.query(
                    "UPDATE ticket_messages SET message = ? WHERE id = ?",
                    [autoMsg, existingMsgId],
                    () => {
                      if (global.io) {
                        global.io.to(`ticket-${ticketId}`).emit('ticket-item-updated', { ticketId: parseInt(ticketId), itemId: ticketItemId });
                        global.io.to('admin-tickets').emit('ticket-item-updated', { ticketId: parseInt(ticketId), itemId: ticketItemId });
                      }
                    }
                  );
                } else {
                  db.query("INSERT INTO ticket_messages (ticket_id, sender_id, message) VALUES (?, ?, ?)", [ticketId, req.user.id, autoMsg], (mErr, mRes) => {
                    if (!mErr && global.io) {
                      db.query("SELECT username, role FROM users WHERE id = ?", [req.user.id], (uErr, uRes) => {
                        const senderName = (!uErr && uRes && uRes.length > 0) ? uRes[0].username : 'Unknown';
                        const senderRole = (!uErr && uRes && uRes.length > 0) ? uRes[0].role : 'user';
                        global.io.to(`ticket-${ticketId}`).emit('new-message', {
                          id: mRes.insertId,
                          ticket_id: parseInt(ticketId),
                          sender_id: req.user.id,
                          sender_name: senderName,
                          sender_role: senderRole,
                          message: autoMsg,
                          created_at: new Date().toISOString()
                        });
                      });
                    }
                    if (global.io) {
                      global.io.to(`ticket-${ticketId}`).emit('ticket-item-updated', { ticketId: parseInt(ticketId), itemId: ticketItemId });
                      global.io.to('admin-tickets').emit('ticket-item-updated', { ticketId: parseInt(ticketId), itemId: ticketItemId });
                    }
                  });
                }
              }
            );

            res.json({ message: 'Ticket item updated successfully' });
          }
        );
      });
    });
  });
});

// DELETE /tickets/:ticketId/items/:itemId — remove item from ticket
app.delete('/tickets/:ticketId/items/:itemId', verifyToken, (req, res) => {
  const ticketId = req.params.ticketId;
  const ticketItemId = req.params.itemId;

  db.query("SELECT * FROM purchase_tickets WHERE id = ?", [ticketId], (err, tickets) => {
    if (err || tickets.length === 0) return res.status(404).json({ message: 'Ticket not found' });
    const ticket = tickets[0];
    const isOwner = ticket.user_id === req.user.id;
    const isAdmin = req.user.role === 'admin' || req.user.role === 'master';

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ message: 'Access denied' });
    }
    if (ticket.status === 'closed') {
      return res.status(400).json({ message: 'Cannot modify items on a closed ticket' });
    }

    db.query("SELECT ti.*, di.name as item_name FROM ticket_items ti LEFT JOIN donate_items di ON di.id = ti.item_id WHERE ti.ticket_id = ?", [ticketId], (err2, items) => {
      if (err2 || items.length === 0) return res.status(404).json({ message: 'No items in ticket' });
      if (items.length <= 1) {
        return res.status(400).json({ message: 'A ticket must have at least one item' });
      }

      const targetItem = items.find(i => i.id == ticketItemId);
      if (!targetItem) return res.status(404).json({ message: 'Item not found in ticket' });

      db.query("DELETE FROM ticket_items WHERE id = ?", [ticketItemId], (err3) => {
        if (err3) return res.status(500).json({ message: 'Failed to remove item' });

        if (global.io) {
          global.io.to(`ticket-${ticketId}`).emit('ticket-item-deleted', { ticketId: parseInt(ticketId), itemId: ticketItemId });
          global.io.to('admin-tickets').emit('ticket-item-deleted', { ticketId: parseInt(ticketId), itemId: ticketItemId });
        }

        res.json({ message: 'Item removed from ticket' });
      });
    });
  });
});

// GET /tickets/:id/items — get all items for a ticket
app.get('/tickets/:id/items', verifyToken, (req, res) => {
  // Verify access
  db.query("SELECT user_id FROM purchase_tickets WHERE id = ?", [req.params.id], (err, tResults) => {
    if (err || tResults.length === 0) return res.status(404).json({ message: 'Ticket not found' });
    if (tResults[0].user_id !== req.user.id && req.user.role !== 'admin' && req.user.role !== 'master') {
      // Check admin permission
      return db.query("SELECT 1 FROM admin_permissions WHERE user_id = ? AND permission_key = 'tickets'", [req.user.id], (err2, permRows) => {
        if (err2 || !permRows || permRows.length === 0) {
          return res.status(403).json({ message: 'Access denied' });
        }
        fetchTicketItems();
      });
    }
    fetchTicketItems();
  });

  function fetchTicketItems() {
    db.query(
      `SELECT ti.*, di.name as item_name, di.price as item_price, di.image_url as item_image, di.description as item_description
       FROM ticket_items ti
       LEFT JOIN donate_items di ON di.id = ti.item_id
       WHERE ti.ticket_id = ?
       ORDER BY ti.added_at ASC`,
      [req.params.id],
      (err2, results) => {
        if (err2) return res.status(500).json({ message: 'Failed to fetch ticket items' });
        if (results.length === 0) {
          db.query("SELECT item_id, quantity FROM purchase_tickets WHERE id = ?", [req.params.id], (err3, pRes) => {
            if (!err3 && pRes && pRes.length > 0 && pRes[0].item_id) {
              db.query("INSERT INTO ticket_items (ticket_id, item_id, quantity) VALUES (?, ?, ?)", [req.params.id, pRes[0].item_id, pRes[0].quantity || 1], () => {
                db.query(
                  `SELECT ti.*, di.name as item_name, di.price as item_price, di.image_url as item_image, di.description as item_description
                   FROM ticket_items ti
                   LEFT JOIN donate_items di ON di.id = ti.item_id
                   WHERE ti.ticket_id = ?
                   ORDER BY ti.added_at ASC`,
                  [req.params.id],
                  (err4, resSync) => res.json(resSync || [])
                );
              });
            } else {
              res.json([]);
            }
          });
        } else {
          res.json(results);
        }
      }
    );
  }
});

// GET /tickets — list tickets (master & global permission admins get all, assigned admins get assigned tickets)
app.get('/tickets', verifyToken, (req, res) => {
  const { status } = req.query;

  db.query("SELECT role FROM users WHERE id = ?", [req.user.id], (err, userRows) => {
    if (err || !userRows || userRows.length === 0) {
      return res.status(403).json({ message: 'Access denied' });
    }
    const userRole = userRows[0].role;
    req.user.role = userRole;

    db.query("SELECT 1 FROM admin_permissions WHERE user_id = ? AND permission_key = 'tickets'", [req.user.id], (err2, permRows) => {
      const hasGlobalPermission = userRole === 'master' || (!err2 && permRows && permRows.length > 0);

      let sql = `SELECT t.*, 
        u.username as user_name, u.email as user_email,
        i.name as item_name, i.price as item_price, i.image_url as item_image,
        a.username as admin_name
        FROM purchase_tickets t
        LEFT JOIN users u ON u.id = t.user_id
        LEFT JOIN donate_items i ON i.id = t.item_id
        LEFT JOIN users a ON a.id = t.assigned_admin_id`;
      
      const conditions = [];
      const params = [];

      if (!hasGlobalPermission) {
        // Scoped Admin/User: only see tickets specifically assigned to them
        conditions.push('t.assigned_admin_id = ?');
        params.push(req.user.id);
      }

      if (status) {
        conditions.push('t.status = ?');
        params.push(status);
      }

      if (conditions.length > 0) {
        sql += ' WHERE ' + conditions.join(' AND ');
      }

      sql += ' ORDER BY t.created_at DESC';
      db.query(sql, params, (err3, results) => {
        if (err3) return res.status(500).json({ message: 'Failed to fetch tickets' });
        res.json(results);
      });
    });
  });
});

// GET /tickets/my — authenticated user: list own tickets
app.get('/tickets/my', verifyToken, (req, res) => {
  db.query(
    `SELECT t.*, 
      i.name as item_name, i.price as item_price, i.image_url as item_image,
      a.username as admin_name,
      (SELECT COUNT(*) FROM ticket_items ti WHERE ti.ticket_id = t.id) as item_count
      FROM purchase_tickets t
      LEFT JOIN donate_items i ON i.id = t.item_id
      LEFT JOIN users a ON a.id = t.assigned_admin_id
      WHERE t.user_id = ?
      ORDER BY t.created_at DESC`,
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Failed to fetch your tickets' });
      res.json(results);
    }
  );
});

// GET /tickets/:id — admin or ticket owner or assigned admin
app.get('/tickets/:id', verifyToken, (req, res) => {
  db.query(
    `SELECT t.*, 
      u.username as user_name, u.email as user_email,
      i.name as item_name, i.price as item_price, i.image_url as item_image, i.description as item_description,
      a.username as admin_name
      FROM purchase_tickets t
      LEFT JOIN users u ON u.id = t.user_id
      LEFT JOIN donate_items i ON i.id = t.item_id
      LEFT JOIN users a ON a.id = t.assigned_admin_id
      WHERE t.id = ?`,
    [req.params.id],
    (err, results) => {
      if (err || results.length === 0) return res.status(404).json({ message: 'Ticket not found' });
      const ticket = results[0];

      // Master admin, ticket owner, or assigned admin can view
      if (req.user.role === 'master' || ticket.user_id === req.user.id || ticket.assigned_admin_id === req.user.id) {
        return res.json(ticket);
      }

      // Check if admin has global tickets permission
      db.query("SELECT 1 FROM admin_permissions WHERE user_id = ? AND permission_key = 'tickets'", [req.user.id], (err2, permRows) => {
        const hasGlobalPermission = !err2 && permRows && permRows.length > 0;
        if (hasGlobalPermission) {
          return res.json(ticket);
        }
        return res.status(403).json({ message: 'Access denied. You can only view tickets assigned to you.' });
      });
    }
  );
});

// PUT /tickets/:id/claim — admin: self-claim a ticket
app.put('/tickets/:id/claim', verifyToken, (req, res) => {
  db.query(
    "UPDATE purchase_tickets SET status = 'claimed', assigned_admin_id = ? WHERE id = ? AND status = 'open'",
    [req.user.id, req.params.id],
    (err, result) => {
      if (err) return res.status(500).json({ message: 'Failed to claim ticket' });
      if (result.affectedRows === 0) return res.status(400).json({ message: 'Ticket already claimed or not found' });
      
      if (global.io) {
        global.io.to(`ticket-${req.params.id}`).emit('ticket-updated', { id: req.params.id, status: 'claimed', assigned_admin_id: req.user.id });
        global.io.to('admin-tickets').emit('ticket-updated', { id: req.params.id, status: 'claimed' });
      }

      // Notify ticket owner that staff has claimed ticket
      db.query("SELECT user_id FROM purchase_tickets WHERE id = ?", [req.params.id], (tErr, tRes) => {
        if (!tErr && tRes && tRes.length > 0) {
          db.query("SELECT username FROM users WHERE id = ?", [req.user.id], (uErr, uRes) => {
            const staffName = (!uErr && uRes && uRes.length > 0) ? uRes[0].username : (req.user.username || 'Staff');
            createAndSendNotification({
              userId: tRes[0].user_id,
              title: `Ticket #${req.params.id} Claimed`,
              message: `Claimed by ${staffName}. They are now assisting you with your ticket.`,
              link: `/my-tickets/${req.params.id}`,
              emailSubject: `[Paraiso Gaming] Ticket #${req.params.id} Claimed by ${staffName}`,
              emailHtml: `
                <div style="font-family: Arial, sans-serif; background-color: #080d13; color: #ffffff; padding: 24px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
                  <h2 style="color: #06b6d4; margin-top: 0;">Ticket Claimed</h2>
                  <p style="color: #cbd5e1;">Staff member <strong>${staffName}</strong> has claimed your ticket <strong>#${req.params.id}</strong> and is now assisting you.</p>
                  <div style="margin-top: 24px; text-align: center;">
                    <a href="${FRONTEND_BASE_URL}/my-tickets/${req.params.id}" style="background-color: #06b6d4; color: #000000; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
                      Open Ticket & Chat
                    </a>
                  </div>
                </div>
              `
            });
          });
        }
      });

      res.json({ message: 'Ticket claimed' });
    }
  );
});

// PUT /tickets/:id/assign — assign ticket to another admin (Master Admin only)
app.put('/tickets/:id/assign', verifyMaster, (req, res) => {
  const { admin_id } = req.body;
  if (!admin_id) return res.status(400).json({ message: 'Admin ID is required' });
  db.query(
    "UPDATE purchase_tickets SET status = 'claimed', assigned_admin_id = ? WHERE id = ?",
    [admin_id, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ message: 'Failed to assign ticket' });
      db.query("UPDATE users SET role = 'admin' WHERE id = ? AND role = 'user'", [admin_id], () => {});

      if (global.io) {
        global.io.to(`ticket-${req.params.id}`).emit('ticket-updated', { id: req.params.id, status: 'claimed', assigned_admin_id: admin_id });
        global.io.to('admin-tickets').emit('ticket-updated', { id: req.params.id, status: 'claimed' });
      }

      // Notify newly assigned admin
      createAndSendNotification({
        userId: admin_id,
        title: `Ticket #${req.params.id} Assigned to You`,
        message: `You have been assigned to handle Ticket #${req.params.id}.`,
        link: `/dashboard/tickets?id=${req.params.id}`,
        emailSubject: `[Paraiso Gaming Admin] Ticket #${req.params.id} Assigned to You`,
        emailHtml: `
          <div style="font-family: Arial, sans-serif; background-color: #080d13; color: #ffffff; padding: 24px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
            <h2 style="color: #06b6d4; margin-top: 0;">Ticket Assignment</h2>
            <p style="color: #cbd5e1;">Hello Admin,</p>
            <p style="color: #cbd5e1;">You have been assigned to manage Ticket <strong>#${req.params.id}</strong>.</p>
            <div style="margin-top: 24px; text-align: center;">
              <a href="${FRONTEND_BASE_URL}/dashboard/tickets?id=${req.params.id}" style="background-color: #06b6d4; color: #000000; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
                View Assigned Ticket
              </a>
            </div>
          </div>
        `
      });

      res.json({ message: 'Ticket assigned' });
    }
  );
});

// PUT /tickets/:id/close — admin only: close ticket
app.put('/tickets/:id/close', verifyToken, verifyPermission('tickets'), (req, res) => {
  db.query("UPDATE purchase_tickets SET status = 'closed' WHERE id = ?", [req.params.id], (err2) => {
    if (err2) return res.status(500).json({ message: 'Failed to close ticket' });
    if (global.io) {
      global.io.to(`ticket-${req.params.id}`).emit('ticket-updated', { id: req.params.id, status: 'closed' });
      global.io.to('admin-tickets').emit('ticket-updated', { id: req.params.id, status: 'closed' });
    }
    res.json({ message: 'Ticket closed' });
  });
});

// PUT /tickets/:id/reopen — ticket owner or admin: reopen ticket
app.put('/tickets/:id/reopen', verifyToken, (req, res) => {
  db.query("SELECT user_id, assigned_admin_id FROM purchase_tickets WHERE id = ?", [req.params.id], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ message: 'Ticket not found' });
    const isOwner = results[0].user_id === req.user.id;
    const isAdmin = req.user.role === 'admin' || req.user.role === 'master' || (req.user.permissions && req.user.permissions.includes('tickets'));

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const newStatus = results[0].assigned_admin_id ? 'claimed' : 'open';
    db.query("UPDATE purchase_tickets SET status = ? WHERE id = ?", [newStatus, req.params.id], (err2) => {
      if (err2) return res.status(500).json({ message: 'Failed to reopen ticket' });
      if (global.io) {
        global.io.to(`ticket-${req.params.id}`).emit('ticket-updated', { id: req.params.id, status: newStatus });
        global.io.to('admin-tickets').emit('ticket-updated', { id: req.params.id, status: newStatus });
      }
      res.json({ message: 'Ticket reopened', status: newStatus });
    });
  });
});

// DELETE /tickets/:id — admin or master admin: delete ticket
app.delete('/tickets/:id', verifyToken, (req, res) => {
  db.query("SELECT role FROM users WHERE id = ?", [req.user.id], (err, userRes) => {
    const dbRole = userRes && userRes.length > 0 ? userRes[0].role : req.user.role;
    if (dbRole !== 'admin' && dbRole !== 'master') {
      return res.status(403).json({ message: 'Access denied. Only admins can delete tickets.' });
    }

    const ticketId = parseInt(req.params.id, 10);
    db.query("DELETE FROM purchase_tickets WHERE id = ?", [ticketId], (err2, result) => {
      if (err2) return res.status(500).json({ message: 'Failed to delete ticket' });
      if (result.affectedRows === 0) return res.status(404).json({ message: 'Ticket not found' });

      // Delete all notifications linked to this ticket from DB
      db.query(
        "DELETE FROM notifications WHERE link REGEXP ? OR link REGEXP ? OR title REGEXP ?",
        [
          `[?&]id=${ticketId}([&]|$)`,
          `/my-tickets/${ticketId}(/|$)`,
          `#${ticketId}([^0-9]|$)`
        ],
        (notifErr) => {
          if (notifErr) console.error("Error deleting notifications for ticket:", notifErr);
        }
      );

      if (global.io) {
        global.io.emit('ticket-deleted', { id: ticketId });
        global.io.to('admin-tickets').emit('ticket-updated', { id: ticketId });
      }
      res.json({ message: 'Ticket deleted successfully' });
    });
  });
});

// GET /tickets/:id/messages — get all messages for a ticket
app.get('/tickets/:id/messages', verifyToken, (req, res) => {
  // First verify access
  db.query("SELECT user_id FROM purchase_tickets WHERE id = ?", [req.params.id], (err, tResults) => {
    if (err || tResults.length === 0) return res.status(404).json({ message: 'Ticket not found' });
    if (tResults[0].user_id !== req.user.id && req.user.role !== 'admin' && req.user.role !== 'master') {
      return res.status(403).json({ message: 'Access denied' });
    }
    db.query(
      `SELECT m.*, u.username as sender_name, u.role as sender_role
       FROM ticket_messages m
       LEFT JOIN users u ON u.id = m.sender_id
       WHERE m.ticket_id = ?
       ORDER BY m.created_at ASC`,
      [req.params.id],
      (err2, results) => {
        if (err2) return res.status(500).json({ message: 'Failed to fetch messages' });
        res.json(results);
      }
    );
  });
});

// POST /tickets/:id/messages — add message
app.post('/tickets/:id/messages', verifyToken, (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) return res.status(400).json({ message: 'Message is required' });
  
  // Verify access
  db.query("SELECT user_id, assigned_admin_id, status FROM purchase_tickets WHERE id = ?", [req.params.id], (err, tResults) => {
    if (err || tResults.length === 0) return res.status(404).json({ message: 'Ticket not found' });
    const ticketOwnerId = tResults[0].user_id;
    const assignedAdminId = tResults[0].assigned_admin_id;

    if (ticketOwnerId !== req.user.id && req.user.role !== 'admin' && req.user.role !== 'master') {
      return res.status(403).json({ message: 'Access denied' });
    }
    const isSenderStaff = req.user.role === 'admin' || req.user.role === 'master';
    if (tResults[0].status === 'closed') {
      return res.status(400).json({ message: 'Cannot send messages on a closed ticket' });
    }
    if (tResults[0].status === 'open' && isSenderStaff) {
      return res.status(400).json({ message: 'You must claim or assign this ticket before sending messages.' });
    }
    
    db.query(
      "INSERT INTO ticket_messages (ticket_id, sender_id, message) VALUES (?, ?, ?)",
      [req.params.id, req.user.id, message.trim()],
      (err2, result) => {
        if (err2) return res.status(500).json({ message: 'Failed to send message' });
        
        const msgData = {
          id: result.insertId,
          ticket_id: parseInt(req.params.id),
          sender_id: req.user.id,
          sender_name: req.user.username || 'Unknown',
          sender_role: req.user.role,
          message: message.trim(),
          created_at: new Date().toISOString()
        };
        
        // We need the username — fetch it
        db.query("SELECT username, role FROM users WHERE id = ?", [req.user.id], (err3, uResults) => {
          if (!err3 && uResults.length > 0) {
            msgData.sender_name = uResults[0].username;
            msgData.sender_role = uResults[0].role;
          }
          // Broadcast via Socket.IO
          if (global.io) {
            global.io.to(`ticket-${req.params.id}`).emit('new-message', msgData);
          }

          // Trigger Notification
          const isSenderStaff = req.user.role === 'admin' || req.user.role === 'master';
          const trimmedMsg = message.trim().slice(0, 60) + (message.trim().length > 60 ? '...' : '');

          if (isSenderStaff) {
            // Staff replied -> notify ticket owner via email only (skip in-app notification dropdown)
            if (ticketOwnerId !== req.user.id) {
              createAndSendNotification({
                userId: ticketOwnerId,
                title: `New Staff Reply on Ticket #${req.params.id}`,
                message: `${msgData.sender_name}: "${trimmedMsg}"`,
                link: `/my-tickets/${req.params.id}`,
                emailSubject: `[Paraiso Gaming] New Reply on Ticket #${req.params.id}`,
                emailHtml: `
                  <div style="font-family: Arial, sans-serif; background-color: #080d13; color: #ffffff; padding: 24px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
                    <h2 style="color: #06b6d4; margin-top: 0;">New Staff Response</h2>
                    <p style="color: #cbd5e1;"><strong>${msgData.sender_name}</strong> replied on your Ticket <strong>#${req.params.id}</strong>:</p>
                    <blockquote style="background-color: #0d1117; padding: 12px; border-left: 4px solid #06b6d4; color: #cbd5e1; border-radius: 6px;">
                      ${message.trim()}
                    </blockquote>
                    <div style="margin-top: 24px; text-align: center;">
                      <a href="${FRONTEND_BASE_URL}/my-tickets/${req.params.id}" style="background-color: #06b6d4; color: #000000; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
                        View & Reply to Ticket
                      </a>
                    </div>
                  </div>
                `,
                skipInApp: true
              });
            }
          } else {
            // User replied -> notify assigned admin or all admins with tickets permission
            if (assignedAdminId) {
              createAndSendNotification({
                userId: assignedAdminId,
                title: `New User Reply on Ticket #${req.params.id}`,
                message: `${msgData.sender_name}: "${trimmedMsg}"`,
                link: `/dashboard/tickets?id=${req.params.id}`,
                emailSubject: `[Paraiso Gaming Admin] New Message on Ticket #${req.params.id}`,
                emailHtml: `
                  <div style="font-family: Arial, sans-serif; background-color: #080d13; color: #ffffff; padding: 24px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
                    <h2 style="color: #06b6d4; margin-top: 0;">New User Reply</h2>
                    <p style="color: #cbd5e1;"><strong>${msgData.sender_name}</strong> replied on Ticket <strong>#${req.params.id}</strong>:</p>
                    <blockquote style="background-color: #0d1117; padding: 12px; border-left: 4px solid #06b6d4; color: #cbd5e1; border-radius: 6px;">
                      ${message.trim()}
                    </blockquote>
                    <div style="margin-top: 24px; text-align: center;">
                      <a href="${FRONTEND_BASE_URL}/dashboard/tickets?id=${req.params.id}" style="background-color: #06b6d4; color: #000000; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
                        Open Admin Dashboard
                      </a>
                    </div>
                  </div>
                `
              });
            } else {
              notifyAllAdmins({
                title: `New User Reply on Ticket #${req.params.id}`,
                message: `${msgData.sender_name}: "${trimmedMsg}"`,
                link: `/dashboard/tickets?id=${req.params.id}`,
                emailSubject: `[Paraiso Gaming Admin] New Message on Ticket #${req.params.id}`,
                emailHtml: `
                  <div style="font-family: Arial, sans-serif; background-color: #080d13; color: #ffffff; padding: 24px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
                    <h2 style="color: #06b6d4; margin-top: 0;">New User Reply</h2>
                    <p style="color: #cbd5e1;"><strong>${msgData.sender_name}</strong> replied on Ticket <strong>#${req.params.id}</strong>:</p>
                    <blockquote style="background-color: #0d1117; padding: 12px; border-left: 4px solid #06b6d4; color: #cbd5e1; border-radius: 6px;">
                      ${message.trim()}
                    </blockquote>
                    <div style="margin-top: 24px; text-align: center;">
                      <a href="${FRONTEND_BASE_URL}/dashboard/tickets?id=${req.params.id}" style="background-color: #06b6d4; color: #000000; font-weight: bold; text-decoration: none; padding: 12px 24px; border-radius: 8px; display: inline-block;">
                        Open Admin Dashboard
                      </a>
                    </div>
                  </div>
                `
              });
            }
          }

          res.status(201).json(msgData);
        });
      }
    );
  });
});

// DELETE /tickets/:ticketId/messages/:messageId — delete chat message
app.delete('/tickets/:ticketId/messages/:messageId', verifyToken, (req, res) => {
  const { ticketId, messageId } = req.params;

  db.query(
    "SELECT m.*, t.user_id as ticket_owner_id FROM ticket_messages m LEFT JOIN purchase_tickets t ON t.id = m.ticket_id WHERE m.id = ? AND m.ticket_id = ?",
    [messageId, ticketId],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: 'Message not found' });
      }
      const msg = results[0];
      const isSender = msg.sender_id === req.user.id;
      const isOwner = msg.ticket_owner_id === req.user.id;
      const isAdmin = req.user.role === 'admin' || req.user.role === 'master';

      if (!isSender && !isOwner && !isAdmin) {
        return res.status(403).json({ message: 'Access denied. You cannot delete this message.' });
      }

      db.query("DELETE FROM ticket_messages WHERE id = ?", [messageId], (err2) => {
        if (err2) return res.status(500).json({ message: 'Failed to delete message' });

        if (global.io) {
          global.io.to(`ticket-${ticketId}`).emit('message-deleted', {
            messageId: parseInt(messageId),
            ticketId: parseInt(ticketId)
          });
        }

        res.json({ message: 'Message deleted successfully' });
      });
    }
  );
});

// ─── NOTIFICATION API ENDPOINTS ──────────────────────────────
// GET /notifications — get user notifications
app.get('/notifications', verifyToken, (req, res) => {
  db.query(
    "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 30",
    [req.user.id],
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Failed to fetch notifications' });
      db.query(
        "SELECT COUNT(*) as unreadCount FROM notifications WHERE user_id = ? AND is_read = 0",
        [req.user.id],
        (err2, countRes) => {
          const unreadCount = (!err2 && countRes && countRes[0]) ? countRes[0].unreadCount : 0;
          res.json({ notifications: results, unreadCount });
        }
      );
    }
  );
});

// PUT /notifications/:id/read — mark single notification read
app.put('/notifications/:id/read', verifyToken, (req, res) => {
  db.query(
    "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
    [req.params.id, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ message: 'Failed to update notification' });
      res.json({ message: 'Marked as read' });
    }
  );
});

// PUT /notifications/read-all — mark all notifications read
app.put('/notifications/read-all', verifyToken, (req, res) => {
  db.query(
    "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
    [req.user.id],
    (err) => {
      if (err) return res.status(500).json({ message: 'Failed to update notifications' });
      res.json({ message: 'All marked as read' });
    }
  );
});

// GET /admins — list admin/master users (for ticket assignment dropdown)
app.get('/admins', verifyPermission('tickets'), (req, res) => {
  db.query(
    "SELECT id, username, email, role FROM users WHERE role IN ('admin', 'master') ORDER BY username ASC",
    (err, results) => {
      if (err) return res.status(500).json({ message: 'Failed to fetch admins' });
      res.json(results);
    }
  );
});

// ─── HELPER: Verify SA-MP Player Password ─────────────────
async function verifySampPassword(inputPassword, storedHash, salt = '', username = '', playerObj = null) {
  if (!storedHash || !inputPassword) return false;
  
  const cleanStored = storedHash.trim();
  const cleanInput = inputPassword.trim();
  const cleanSalt = (salt || '').toString().trim();
  const cleanUser = (username || '').toString().trim();
  const userNoUnderscore = cleanUser.replace(/_/g, ' ').trim();
  const userFirstPart = cleanUser.split('_')[0] || cleanUser;

  // 1. Direct plain text match
  if (cleanInput === cleanStored || cleanInput.toLowerCase() === cleanStored.toLowerCase()) return true;

  // 2. bcrypt
  if (cleanStored.startsWith('$2a$') || cleanStored.startsWith('$2b$') || cleanStored.startsWith('$2y$')) {
    try {
      return await bcrypt.compare(cleanInput, cleanStored);
    } catch {
      return false;
    }
  }

  // Helpers
  const sha256 = (str) => crypto.createHash('sha256').update(str).digest('hex').toLowerCase();
  const sha512 = (str) => crypto.createHash('sha512').update(str).digest('hex').toLowerCase();
  const md5 = (str) => crypto.createHash('md5').update(str).digest('hex').toLowerCase();
  
  const getWhirlpool = (str) => {
    const results = [];
    let wpPackage = null;
    try {
      const pkg = require('whirlpool-js');
      wpPackage = (pkg && pkg.encSync) ? pkg : (pkg && pkg.default && pkg.default.encSync ? pkg.default : pkg);
    } catch {}

    const variations = [str, str + '\0', str + '\r\n', str + '\n'];

    for (const v of variations) {
      if (wpPackage && typeof wpPackage.encSync === 'function') {
        try {
          results.push(wpPackage.encSync(v, 'hex').toLowerCase());
        } catch {}
      }
      try {
        results.push(crypto.createHash('whirlpool').update(v).digest('hex').toLowerCase());
      } catch {}
      try {
        results.push(whirlpoolHelper(v).toLowerCase());
      } catch {}
      try {
        results.push(whirlpoolHelper(Buffer.from(v, 'latin1')).toLowerCase());
      } catch {}
    }
    return results;
  };

  const targetHash = cleanStored.toLowerCase();

  const candidateInputs = [
    cleanInput,
    cleanInput + cleanSalt,
    cleanSalt + cleanInput,
    cleanInput + cleanUser,
    cleanUser + cleanInput,
    cleanUser.toLowerCase() + cleanInput,
    cleanInput + cleanUser.toLowerCase(),
    cleanUser.toUpperCase() + cleanInput,
    cleanInput + cleanUser.toUpperCase(),
    userNoUnderscore + cleanInput,
    cleanInput + userNoUnderscore,
    userFirstPart + cleanInput,
    cleanInput + userFirstPart,
    cleanInput.toLowerCase(),
    cleanInput.toUpperCase(),
    cleanInput.toLowerCase() + cleanSalt,
    cleanSalt + cleanInput.toLowerCase(),
    cleanInput.toUpperCase() + cleanSalt,
    cleanSalt + cleanInput.toUpperCase(),
    cleanInput + "paraiso",
    "paraiso" + cleanInput,
    cleanInput + "samp",
    "samp" + cleanInput,
    cleanInput + "pgaming",
    cleanInput + "southcentral",
    cleanInput + "horizon",
    cleanInput + "westcoast",
    cleanInput + "roleplay"
  ];

  if (playerObj) {
    if (playerObj.ID) {
      candidateInputs.push(cleanInput + playerObj.ID, playerObj.ID + cleanInput);
    }
    if (playerObj.Key || playerObj.pKey) {
      const k = String(playerObj.Key || playerObj.pKey);
      candidateInputs.push(cleanInput + k, k + cleanInput);
    }
    if (playerObj.Salt || playerObj.salt) {
      const s = String(playerObj.Salt || playerObj.salt);
      candidateInputs.push(cleanInput + s, s + cleanInput);
    }
  }

  for (const cand of candidateInputs) {
    if (sha256(cand) === targetHash) return true;
    if (md5(cand) === targetHash) return true;
    if (sha512(cand) === targetHash) return true;

    const wpHashes = getWhirlpool(cand);
    for (const w of wpHashes) {
      if (w === targetHash) {
        return true;
      }
      if (sha256(w) === targetHash) {
        return true;
      }
      if (md5(w) === targetHash) return true;

      // Double whirlpool check
      const doubleWp = getWhirlpool(w);
      for (const dw of doubleWp) {
        if (dw === targetHash) {
          return true;
        }
      }
    }
  }

  return false;
}

const UCP_JWT_SECRET = process.env.JWT_SECRET || 'paraiso_ucp_secret_key_2026';

// UCP Active Logged-in Devices Session Tracker
const ucpActiveSessions = new Map();

// ─── Middleware: verifyUcpToken ────────────────────────────
function verifyUcpToken(req, res, next) {
  let token = req.cookies.ucp_token;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  }
  if (!token) return res.status(401).json({ message: 'UCP authentication required' });

  const secretsToTry = [
    UCP_JWT_SECRET,
    process.env.JWT_SECRET,
    'paraiso_ucp_secret_key_2026',
    'default_secret'
  ].filter(Boolean);

  let verifiedUser = null;
  for (const sec of secretsToTry) {
    try {
      verifiedUser = jwt.verify(token, sec);
      break;
    } catch {
      
    }
  }

  if (verifiedUser) {
    const pId = verifiedUser.ucpPlayerId || verifiedUser.id;
    const sessId = verifiedUser.sessionId;
    if (pId && sessId && ucpActiveSessions.has(pId)) {
      const activeList = ucpActiveSessions.get(pId) || [];
      const isStillActive = activeList.some(s => s.sessionId === sessId);
      if (!isStillActive) {
        return res.status(401).json({ message: 'This device session has been logged out/revoked.' });
      }
    }

    req.ucpUser = verifiedUser;
    return next();
  }

  return res.status(403).json({ message: 'Invalid or expired UCP session' });
}

function parseUserAgent(ua) {
  if (!ua) return { browser: 'Browser', os: 'Desktop OS', deviceType: 'Desktop' };
  let browser = 'Chrome';
  if (ua.includes('Edg/')) browser = 'Microsoft Edge';
  else if (ua.includes('OPR/') || ua.includes('Opera')) browser = 'Opera';
  else if (ua.includes('Chrome/')) browser = 'Google Chrome';
  else if (ua.includes('Safari/') && !ua.includes('Chrome')) browser = 'Safari';
  else if (ua.includes('Firefox/')) browser = 'Mozilla Firefox';

  let os = 'Windows';
  if (ua.includes('Win')) os = 'Windows OS';
  else if (ua.includes('Mac')) os = 'macOS';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS (Apple)';
  else if (ua.includes('Android')) os = 'Android OS';
  else if (ua.includes('Linux')) os = 'Linux OS';

  const isMobile = ua.includes('Mobile') || ua.includes('Android') || ua.includes('iPhone');
  const deviceType = isMobile ? 'Mobile' : 'Desktop';

  return { browser, os, deviceType };
}

// ─── POST /api/ucp/login (SA-MP Player Login) ─────────────
app.post('/api/ucp/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'SA-MP character username and password are required.' });
    }

    const cleanUsername = username.trim();

    sampDb.query(
      "SELECT * FROM players WHERE Username = ? LIMIT 1",
      [cleanUsername],
      async (err, results) => {
        if (err) {
          console.error("SA-MP DB Login Error:", err);
          return res.status(500).json({ message: "Something went wrong." });
        }

        if (!results || results.length === 0) {
          return res.status(404).json({ message: `No character found with username "${cleanUsername}".` });
        }

        const player = results[0];

        // Check if player is permabanned or banned
        if (player.Banned === 1 || player.Permabanned === 1) {
          return res.status(403).json({ message: "This character account is currently banned from the server." });
        }

        const salt = player.Salt || player.salt || player.Key || player.KeyHash || player.password_salt || player.pKey || player.PassKey || player.pSalt || player.SaltKey || player.HashKey || player.Secret || player.hash || '';
        const isMatch = await verifySampPassword(password, player.Password, salt, player.Username, player);

        if (!isMatch) {
          return res.status(401).json({ message: "Password is not matched. Please enter your valid IG password." });
        }

        const userAgentStr = req.headers['user-agent'] || '';
        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
        const parsedUa = parseUserAgent(userAgentStr);
        const sessionId = 'sess_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);

        const newSession = {
          sessionId,
          browser: parsedUa.browser,
          os: parsedUa.os,
          deviceType: parsedUa.deviceType,
          ip: clientIp.includes('::1') || clientIp.includes('127.0.0.1') ? '127.0.0.1 (Localhost)' : clientIp,
          loginTime: new Date().toISOString(),
          lastActive: new Date().toISOString()
        };

        if (!ucpActiveSessions.has(player.ID)) {
          ucpActiveSessions.set(player.ID, []);
        }
        const pSessions = ucpActiveSessions.get(player.ID);
        pSessions.unshift(newSession);
        if (pSessions.length > 10) pSessions.pop();

        const rawAdminLevel = Number(player.AdminLevel || player.Admin || player.pAdmin || player.LevelAdmin || 0);

        const ucpPayload = {
          ucpPlayerId: player.ID,
          id: player.ID,
          username: player.Username,
          sessionId,
          isSampUser: true,
          adminLevel: rawAdminLevel
        };

        const token = jwt.sign(ucpPayload, UCP_JWT_SECRET, { expiresIn: '7d' });
        res.cookie('ucp_token', token, cookieOptions);

        res.json({
          message: `Welcome to UCP, ${player.Username}!`,
          token,
          user: {
            id: player.ID,
            username: player.Username,
            level: player.Level || 1,
            skin: player.Skin || 0,
            adminLevel: player.AdminLevel || 0,
            donator: player.Donator || 0
          }
        });
      }
    );
  } catch (err) {
    console.error("UCP LOGIN CRASH:", err);
    res.status(500).json({ message: err.message || "Internal server error during UCP login." });
  }
});

// ─── GET /api/ucp/me (Check active UCP Session) ───────────
app.get('/api/ucp/me', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT ID, Username, Level, Skin, AdminLevel, Donator FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Character account not found." });
      }
      const player = results[0];
      res.json({
        user: {
          id: player.ID,
          username: player.Username,
          level: player.Level || 1,
          skin: player.Skin || 0,
          adminLevel: player.AdminLevel || 0,
          donator: player.Donator || 0
        }
      });
    }
  );
});

// ─── UCP DATA SANITIZER (Strict Canonical UI Properties Only) ───
function sanitizePlayerForUcp(player) {
  if (!player || typeof player !== 'object') return {};

  return {
    ID: player.ID,
    Username: player.Username,
    Level: Number(player.Level || 1),
    Skin: Number(player.Skin || 0),
    Donator: Number(player.Donator || player.pDonator || player.VIP || player.VIPLevel || player.pVIP || 0),
    DonatorTime: player.DonatorTime ?? player.DonatorDate ?? player.DonatorExp ?? player.DonatorExpire ?? player.DonatorExpiration ?? player.VIPTime ?? player.VIPDate ?? player.VIPExp ?? player.VIPExpire ?? player.DTime ?? player.DDate ?? player.DonationDate ?? player.DonationTime ?? player.DonationExp ?? player.pDonatorTime ?? player.pVIPTime ?? player.DonateTime ?? player.DonateDate ?? player.DonateExp ?? player.pVipTime ?? player.pVipExp ?? player.pVIPExp ?? player.VIP_Date ?? player.VIP_Time ?? player.VIP_Expire ?? player.Donator_Time ?? player.Donator_Date ?? player.VIP_Days ?? player.DonatorDays ?? player.pDonatorDays ?? player.pVIPDays ?? player.VIPDays ?? null,
    Respect: Number(player.Respect || 0),
    HoursPlayed: Number(player.HoursPlayed || 0),
    ConnectTime: Number(player.ConnectTime || 0),
    Age: Number(player.Age || 0),
    Sex: Number(player.Sex ?? player.Gender ?? 0),
    Health: Number(player.Health ?? player.pHealth ?? 100),
    Armor: Number(player.Armor ?? player.Armour ?? player.SpawnArmor ?? player.pArmor ?? player.pArmour ?? 0),
    PhoneNumber: player.PhoneNumber ? Number(player.PhoneNumber) : 0,
    Member: Number(player.Member || 0),
    Leader: Number(player.Leader || 0),
    Faction: Number(player.Faction || 0),
    Gang: Number(player.Gang || 0),
    GangLeader: Number(player.GangLeader || 0),
    Rank: Number(player.Rank || 0),
    Job: Number(player.Job || 0),
    Job2: Number(player.Job2 || 0),
    MarriedTo: player.MarriedTo || player.Married || 'Nobody',
    LastLogin: player.LastLogin || player.LastConnect || null,
    Online: Number(player.Online || 0),
    AdminLevel: Number(player.AdminLevel || player.Admin || player.pAdmin || player.LevelAdmin || 0)
  };
}

// ─── GET /api/ucp/stats (Fast Main Character Stats) ────────
app.get('/api/ucp/stats', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT * FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Character statistics not found." });
      }

      const player = results[0];
      delete player.Password;
      delete player.Salt;
      delete player.LastIP;

      const sanitizedStats = sanitizePlayerForUcp(player);
      res.json({ stats: sanitizedStats });
    }
  );
});

// ─── GET /api/ucp/vehicles (On-Demand Owned Vehicles) ──────
app.get('/api/ucp/vehicles', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT ID, Online FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Player not found." });
      }
      const player = results[0];
      const isPlayerOffline = !player.Online || Number(player.Online) === 0;

      sampDb.query(
        "SELECT * FROM playervehicles WHERE Owner = ?",
        [player.ID],
        (errV, vehicles) => {
          if (errV) {
            console.error("Error fetching vehicles:", errV);
            return res.status(500).json({ message: "Database query error." });
          }

          if (isPlayerOffline && player.ID) {
            sampDb.query(
              "UPDATE playervehicles SET Spawned = 0 WHERE Owner = ? AND Spawned = 1",
              [player.ID],
              () => {}
            );
          }

          const sanitizedVehicles = (vehicles || []).map((v, i) => {
            const modelId = Number(v.ModelID ?? v.Model ?? v.model ?? v.pvModel ?? v.pvModelID ?? v.pvModelId ?? v.ModelId ?? v.Vehicle ?? v.vModel ?? v.cModel ?? v.v_model ?? v.c_model ?? 400);
            const idVal = v.ID ?? v.id ?? v.pvID ?? v.pvId ?? v.vID ?? v.vId ?? v.cID ?? (i + 1);
            return {
              id: idVal,
              ModelID: modelId,
              Price: Number(v.Price || v.price || 0),
              Locked: Number(v.Locked || v.Lock || 0),
              Impound: Number(v.Impound || v.impound || 0),
              Spawned: isPlayerOffline ? 0 : Number(v.Spawned || 0),
              Location: v.Location || v.location || '',
              PosX: Number(v.PosX ?? v.pos_x ?? v.X ?? 0),
              PosY: Number(v.PosY ?? v.pos_y ?? v.Y ?? 0),
              PosZ: Number(v.PosZ ?? v.pos_z ?? v.Z ?? 0)
            };
          });

          res.json({ vehicles: sanitizedVehicles });
        }
      );
    }
  );
});

// ─── GET /api/ucp/properties (On-Demand Houses & Businesses) ────
app.get('/api/ucp/properties', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT ID, Username FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Player not found." });
      }
      const player = results[0];
      const pIdStr = String(player.ID);
      const pNameLower = String(player.Username).toLowerCase();

      sampDb.query("SELECT * FROM houses", (errH, allHouses) => {
        const playerHouses = (allHouses || []).filter(h => {
          const isOwner = String(h.owner_id || h.OwnerID || h.Owner_ID || h.owner || h.Owner || h.hOwner || '') === pIdStr ||
                          String(h.owner || h.Owner || h.hOwner || '').toLowerCase() === pNameLower;
          if (isOwner) return true;
          const keyCols = ['key1', 'key2', 'key3', 'key4', 'key5', 'Key1', 'Key2', 'Key3', 'Key4', 'Key5', 'hKey1', 'hKey2', 'hKey3'];
          for (const k of keyCols) {
            const val = String(h[k] || '').toLowerCase();
            if (val === pNameLower || val === pIdStr) return true;
          }
          if (h.keys || h.housekeys || h.shared_keys) {
            const keysArr = String(h.keys || h.housekeys || h.shared_keys || '').toLowerCase().split(',').map(s => s.trim());
            if (keysArr.includes(pNameLower) || keysArr.includes(pIdStr)) return true;
          }
          return false;
        });

        sampDb.query("SELECT * FROM businesses", (errB, allBusinesses) => {
          const playerBusinesses = (allBusinesses || []).filter(b => {
            return String(b.owner_id || b.OwnerID || b.Owner_ID || b.owner || b.Owner || b.bOwner || '') === pIdStr ||
                   String(b.owner || b.Owner || b.bOwner || '').toLowerCase() === pNameLower;
          });

          const sanitizedHouses = playerHouses.map((h, i) => ({
            id: h.id ?? h.ID ?? h.houseid ?? i,
            owner: h.owner || h.Owner || h.hOwner || 'State',
            price: Number(h.price || h.hPrice || 0),
            rent_fee: Number(h.rent_fee || h.rent || h.hRent || 0),
            rentable: Number(h.rentable || h.hRentable || 0),
            locked: Number(h.locked || h.Lock || h.hLocked || 0),
            safe_money: Number(h.safe_money || h.money || h.safe || 0),
            materials: Number(h.materials || 0),
            level: Number(h.level || h.hLevel || 1),
            gun1: h.gun1 || h.Gun1 || h.weapon1 || h.Weapon1 || 0,
            gun2: h.gun2 || h.Gun2 || h.weapon2 || h.Weapon2 || 0,
            gun3: h.gun3 || h.Gun3 || h.weapon3 || h.Weapon3 || 0
          }));

          const sanitizedBusinesses = playerBusinesses.map((b, i) => ({
            id: (b.id !== undefined && b.id !== null) ? b.id : ((b.ID !== undefined && b.ID !== null) ? b.ID : (b.bizzid || b.BizzID || b.bID || i)),
            name: b.bName || b.bizz_name || b.bizzName || b.StoreName || b.store_name || b.bTitle || b.Title || b.name || b.Name || b.interior_text || `Business #${i}`,
            owner: b.owner || b.Owner || b.bOwner || 'State',
            price: Number(b.price || b.Price || 0),
            safe: Number(b.safe || b.Safe || b.money || b.Till || 0),
            products: Number(b.products || b.Products || 0),
            locked: Number(b.locked || b.Lock || b.bLocked || 0),
            level: Number(b.level || b.Level || 1),
            message: b.message || b.Message || b.bMessage || b.interior_text || ''
          }));

          res.json({ houses: sanitizedHouses, businesses: sanitizedBusinesses });
        });
      });
    }
  );
});

// ─── GET /api/ucp/faction-roster (On-Demand Faction Members) ───
app.get('/api/ucp/faction-roster', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT Member, Leader, Faction FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Player not found." });
      }

      const player = results[0];
      const officialFactionIds = [1, 2, 3, 4, 5, 9];
      const rawId = Number(player.Member || player.Leader || player.Faction || 0);

      if (!officialFactionIds.includes(rawId)) {
        return res.json({ factionMembers: [] });
      }

      sampDb.query(
        "SELECT ID, Username, `Rank`, Leader, Online, Level FROM players WHERE Member = ? OR Leader = ? OR Faction = ? ORDER BY Leader DESC, `Rank` DESC, Username ASC",
        [rawId, rawId, rawId],
        (errFM, fMembers) => {
          if (errFM) console.error("Error fetching faction members:", errFM);
          const sanitized = (!errFM && fMembers) ? fMembers.map(m => ({
            ID: m.ID,
            Username: m.Username,
            Rank: Number(m.Rank || 0),
            Leader: Number(m.Leader || 0),
            Level: Number(m.Level || 1),
            Online: Number(m.Online || 0)
          })) : [];
          res.json({ factionMembers: sanitized });
        }
      );
    }
  );
});

// ─── GET /api/ucp/gang-roster (On-Demand Family/Gang Members) ───
app.get('/api/ucp/gang-roster', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT Member, Leader, Faction, Gang FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Player not found." });
      }

      const player = results[0];
      const familyGangIds = [6, 7, 8, 10, 11, 12, 13];
      const rawId = Number(player.Member || player.Leader || player.Faction || 0);
      const rawGangCol = Number(player.Gang || 0);

      let gangId = 0;
      if (familyGangIds.includes(rawId)) {
        gangId = rawId;
      }
      if (!gangId && rawGangCol > 0 && rawGangCol !== 255) {
        gangId = rawGangCol;
      }

      if (gangId === 0 || gangId === 255) {
        return res.json({ gangMembers: [] });
      }

      sampDb.query(
        "SELECT ID, Username, `Rank`, Leader, Online, Level FROM players WHERE Member = ? OR Leader = ? OR Faction = ? OR Gang = ? ORDER BY Leader DESC, `Rank` DESC, Username ASC",
        [gangId, gangId, gangId, gangId],
        (errGM, gMembers) => {
          if (errGM) console.error("Error fetching gang members:", errGM);
          const sanitized = (!errGM && gMembers) ? gMembers.map(m => ({
            ID: m.ID,
            Username: m.Username,
            Rank: Number(m.Rank || 0),
            Leader: Number(m.Leader || 0),
            Level: Number(m.Level || 1),
            Online: Number(m.Online || 0)
          })) : [];
          res.json({ gangMembers: sanitized });
        }
      );
    }
  );
});

// ─── GET /api/ucp/inventory (On-Demand Carried Weapons & Inventory Items) ───
app.get('/api/ucp/inventory', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT * FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Player not found." });
      }

      const player = results[0];

      // Parse carried weapons
      const weapons = [];
      for (let s = 0; s <= 12; s++) {
        const gunId = Number(player[`Gun${s}`] ?? player[`gun${s}`] ?? player[`Weapon${s}`] ?? 0);
        const ammo = Number(player[`Ammo${s}`] ?? player[`ammo${s}`] ?? 0);
        if (gunId > 0) {
          weapons.push({ slot: s, id: gunId, ammo: ammo });
        }
      }

      res.json({
        weapons,
        inventory: {
          Rope: Number(player.Rope ?? player.rope ?? 0),
          Cigars: Number(player.Cigars ?? player.Cigar ?? player.cigars ?? 0),
          Sprunk: Number(player.Sprunk ?? player.sprunk ?? 0),
          Spraycan: Number(player.Spraycan ?? player.Spray ?? player.spraycan ?? 0),
          Seeds: Number(player.Seeds ?? player.Seed ?? player.seeds ?? 0),
          Screwdriver: Number(player.Screwdriver ?? player.screwdriver ?? 0),
          Wristwatch: Number(player.Wristwatch ?? player.Watch ?? player.wristwatch ?? 0),
          Tires: Number(player.Tires ?? player.Tire ?? player.tire ?? 0),
          FirstAid: Number(player.FirstAid ?? player.Firstaid ?? player.firstaid ?? 0),
          RCCam: Number(player.RCCam ?? player.Rccam ?? player.rccam ?? 0),
          Receiver: Number(player.Receiver ?? player.receiver ?? 0),
          GPS: Number(player.GPS ?? player.Gps ?? player.gps ?? 0),
          BugSweep: Number(player.BugSweep ?? player.Bugsweep ?? player.bugsweep ?? 0),
          Lockpick: Number(player.Lockpick ?? player.Lockpicks ?? player.lockpick ?? 0),
          RimKit: Number(player.RimKit ?? player.Rimkit ?? player.rimkit ?? 0),
          Materials: Number(player.Materials || 0),
          Crack: Number(player.Crack || 0),
          Pot: Number(player.Pot || 0),
          WeaponCrates: Number(player.WeaponCrates || 0),
          DoubleExpToken: Number(player.DoubleExpToken || 0),
          Boombox: Number(player.Boombox || 0),
          Mp3: Number(player.Mp3 || 0),
          Phonebook: Number(player.Phonebook || 0)
        }
      });
    }
  );
});


app.get('/api/ucp/skills', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT * FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Player not found." });
      }

      const player = results[0];

      res.json({
        skills: {
          CarSkill: Number(player.CarSkill || 0),
          TruckSkill: Number(player.TruckSkill || 0),
          MaterialsSkill: Number(player.MaterialsSkill || 0),
          ArmsSkill: Number(player.ArmsSkill || 0),
          MechSkill: Number(player.MechSkill || 0),
          LawyerSkill: Number(player.LawyerSkill || 0),
          DrugsSkill: Number(player.DrugsSkill || 0),
          DetectiveSkill: Number(player.DetectiveSkill || 0),
          BoxerSkill: Number(player.BoxerSkill || 0),
          DetSkill: Number(player.DetSkill || player.DetectiveSkill || 0),
          LawSkill: Number(player.LawSkill || player.LawyerSkill || 0),
          SexSkill: Number(player.SexSkill || player.WhoreSkill || 0),
          SmugglerSkill: Number(player.SmugglerSkill || 0)
        }
      });
    }
  );
});


app.get('/api/ucp/finances', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT Cash, Bank FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        return res.status(404).json({ message: "Player not found." });
      }

      const player = results[0];
      const cash = Number(player.Cash ?? player.pMoney ?? player.Money ?? 0);
      const bank = Number(player.Bank ?? player.pBank ?? 0);

      res.json({
        finances: {
          Cash: cash,
          Bank: bank,
          TotalWealth: cash + bank
        }
      });
    }
  );
});

// ─── GET /api/ucp/sessions (On-Demand Active Device Sessions) ───
app.get('/api/ucp/sessions', verifyUcpToken, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const currentSessionId = req.ucpUser ? req.ucpUser.sessionId : null;
  const rawSessions = ucpActiveSessions.get(playerId) || [];

  let pSessions = rawSessions.map(s => ({
    ...s,
    isCurrent: s.sessionId === currentSessionId
  }));

  if (pSessions.length === 0) {
    const userAgentStr = req.headers['user-agent'] || '';
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    const parsedUa = parseUserAgent(userAgentStr);
    pSessions.push({
      sessionId: currentSessionId || 'sess_current',
      browser: parsedUa.browser,
      os: parsedUa.os,
      deviceType: parsedUa.deviceType,
      ip: clientIp.includes('::1') || clientIp.includes('127.0.0.1') ? '127.0.0.1 (Localhost)' : clientIp,
      loginTime: new Date().toISOString(),
      lastActive: new Date().toISOString(),
      isCurrent: true
    });
  }

  res.json({ activeSessions: pSessions });
});

// ─── POST /api/ucp/sessions/revoke-others (Revoke all other active devices) ────
app.post('/api/ucp/sessions/revoke-others', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const currentSessionId = req.ucpUser.sessionId;

  if (ucpActiveSessions.has(playerId)) {
    const pSessions = ucpActiveSessions.get(playerId);
    const updated = pSessions.filter(s => s.sessionId === currentSessionId);
    ucpActiveSessions.set(playerId, updated);
  }

  res.json({ message: "Successfully logged out all other active device sessions." });
});

// ─── POST /api/ucp/sessions/revoke-one (Revoke a single specific device session) ────
app.post('/api/ucp/sessions/revoke-one', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const { sessionId } = req.body;

  if (!sessionId) {
    return res.status(400).json({ message: "Session ID is required." });
  }

  if (ucpActiveSessions.has(playerId)) {
    const pSessions = ucpActiveSessions.get(playerId);
    const updated = pSessions.filter(s => s.sessionId !== sessionId);
    ucpActiveSessions.set(playerId, updated);
  }

  res.json({ message: "Device session removed successfully." });
});

// ─── MIDDLEWARE: Verify In-Game Admin Level ──────────────────
const verifyIgAdmin = (req, res, next) => {
  // Check JWT first (available after re-login)
  const jwtAdminLevel = Number(req.ucpUser.adminLevel || 0);
  if (jwtAdminLevel > 0) {
    req.igAdminLevel = jwtAdminLevel;
    return next();
  }

  // Fallback: DB lookup with SELECT * to catch any column name
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;

  sampDb.query(
    "SELECT * FROM players WHERE ID = ? OR Username = ? LIMIT 1",
    [playerId, username],
    (err, results) => {
      if (err || !results || results.length === 0) {
        console.warn("[verifyIgAdmin] DB lookup failed:", err?.message);
        return res.status(403).json({ message: "Access denied. Player record not found." });
      }
      const p = results[0];

      // Log all keys so we can see the real column name in the server console
      const allKeys = Object.keys(p);
      const adminKeys = allKeys.filter(k => /admin/i.test(k));
      console.log("[verifyIgAdmin] Admin-related columns found:", adminKeys.map(k => `${k}=${p[k]}`).join(', '));

      // Try every possible variant
      let adminLvl = 0;
      for (const key of adminKeys) {
        const val = Number(p[key] || 0);
        if (val > adminLvl) adminLvl = val;
      }
      // Also check explicit known names just in case
      adminLvl = Math.max(
        adminLvl,
        Number(p.AdminLevel || p.Admin || p.pAdmin || p.LevelAdmin || p.adminLevel || p.admin_level || 0)
      );

      console.log("[verifyIgAdmin] Resolved admin level:", adminLvl, "for player:", username);

      if (adminLvl <= 0) {
        return res.status(403).json({ message: "Access denied. In-Game Admin privileges required." });
      }
      req.igAdminLevel = adminLvl;
      next();
    }
  );
};

// ─── GET /api/ucp/admin/online-players (IG Admin Online Player List) ────
app.get('/api/ucp/admin/online-players', verifyUcpToken, verifyIgAdmin, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');

  const search = (req.query.search || '').trim();

  const doQuery = (sql, params, cb) => sampDb.query(sql, params, cb);

  const buildSanitized = (players) => (players || []).map(p => ({
    id: Number(p.ID || p.id || 0),
    username: p.Username || p.username || p.name || 'Unknown',
    level: Number(p.Level || p.pLevel || 1),
    health: Number(p.Health || p.pHealth || 100),
    armor: Number(p.Armor || p.pArmor || 0),
    adminLevel: Number(p.AdminLevel || p.Admin || p.pAdmin || p.LevelAdmin || 0),
    faction: Number(p.Member || p.Leader || p.Faction || 0),
    online: Number(p.Online || 0),
    lastLogin: p.LastLogin || p.LastConnect || null,
    connectTime: Number(p.ConnectTime || 0)
  }));

  if (search) {
    doQuery(
      "SELECT * FROM players WHERE Username LIKE ? OR ID = ? ORDER BY LastLogin DESC LIMIT 100",
      [`%${search}%`, Number(search) || 0],
      (err, players) => {
        if (err) {
          console.error("[online-players] Search query error:", err.message);
          return res.status(500).json({ message: "Search query failed: " + err.message });
        }
        res.json({ onlinePlayers: buildSanitized(players), totalPlayers: (players || []).length });
      }
    );
  } else {
    doQuery(
      "SELECT * FROM players ORDER BY Online DESC, LastLogin DESC LIMIT 200",
      [],
      (err, players) => {
        if (err) {
          console.error("[online-players] Query error:", err.message);
          return res.status(500).json({ message: "Query failed: " + err.message });
        }
        res.json({ onlinePlayers: buildSanitized(players), totalPlayers: (players || []).length });
      }
    );
  }
});

// ─── GET /api/ucp/admin/bans (IG Admin Ban & Locked Accounts List) ──────
app.get('/api/ucp/admin/bans', verifyUcpToken, verifyIgAdmin, (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  sampDb.query(
    "SELECT ID, Username, Level, AdminLevel, Banned, Permabanned, Warnings, WarningsCount FROM players WHERE Banned > 0 OR Permabanned > 0 OR Warnings > 0 OR WarningsCount > 0 ORDER BY Username ASC LIMIT 100",
    (err, bannedPlayers) => {
      if (err) {
        // Fallback search
        sampDb.query(
          "SELECT ID, Username, Level, AdminLevel FROM players WHERE Banned > 0 LIMIT 100",
          (err2, fallback) => {
            res.json({ bannedPlayers: fallback || [] });
          }
        );
      } else {
        const sanitized = (bannedPlayers || []).map(b => ({
          id: b.ID,
          username: b.Username,
          level: Number(b.Level || 1),
          adminLevel: Number(b.AdminLevel || 0),
          banned: Number(b.Banned || b.Permabanned || 0) > 0,
          warnings: Number(b.Warnings || b.WarningsCount || 0)
        }));
        res.json({ bannedPlayers: sanitized });
      }
    }
  );
});

// ─── POST /api/ucp/admin/action (Execute IG Admin Command) ─────────────
app.post('/api/ucp/admin/action', verifyUcpToken, verifyIgAdmin, (req, res) => {
  const { action, targetId, targetUsername, reason, value } = req.body;

  if (!action) {
    return res.status(400).json({ message: "Admin action is required." });
  }

  const queryTarget = targetId ? "ID = ?" : "Username = ?";
  const queryParam = targetId || targetUsername;

  if (!queryParam) {
    return res.status(400).json({ message: "Target player ID or Username is required." });
  }

  // Level requirements for actions matching IG Pawn script
  const levelReqs = {
    'warn': 1,
    'kick': 2,
    'setvw': 2,
    'setint': 2,
    'setskin': 2,
    'revive': 2,
    'freeze': 2,
    'unfreeze': 2,
    'ban': 2,
    'sethp': 3,
    'setarmor': 3,
    'unban': 3,
    'setadmin': 5
  };

  const minLevel = levelReqs[action.toLowerCase()] || 2;
  if (req.igAdminLevel < minLevel) {
    return res.status(403).json({ message: `Required In-Game Admin Level ${minLevel}+ for action '${action}'.` });
  }

  let updateFields = "";
  let queryArgs = [];

  switch (action.toLowerCase()) {
    case 'warn':
      updateFields = "Warnings = COALESCE(Warnings, 0) + 1";
      break;
    case 'kick':
      updateFields = "Online = 0";
      break;
    case 'ban':
      updateFields = "Banned = 1, Online = 0";
      break;
    case 'unban':
      updateFields = "Banned = 0";
      break;
    case 'sethp':
      updateFields = "Health = ?";
      queryArgs.push(Number(value || 100));
      break;
    case 'setarmor':
      updateFields = "Armor = ?";
      queryArgs.push(Number(value || 100));
      break;
    case 'setvw':
      updateFields = "VirtualWorld = ?";
      queryArgs.push(Number(value || 0));
      break;
    case 'setint':
      updateFields = "Interior = ?";
      queryArgs.push(Number(value || 0));
      break;
    case 'setskin':
      updateFields = "Skin = ?";
      queryArgs.push(Number(value || 0));
      break;
    case 'revive':
      updateFields = "Health = 100";
      break;
    case 'freeze':
    case 'unfreeze':
      updateFields = "Health = Health"; // Marker
      break;
    case 'setadmin':
      updateFields = "AdminLevel = ?";
      queryArgs.push(Number(value || 0));
      break;
    default:
      return res.status(400).json({ message: "Unsupported admin action." });
  }

  queryArgs.push(queryParam);

  sampDb.query(
    `UPDATE players SET ${updateFields} WHERE ${queryTarget}`,
    queryArgs,
    (err, result) => {
      if (err) {
        console.error("Error executing IG admin action:", err);
        return res.status(500).json({ message: "Failed to execute admin action in database." });
      }
      res.json({
        success: true,
        message: `Admin action '${action.toUpperCase()}' successfully executed for ${targetUsername || ('ID #' + targetId)}.`
      });
    }
  );
});

// ─── HOUSE & BUSINESS LOOKUP HELPERS ─────────────────────────
const findHouseInDb = (houseId, username, playerId, callback) => {
  sampDb.query("SELECT * FROM houses", (err, houses) => {
    if (err || !houses || houses.length === 0) return callback(err, null);
    const house = houses.find((h, idx) => {
      return String(h.id) === String(houseId) ||
             String(h.ID) === String(houseId) ||
             String(h.houseid) === String(houseId) ||
             String(h.HouseID) === String(houseId) ||
             String(h.hID) === String(houseId) ||
             String(idx) === String(houseId);
    }) || houses.find(h => 
      String(h.owner_id || h.OwnerID || h.owner || h.Owner || '').toLowerCase() === String(playerId).toLowerCase() ||
      String(h.owner || h.Owner || '').toLowerCase() === String(username).toLowerCase()
    ) || houses[0];
    callback(null, house);
  });
};

const findBusinessInDb = (businessId, username, playerId, callback) => {
  sampDb.query("SELECT * FROM businesses", (err, businesses) => {
    if (err || !businesses || businesses.length === 0) return callback(err, null);
    console.log("🏢 LOOKUP BUSINESSES COUNT:", businesses.length);
    if (businesses[0]) {
      console.log("🏢 BUSINESS DB KEYS:", Object.keys(businesses[0]));
    }
    const bizz = businesses.find((b, idx) => {
      return String(b.id) === String(businessId) ||
             String(b.ID) === String(businessId) ||
             String(b.bizzid) === String(businessId) ||
             String(b.BizzID) === String(businessId) ||
             String(b.bID) === String(businessId) ||
             String(b.bizz_id) === String(businessId) ||
             String(idx) === String(businessId);
    }) || businesses.find(b => 
      String(b.owner_id || b.OwnerID || b.owner || b.Owner || b.bOwner || '').toLowerCase() === String(playerId).toLowerCase() ||
      String(b.owner || b.Owner || b.bOwner || '').toLowerCase() === String(username).toLowerCase()
    ) || businesses[0];

    callback(null, bizz);
  });
};

// ─── HOUSE MANAGEMENT ENDPOINTS ─────────────────────────────

// 1. Give House Key (/givehousekeys)
app.post('/api/ucp/houses/give-key', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;
  const { houseId, targetUsername } = req.body;

  if (!houseId || !targetUsername || !targetUsername.trim()) {
    return res.status(400).json({ message: "House ID and Target Character Name are required." });
  }

  const cleanTarget = targetUsername.trim();

  sampDb.query("SELECT ID, Username FROM players WHERE LOWER(Username) = LOWER(?) LIMIT 1", [cleanTarget], (errP, pResults) => {
    if (errP || !pResults || pResults.length === 0) {
      return res.status(404).json({ message: `Target character "${cleanTarget}" not found in database.` });
    }

    const targetPlayer = pResults[0];

    findHouseInDb(houseId, username, playerId, (errH, house) => {
      if (errH || !house) {
        return res.status(404).json({ message: "House not found." });
      }

      const isOwner = String(house.owner_id || house.OwnerID || house.owner || house.Owner || '').toLowerCase() === String(playerId).toLowerCase() ||
                      String(house.owner || house.Owner || '').toLowerCase() === String(username).toLowerCase();

      if (!isOwner) {
        return res.status(403).json({ message: "You are not the owner of this house." });
      }

      const keysColNames = ['key1', 'key2', 'key3', 'key4', 'key5', 'Key1', 'Key2', 'Key3', 'Key4', 'Key5', 'hKey1', 'hKey2', 'hKey3'];
      let targetCol = null;

      for (const col of keysColNames) {
        if (col in house) {
          const val = house[col];
          if (String(val).toLowerCase() === String(targetPlayer.Username).toLowerCase() || String(val) === String(targetPlayer.ID)) {
            return res.status(400).json({ message: `Character "${targetPlayer.Username}" already has a key to this house.` });
          }
          if (!targetCol && (!val || val === '0' || val === 0 || val === 'None' || val === '' || val === null)) {
            targetCol = col;
          }
        }
      }

      const houseIdCol = Object.keys(house).find(k => k.toLowerCase() === 'id' || k.toLowerCase() === 'houseid') || 'id';

      if (targetCol) {
        sampDb.query(`UPDATE houses SET \`${targetCol}\` = ? WHERE \`${houseIdCol}\` = ?`, [targetPlayer.Username, house[houseIdCol]], (errU) => {
          if (errU) {
            console.error("Error giving house key:", errU);
            return res.status(500).json({ message: "Failed to update house key in database." });
          }
          res.json({ message: `Successfully gave house key to ${targetPlayer.Username}!` });
        });
      } else if ('keys' in house || 'housekeys' in house || 'shared_keys' in house) {
        const listCol = 'keys' in house ? 'keys' : ('housekeys' in house ? 'housekeys' : 'shared_keys');
        let currentKeys = house[listCol] ? String(house[listCol]).split(',').map(s => s.trim()).filter(Boolean) : [];
        if (!currentKeys.includes(targetPlayer.Username)) {
          currentKeys.push(targetPlayer.Username);
        }
        sampDb.query(`UPDATE houses SET \`${listCol}\` = ? WHERE \`${houseIdCol}\` = ?`, [currentKeys.join(','), house[houseIdCol]], (errU) => {
          if (errU) return res.status(500).json({ message: "Failed to update house keys." });
          res.json({ message: `Successfully gave house key to ${targetPlayer.Username}!` });
        });
      } else {
        sampDb.query(`UPDATE houses SET key1 = ? WHERE \`${houseIdCol}\` = ?`, [targetPlayer.Username, house[houseIdCol]], (errU) => {
          if (errU) {
            sampDb.query(`UPDATE houses SET key1 = key1 WHERE \`${houseIdCol}\` = ?`, [house[houseIdCol]], () => {});
          }
          res.json({ message: `House key given to ${targetPlayer.Username} successfully!` });
        });
      }
    });
  });
});

// 2. Take House Key (/takehousekeys)
app.post('/api/ucp/houses/take-key', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;
  const { houseId, targetUsername } = req.body;

  if (!houseId || !targetUsername) {
    return res.status(400).json({ message: "House ID and Target Character Name are required." });
  }

  const cleanTarget = targetUsername.trim().toLowerCase();

  findHouseInDb(houseId, username, playerId, (errH, house) => {
    if (errH || !house) {
      return res.status(404).json({ message: "House not found." });
    }

    const isOwner = String(house.owner_id || house.OwnerID || house.owner || house.Owner || '').toLowerCase() === String(playerId).toLowerCase() ||
                    String(house.owner || house.Owner || '').toLowerCase() === String(username).toLowerCase();

    if (!isOwner) {
      return res.status(403).json({ message: "You are not the owner of this house." });
    }

    const houseIdCol = Object.keys(house).find(k => k.toLowerCase() === 'id' || k.toLowerCase() === 'houseid') || 'id';
    const keysColNames = ['key1', 'key2', 'key3', 'key4', 'key5', 'Key1', 'Key2', 'Key3', 'Key4', 'Key5', 'hKey1', 'hKey2', 'hKey3'];

    keysColNames.forEach(col => {
      if (col in house) {
        const val = String(house[col] || '').toLowerCase();
        if (val === cleanTarget) {
          sampDb.query(`UPDATE houses SET \`${col}\` = '0' WHERE \`${houseIdCol}\` = ?`, [house[houseIdCol]], () => {});
        }
      }
    });

    if ('keys' in house || 'housekeys' in house || 'shared_keys' in house) {
      const listCol = 'keys' in house ? 'keys' : ('housekeys' in house ? 'housekeys' : 'shared_keys');
      let currentKeys = house[listCol] ? String(house[listCol]).split(',').map(s => s.trim()).filter(s => s.toLowerCase() !== cleanTarget) : [];
      sampDb.query(`UPDATE houses SET \`${listCol}\` = ? WHERE \`${houseIdCol}\` = ?`, [currentKeys.join(','), house[houseIdCol]], () => {});
    }

    res.json({ message: `Successfully revoked house key from ${targetUsername}!` });
  });
});

// 3. Toggle House Lock Status
app.post('/api/ucp/houses/toggle-lock', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;
  const { houseId } = req.body;

  findHouseInDb(houseId, username, playerId, (errH, house) => {
    if (errH || !house) return res.status(404).json({ message: "House not found." });

    const houseIdCol = Object.keys(house).find(k => k.toLowerCase() === 'id' || k.toLowerCase() === 'houseid') || 'id';
    const lockCol = Object.keys(house).find(k => k.toLowerCase() === 'locked' || k.toLowerCase() === 'lock' || k.toLowerCase() === 'hlocked') || 'locked';
    
    const currentLock = Number(house[lockCol] || 0);
    const newLock = currentLock === 1 ? 0 : 1;

    sampDb.query(`UPDATE houses SET \`${lockCol}\` = ? WHERE \`${houseIdCol}\` = ?`, [newLock, house[houseIdCol]], (errU) => {
      if (errU) return res.status(500).json({ message: "Failed to update house lock state." });
      res.json({ message: `House is now ${newLock === 1 ? 'Locked 🔒' : 'Unlocked 🔓'}!` });
    });
  });
});


// ─── BUSINESS MANAGEMENT ENDPOINTS ─────────────────────────

// 1. Transfer Ownership / Sell Business to Player
app.post('/api/ucp/businesses/change-owner', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;
  const { businessId, newOwnerUsername } = req.body;

  if (!businessId || !newOwnerUsername || !newOwnerUsername.trim()) {
    return res.status(400).json({ message: "Business ID and New Owner Character Name are required." });
  }

  const cleanTarget = newOwnerUsername.trim();

  sampDb.query("SELECT ID, Username FROM players WHERE LOWER(Username) = LOWER(?) LIMIT 1", [cleanTarget], (errP, pResults) => {
    if (errP || !pResults || pResults.length === 0) {
      return res.status(404).json({ message: `Character "${cleanTarget}" not found in database.` });
    }

    const newOwner = pResults[0];

    findBusinessInDb(businessId, username, playerId, (errB, bizz) => {
      if (errB || !bizz) {
        return res.status(404).json({ message: "Business not found." });
      }

      const isOwner = String(bizz.owner_id || bizz.OwnerID || bizz.owner || bizz.Owner || bizz.bOwner || '').toLowerCase() === String(playerId).toLowerCase() ||
                      String(bizz.owner || bizz.Owner || bizz.bOwner || '').toLowerCase() === String(username).toLowerCase();

      if (!isOwner) {
        return res.status(403).json({ message: "You are not the owner of this business." });
      }

      const bizzIdCol = Object.keys(bizz).find(k => k.toLowerCase() === 'id' || k.toLowerCase() === 'bizzid' || k.toLowerCase() === 'bid' || k.toLowerCase() === 'bizz_id') || 'id';
      const ownerCol = Object.keys(bizz).find(k => k.toLowerCase() === 'owner' || k.toLowerCase() === 'bowner') || 'owner';
      const ownerIdCol = Object.keys(bizz).find(k => k.toLowerCase() === 'owner_id' || k.toLowerCase() === 'ownerid');

      let updateSql = `UPDATE businesses SET \`${ownerCol}\` = ?`;
      let params = [newOwner.Username];

      if (ownerIdCol && ownerIdCol in bizz) {
        updateSql += `, \`${ownerIdCol}\` = ?`;
        params.push(newOwner.ID);
      }

      updateSql += ` WHERE \`${bizzIdCol}\` = ?`;
      params.push(bizz[bizzIdCol]);

      sampDb.query(updateSql, params, (errU) => {
        if (errU) {
          console.error("Error transferring business ownership:", errU);
          return res.status(500).json({ message: "Failed to transfer business ownership." });
        }
        res.json({ message: `Business ownership transferred to ${newOwner.Username} successfully!` });
      });
    });
  });
});

// 2. Update Business Details (Store Name & Message)
app.post('/api/ucp/businesses/update-details', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;
  const { businessId, storeName, storeMessage } = req.body;

  findBusinessInDb(businessId, username, playerId, (errB, bizz) => {
    if (errB || !bizz) return res.status(404).json({ message: "Business not found." });

    const isOwner = String(bizz.owner_id || bizz.OwnerID || bizz.owner || bizz.Owner || bizz.bOwner || '').toLowerCase() === String(playerId).toLowerCase() ||
                    String(bizz.owner || bizz.Owner || bizz.bOwner || '').toLowerCase() === String(username).toLowerCase();

    if (!isOwner) return res.status(403).json({ message: "You are not the owner of this business." });

    const bizzIdCol = Object.keys(bizz).find(k => k.toLowerCase() === 'id' || k.toLowerCase() === 'bizzid' || k.toLowerCase() === 'bid' || k.toLowerCase() === 'bizz_id') || 'id';
    const nameCol = Object.keys(bizz).find(k => k.toLowerCase() === 'name' || k.toLowerCase() === 'storename' || k.toLowerCase() === 'bname') || 'name';
    const msgCol = Object.keys(bizz).find(k => k.toLowerCase() === 'message' || k.toLowerCase() === 'bmessage') || 'message';

    let updates = [];
    let params = [];

    if (storeName !== undefined && nameCol in bizz) {
      updates.push(`\`${nameCol}\` = ?`);
      params.push(storeName.trim());
    }

    if (storeMessage !== undefined && msgCol in bizz) {
      updates.push(`\`${msgCol}\` = ?`);
      params.push(storeMessage.trim());
    }

    if (updates.length === 0) return res.status(400).json({ message: "No valid fields provided to update." });

    params.push(bizz[bizzIdCol]);

    sampDb.query(`UPDATE businesses SET ${updates.join(', ')} WHERE \`${bizzIdCol}\` = ?`, params, (errU) => {
      if (errU) return res.status(500).json({ message: "Failed to update business details." });
      res.json({ message: "Business store details updated successfully!" });
    });
  });
});

// 3. Toggle Business Lock Status
app.post('/api/ucp/businesses/toggle-lock', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;
  const { businessId } = req.body;

  findBusinessInDb(businessId, username, playerId, (errB, bizz) => {
    if (errB || !bizz) return res.status(404).json({ message: "Business not found." });

    const isOwner = String(bizz.owner_id || bizz.OwnerID || bizz.owner || bizz.Owner || bizz.bOwner || '').toLowerCase() === String(playerId).toLowerCase() ||
                    String(bizz.owner || bizz.Owner || bizz.bOwner || '').toLowerCase() === String(username).toLowerCase();

    if (!isOwner) return res.status(403).json({ message: "You are not the owner of this business." });

    const bizzIdCol = Object.keys(bizz).find(k => k.toLowerCase() === 'id' || k.toLowerCase() === 'bizzid' || k.toLowerCase() === 'bid' || k.toLowerCase() === 'bizz_id') || 'id';
    const lockCol = Object.keys(bizz).find(k => k.toLowerCase() === 'locked' || k.toLowerCase() === 'lock' || k.toLowerCase() === 'blocked') || 'locked';
    
    const currentLock = Number(bizz[lockCol] || 0);
    const newLock = currentLock === 1 ? 0 : 1;

    sampDb.query(`UPDATE businesses SET \`${lockCol}\` = ? WHERE \`${bizzIdCol}\` = ?`, [newLock, bizz[bizzIdCol]], (errU) => {
      if (errU) return res.status(500).json({ message: "Failed to update business lock state." });
      res.json({ message: `Business is now ${newLock === 1 ? 'Locked 🔒' : 'Unlocked 🔓'}!` });
    });
  });
});

// 4. Deposit / Withdraw Money from Business Safe
app.post('/api/ucp/businesses/safe-transaction', verifyUcpToken, (req, res) => {
  const playerId = req.ucpUser.ucpPlayerId || req.ucpUser.id;
  const username = req.ucpUser.username;
  const { businessId, action, amount } = req.body;

  const numAmount = parseInt(amount, 10);
  if (!businessId || !action || isNaN(numAmount) || numAmount <= 0) {
    return res.status(400).json({ message: "Business ID, Action (deposit/withdraw), and valid positive Amount are required." });
  }

  findBusinessInDb(businessId, username, playerId, (errB, bizz) => {
    if (errB || !bizz) return res.status(404).json({ message: "Business not found." });

    const isOwner = String(bizz.owner_id || bizz.OwnerID || bizz.owner || bizz.Owner || bizz.bOwner || '').toLowerCase() === String(playerId).toLowerCase() ||
                    String(bizz.owner || bizz.Owner || bizz.bOwner || '').toLowerCase() === String(username).toLowerCase();

    if (!isOwner) return res.status(403).json({ message: "You are not the owner of this business." });

    sampDb.query("SELECT * FROM players WHERE ID = ? OR Username = ? LIMIT 1", [playerId, username], (errP, pResults) => {
      if (errP || !pResults || pResults.length === 0) return res.status(404).json({ message: "Player account not found." });

      const player = pResults[0];
      const bizzIdCol = Object.keys(bizz).find(k => k.toLowerCase() === 'id' || k.toLowerCase() === 'bizzid' || k.toLowerCase() === 'bid' || k.toLowerCase() === 'bizz_id') || 'id';
      const safeCol = Object.keys(bizz).find(k => k.toLowerCase() === 'safe' || k.toLowerCase() === 'till' || k.toLowerCase() === 'vault' || k.toLowerCase() === 'bsafe' || k.toLowerCase() === 'money') || 'safe';
      const cashCol = 'Money' in player ? 'Money' : ('Cash' in player ? 'Cash' : ('money' in player ? 'money' : 'Money'));

      const currentSafe = Number(bizz[safeCol] || 0);
      const currentCash = Number(player[cashCol] || 0);

      if (action === 'withdraw') {
        if (currentSafe < numAmount) {
          return res.status(400).json({ message: `Insufficient business safe balance! Available in safe: $${currentSafe.toLocaleString()}` });
        }
        const newSafe = currentSafe - numAmount;
        const newCash = currentCash + numAmount;

        sampDb.query(`UPDATE businesses SET \`${safeCol}\` = ? WHERE \`${bizzIdCol}\` = ?`, [newSafe, bizz[bizzIdCol]], (errU1) => {
          if (errU1) return res.status(500).json({ message: "Failed to update business safe." });
          sampDb.query(`UPDATE players SET \`${cashCol}\` = ? WHERE ID = ?`, [newCash, player.ID], () => {});
          res.json({ message: `Successfully withdrew $${numAmount.toLocaleString()} from business safe to your character's cash!` });
        });

      } else if (action === 'deposit') {
        if (currentCash < numAmount) {
          return res.status(400).json({ message: `Insufficient character cash! You have: $${currentCash.toLocaleString()}` });
        }
        const newSafe = currentSafe + numAmount;
        const newCash = currentCash - numAmount;

        sampDb.query(`UPDATE businesses SET \`${safeCol}\` = ? WHERE \`${bizzIdCol}\` = ?`, [newSafe, bizz[bizzIdCol]], (errU1) => {
          if (errU1) return res.status(500).json({ message: "Failed to update business safe." });
          sampDb.query(`UPDATE players SET \`${cashCol}\` = ? WHERE ID = ?`, [newCash, player.ID], () => {});
          res.json({ message: `Successfully deposited $${numAmount.toLocaleString()} into business safe!` });
        });
      }
    });
  });
});

// ─── GET /api/ucp/groups (Get All Factions & Gang Ranks Directory) ────
app.get('/api/ucp/groups', (req, res) => {
  sampDb.query(
    "SELECT group_id, rank_level, name FROM group_ranks ORDER BY group_id, rank_level",
    (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Failed to fetch groups directory." });
      }
      res.json({ groups: results });
    }
  );
});

// ─── GET /api/ucp/player/:username (Get Public Player Info by Username) ──
app.get('/api/ucp/player/:username', (req, res) => {
  const targetUsername = req.params.username.trim();

  sampDb.query(
    "SELECT * FROM players WHERE Username = ? LIMIT 1",
    [targetUsername],
    (err, results) => {
      if (err) {
        console.error("Error querying player by username:", err);
        return res.status(500).json({ message: "Database query error." });
      }

      if (!results || results.length === 0) {
        return res.status(404).json({ message: `No character found with username "${targetUsername}".` });
      }

      const player = results[0];
      const sanitizedPlayer = sanitizePlayerForUcp(player);

      res.json({ player: sanitizedPlayer });
    }
  );
});

// ─── GET /api/ucp/total-players (Get Count of Registered Players) ──
app.get('/api/ucp/total-players', (req, res) => {
  sampDb.query("SELECT COUNT(*) AS totalPlayers FROM players", (err, results) => {
    if (err) {
      console.error("Error fetching total players:", err);
      return res.status(500).json({ message: "Database query error." });
    }
    const total = results && results.length > 0 ? results[0].totalPlayers : 0;
    res.json({ totalPlayers: total });
  });
});

// ─── POST /api/ucp/logout ──────────────────────────────────
app.post('/api/ucp/logout', (req, res) => {
  res.clearCookie('ucp_token', cookieOptions);
  res.json({ message: 'Logged out from UCP successfully.' });
});

// ─── GET / ────────────────────────────────────────────────
app.get('/', (req, res) => res.send('Server is running and working perfectly!'));

// SOCKET.IO SETUP
const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    credentials: true
  }
});
global.io = io;

// Authenticate socket connections via JWT
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Authentication required'));
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    socket.user = decoded;
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  console.log(`Socket connected: ${socket.user.id} (${socket.user.role})`);
  
  // Join user's personal notification room
  socket.join(`user-${socket.user.id}`);
  
  // Admin joins the admin-tickets room for real-time notifications
  if (socket.user.role === 'admin' || socket.user.role === 'master') {
    socket.join('admin-tickets');
  }
  
  // Join a specific ticket room
  socket.on('join-ticket', (ticketId) => {
    // Verify access before joining
    db.query("SELECT user_id FROM purchase_tickets WHERE id = ?", [ticketId], (err, results) => {
      if (err || results.length === 0) return;
      if (results[0].user_id === socket.user.id || socket.user.role === 'admin' || socket.user.role === 'master') {
        socket.join(`ticket-${ticketId}`);
        console.log(`User ${socket.user.id} joined ticket-${ticketId}`);
      }
    });
  });
  
  // Leave a ticket room
  socket.on('leave-ticket', (ticketId) => {
    socket.leave(`ticket-${ticketId}`);
  });
  
  socket.on('disconnect', () => {
    console.log(`Socket disconnected: ${socket.user.id}`);
  });
});

// ─── GET /api/highscores (Public Leaderboard & Highscores) ─────────────────────
app.get('/api/highscores', highscoresLimiter, (req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  const category = (req.query.category || 'wealth').toLowerCase().trim();

  // Helper map for job skill column names
  const jobSkillCols = {
    trucker: ['TruckSkill', 'pTruckSkill'],
    mechanic: ['MechSkill', 'pMechSkill', 'MechanicSkill'],
    arms: ['ArmsSkill', 'pArmsSkill', 'MaterialsSkill'],
    detective: ['DetectiveSkill', 'DetSkill', 'pDetectiveSkill'],
    lawyer: ['LawyerSkill', 'LawSkill', 'pLawyerSkill'],
    drugs: ['DrugsSkill', 'pDrugsSkill'],
    boxing: ['BoxWins', 'BoxingWins', 'pBoxWins', 'pBoxingWins', 'BoxSkill', 'BoxerSkill', 'BoxingSkill', 'pBoxerSkill', 'BoxWon', 'pBoxWon'],
    fishing: ['FishSkill', 'FishingSkill', 'pFishSkill'],
    carjacker: ['CarSkill', 'CarjackerSkill', 'pCarSkill'],
    smuggler: ['SmugglerSkill', 'pSmugglerSkill'],
    prostitute: ['SexSkill', 'WhoreSkill', 'pSexSkill']
  };

  if (category === 'cars') {
    const vehicleNames = {
      400: 'Landstalker', 401: 'Bravura', 402: 'Buffalo', 403: 'Linerunner', 404: 'Perennial',
      405: 'Sentinel', 406: 'Dumper', 407: 'Firetruck', 408: 'Trashmaster', 409: 'Stretch',
      410: 'Manana', 411: 'Infernus', 412: 'Voodoo', 413: 'Pony', 414: 'Mule', 415: 'Cheetah',
      416: 'Ambulance', 417: 'Leviathan', 418: 'Moonbeam', 419: 'Esperanto', 420: 'Taxi',
      421: 'Washington', 422: 'Bobcat', 423: 'Mr Whoopee', 424: 'BF Injection', 425: 'Hunter',
      426: 'Premier', 427: 'Enforcer', 428: 'Securicar', 429: 'Banshee', 430: 'Predator',
      431: 'Bus', 432: 'Rhino', 433: 'Barracks', 434: 'Hotknife', 435: 'Trailer', 436: 'Previon',
      437: 'Coach', 438: 'Cabbie', 439: 'Stallion', 440: 'Rumpo', 441: 'RC Bandit', 442: 'Romero',
      443: 'Packer', 444: 'Monster', 445: 'Admiral', 446: 'Squalo', 447: 'Seasparrow', 448: 'Pizzaboy',
      449: 'Tram', 450: 'Trailer 2', 451: 'Turismo', 452: 'Speeder', 453: 'Reefer', 454: 'Tropic',
      455: 'Flatbed', 456: 'Yankee', 457: 'Caddy', 458: 'Solair', 459: 'Topfun Van', 460: 'Skimmer',
      461: 'PCJ-600', 462: 'Faggio', 463: 'Freeway', 464: 'RC Baron', 465: 'RC Raider', 466: 'Glendale',
      467: 'Oceanic', 468: 'Sanchez', 469: 'Sparrow', 470: 'Patriot', 471: 'Quadbike', 472: 'Coastguard',
      473: 'Dinghy', 474: 'Hermes', 475: 'Sabre', 476: 'Rustler', 477: 'ZR-350', 478: 'Walton',
      479: 'Regina', 480: 'Comet', 481: 'BMX', 482: 'Burrito', 483: 'Camper', 484: 'Marquis',
      485: 'Baggage', 486: 'Dozer', 487: 'Maverick', 488: 'SAN News Mav', 489: 'Rancher', 490: 'FBI Rancher',
      491: 'Virgo', 492: 'Greenwood', 493: 'Jetmax', 494: 'Hotring Racer', 495: 'Sandking',
      496: 'Blista Compact', 497: 'Police Mav', 498: 'Boxville', 499: 'Benson', 500: 'Mesa',
      501: 'RC Goblin', 502: 'Hotring 2', 503: 'Hotring 3', 504: 'Bloodring', 505: 'Rancher Lure',
      506: 'Super GT', 507: 'Elegant', 508: 'Journey', 509: 'Bike', 510: 'Mountain Bike',
      511: 'Beagle', 512: 'Cropduster', 513: 'Stuntplane', 514: 'Tanker', 515: 'Roadtrain',
      516: 'Nebula', 517: 'Majestic', 518: 'Buccaneer', 519: 'Shamal', 520: 'Hydra', 521: 'FCR-900',
      522: 'NRG-500', 523: 'HPV-1000', 524: 'Cement Truck', 525: 'Towtruck', 526: 'Fortune',
      527: 'Cadrona', 528: 'FBI Truck', 529: 'Willard', 530: 'Forklift', 531: 'Tractor',
      532: 'Combine', 533: 'Feltzer', 534: 'Remington', 535: 'Slamvan', 536: 'Blade', 537: 'Freight',
      538: 'Streak', 539: 'Vortex', 540: 'Vincent', 541: 'Bullet', 542: 'Clover', 543: 'Sadler',
      544: 'Firetruck LA', 545: 'Hustler', 546: 'Intruder', 547: 'Primo', 548: 'Cargobob', 549: 'Tampa',
      550: 'Sunrise', 551: 'Merit', 552: 'Utility Van', 553: 'Nevada', 554: 'Yosemite', 555: 'Windsor',
      556: 'Monster 2', 557: 'Monster 3', 558: 'Uranus', 559: 'Jester', 560: 'Sultan', 561: 'Stratum',
      562: 'Elegy', 563: 'Raindance', 564: 'RC Tiger', 565: 'Flash', 566: 'Tahoma', 567: 'Savanna',
      568: 'Bandito', 571: 'Kart', 572: 'Mower', 573: 'Dune', 574: 'Sweeper', 575: 'Broadway',
      576: 'Tornado', 577: 'AT-400', 578: 'DFT-30', 579: 'Huntley', 580: 'Stafford', 581: 'BF-400',
      582: 'Newsvan', 583: 'Tug', 585: 'Emperor', 586: 'Wayfarer', 587: 'Euro', 588: 'Hotdog',
      589: 'Club', 592: 'Andromada', 593: 'Dodo', 594: 'RC Cam', 595: 'Launch', 596: 'Police LSPD',
      597: 'Police SFPD', 598: 'Police LVPD', 599: 'Police Ranger', 600: 'Picador', 601: 'SWAT Tank',
      602: 'Alpha', 603: 'Phoenix', 604: 'Glendale Shit', 605: 'Sadler Shit'
    };

    const processVehiclesData = (vehicles) => {
      if (!vehicles || vehicles.length === 0) return [];
      const modelCounts = {};
      vehicles.forEach(v => {
        const modelId = Number(v.Model || v.VehicleModel || v.vModel || v.cModel || v.model || v.ModelID || v.v_model || v.car_model || v.CarModel || 0);
        if (modelId >= 400 && modelId <= 611) {
          modelCounts[modelId] = (modelCounts[modelId] || 0) + 1;
        }
      });

      return Object.keys(modelCounts)
        .map(model => {
          const mId = Number(model);
          const nameStr = vehicleNames[mId] || `Vehicle #${mId}`;
          return {
            name: `${mId}`,
            modelName: nameStr,
            modelId: mId,
            value: modelCounts[mId],
            unit: ''
          };
        })
        .sort((a, b) => b.value - a.value)
        .slice(0, 20);
    };

    // Query vehicles table with fallbacks for player_vehicles and cars tables
    sampDb.query("SELECT * FROM vehicles LIMIT 5000", (err, vehicles) => {
      if (!err && vehicles && vehicles.length > 0) {
        return res.json({ category, highscores: processVehiclesData(vehicles) });
      }
      sampDb.query("SELECT * FROM player_vehicles LIMIT 5000", (err2, pVehicles) => {
        if (!err2 && pVehicles && pVehicles.length > 0) {
          return res.json({ category, highscores: processVehiclesData(pVehicles) });
        }
        sampDb.query("SELECT * FROM cars LIMIT 5000", (err3, cVehicles) => {
          if (!err3 && cVehicles && cVehicles.length > 0) {
            return res.json({ category, highscores: processVehiclesData(cVehicles) });
          }
          return res.json({ category, highscores: [] });
        });
      });
    });
    return;
  }

  if (category === 'crimes') {
    const processCrimesData = (rows) => {
      if (!rows || rows.length === 0) return [];
      const crimeCounts = {};
      rows.forEach(r => {
        const rawCharge = r.Charge || r.Crime || r.crime || r.charge || r.Reason || r.reason || r.CrimeName || r.crime_name || r.Detail || r.Offense || '';
        const chargeName = rawCharge.toString().trim();
        if (chargeName && chargeName !== '0' && chargeName !== 'None' && chargeName !== 'null' && isNaN(Number(chargeName))) {
          const countVal = Number(r.count || r.Amount || r.amount || 1);
          crimeCounts[chargeName] = (crimeCounts[chargeName] || 0) + countVal;
        }
      });

      return Object.keys(crimeCounts)
        .map(charge => ({
          name: charge,
          value: crimeCounts[charge],
          unit: ''
        }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 20);
    };

    // Query real DB tables in sequence (crimes -> charges -> mdc_crimes -> arrests -> players)
    sampDb.query("SELECT * FROM crimes LIMIT 5000", (err1, r1) => {
      if (!err1 && r1 && r1.length > 0) {
        const resList = processCrimesData(r1);
        if (resList.length > 0) return res.json({ category, highscores: resList });
      }
      sampDb.query("SELECT * FROM charges LIMIT 5000", (err2, r2) => {
        if (!err2 && r2 && r2.length > 0) {
          const resList = processCrimesData(r2);
          if (resList.length > 0) return res.json({ category, highscores: resList });
        }
        sampDb.query("SELECT * FROM mdc_crimes LIMIT 5000", (err3, r3) => {
          if (!err3 && r3 && r3.length > 0) {
            const resList = processCrimesData(r3);
            if (resList.length > 0) return res.json({ category, highscores: resList });
          }
          sampDb.query("SELECT * FROM arrests LIMIT 5000", (err4, r4) => {
            if (!err4 && r4 && r4.length > 0) {
              const resList = processCrimesData(r4);
              if (resList.length > 0) return res.json({ category, highscores: resList });
            }
            sampDb.query("SELECT * FROM players LIMIT 1000", (err5, players) => {
              if (err5 || !players) return res.json({ category, highscores: [] });
              const counts = {};
              players.forEach(p => {
                const c = p.CrimeRecord || p.MainCrime || p.pCrimeRecord || p.ChargesRecord || p.WantedReason;
                if (c && typeof c === 'string' && c.trim() !== '' && c !== 'None' && c !== '0' && isNaN(Number(c))) {
                  const parts = c.split(/[,;|]/);
                  parts.forEach(pt => {
                    const clean = pt.trim();
                    if (clean && clean !== '0' && clean !== 'None' && isNaN(Number(clean))) {
                      counts[clean] = (counts[clean] || 0) + 1;
                    }
                  });
                }
              });
              const list = Object.keys(counts)
                .map(chg => ({ name: chg, value: counts[chg], unit: '' }))
                .sort((a, b) => b.value - a.value)
                .slice(0, 20);

              return res.json({ category, highscores: list });
            });
          });
        });
      });
    });
    return;
  }

  if (category === 'factions-roster' || category === 'factions-wealth') {
    sampDb.query("SELECT * FROM factions LIMIT 100", (errF, fRows) => {
      sampDb.query("SELECT * FROM families LIMIT 100", (errFam, famRows) => {
        sampDb.query("SELECT * FROM gangs LIMIT 100", (errG, gRows) => {
          
          const defaultFactionMeta = {
            1: 'Paraiso Police Department',
            2: 'Federal Bureau of Investigation',
            3: 'Paraiso Fire & Medic Department',
            4: 'Paraiso San Andreas News',
            5: 'Paraiso National Guard',
            6: 'Government',
            7: 'Grove Street Families',
            8: '18th Street Pacris Fraternity',
            9: 'La Cosa Nostra',
            10: 'Hoodlum Outcast',
            11: 'The Young Lords',
            12: 'Hitman Agency',
            13: 'The Sovereignty'
          };

          const dynamicMeta = {};

          if (!errF && fRows && fRows.length > 0) {
            fRows.forEach(r => {
              const fid = Number(r.id || r.ID || r.fId || r.FactionID || 0);
              const fname = (r.name || r.Name || r.FactionName || '').toString().trim();
              if (fid > 0 && fname) dynamicMeta[`faction_${fid}`] = fname;
            });
          }

          if (!errFam && famRows && famRows.length > 0) {
            famRows.forEach(r => {
              const gid = Number(r.id || r.ID || r.fId || r.FamilyID || r.GangID || 0);
              const gname = (r.name || r.Name || r.FamilyName || r.GangName || '').toString().trim();
              if (gid > 0 && gname) dynamicMeta[`family_${gid}`] = gname;
            });
          }

          if (!errG && gRows && gRows.length > 0) {
            gRows.forEach(r => {
              const gid = Number(r.id || r.ID || r.fId || r.GangID || 0);
              const gname = (r.name || r.Name || r.GangName || '').toString().trim();
              if (gid > 0 && gname && !dynamicMeta[`family_${gid}`]) {
                dynamicMeta[`family_${gid}`] = gname;
              }
            });
          }

          sampDb.query("SELECT * FROM players LIMIT 1000", (errP, players) => {
            if (errP || !players) return res.json({ category, highscores: [] });

            const factionsData = {};

            // Pre-initialize any dynamic Faction/Gang found in DB tables
            Object.keys(dynamicMeta).forEach(key => {
              const fid = Number(key.replace('faction_', '').replace('family_', ''));
              if (fid > 0 && fid !== 255 && fid !== 12) {
                factionsData[key] = {
                  id: fid,
                  name: dynamicMeta[key],
                  members: 0,
                  totalWealth: 0
                };
              }
            });

            players.forEach(p => {
              const cash = Number(p.Cash ?? p.pMoney ?? p.Money ?? 0);
              const bank = Number(p.Bank ?? p.pBank ?? 0);
              const wealth = cash + bank;

              // Check Faction / Gang ID (ignore 0, 255, 12-hitman)
              const fId = Number(p.Member || p.Leader || p.Faction || p.pMember || p.pLeader || p.Fequipe || p.Family || p.Gang || p.pFequipe || p.pFamily || p.pGang || 0);
              
              if (fId > 0 && fId !== 255 && fId !== 12) {
                const key = `faction_${fId}`;
                if (!factionsData[key]) {
                  const fname = dynamicMeta[key] || dynamicMeta[`family_${fId}`] || defaultFactionMeta[fId] || `Faction #${fId}`;
                  factionsData[key] = { id: fId, name: fname, members: 0, totalWealth: 0 };
                }
                factionsData[key].members += 1;
                factionsData[key].totalWealth += wealth;
              }
            });

            // Add stash cash from database tables
            if (fRows && fRows.length > 0) {
              fRows.forEach(r => {
                const fid = Number(r.id || r.ID || r.fId || r.FactionID || 0);
                const stash = Number(r.Bank || r.Vault || r.Stash || r.Safe || r.Money || r.fBank || r.fVault || r.Cash || 0);
                if (fid > 0 && factionsData[`faction_${fid}`]) factionsData[`faction_${fid}`].totalWealth += stash;
              });
            }

            if (famRows && famRows.length > 0) {
              famRows.forEach(r => {
                const gid = Number(r.id || r.ID || r.fId || r.FamilyID || r.GangID || 0);
                const stash = Number(r.Bank || r.Vault || r.Stash || r.Safe || r.Money || r.fBank || r.fVault || r.Cash || 0);
                if (gid > 0 && factionsData[`faction_${gid}`]) factionsData[`faction_${gid}`].totalWealth += stash;
              });
            }

            const list = Object.values(factionsData)
              .filter(f => f.id !== 255 && f.id !== 0 && f.id !== 12 && !f.name.toLowerCase().includes('hitman'))
              .map(f => ({
                id: f.id,
                name: f.name,
                value: category === 'factions-roster' ? f.members : f.totalWealth,
                unit: category === 'factions-roster' ? 'Members' : '$'
              }));

            list.sort((a, b) => b.value - a.value);
            return res.json({ category, highscores: list.slice(0, 20) });
          });
        });
      });
    });
    return;
  }

  if (category === 'kills') {
    sampDb.query("SELECT * FROM kills LIMIT 5000", (errK, killRows) => {
      sampDb.query("SELECT * FROM players LIMIT 1000", (errP, players) => {
        if (errP || !players) players = [];
        
        const playerMapById = {};
        const playerMapByName = {};
        players.forEach(p => {
          const pid = Number(p.ID ?? p.id ?? 0);
          const uname = p.Username || p.username || '';
          if (pid > 0 && uname) playerMapById[pid] = uname;
          if (uname) playerMapByName[uname.toLowerCase()] = p;
        });

        const killCounts = {};

        if (!errK && killRows && killRows.length > 0) {
          killRows.forEach(r => {
            let killerVal = r.Killer || r.killer || r.killer_id || r.killerid || r.KillerID || r.KillerName || r.killer_name || r.Player || r.Username || r.username || r.char_id || r.character_id || r.player_id || Object.values(r)[1] || Object.values(r)[0] || '';
            killerVal = killerVal ? killerVal.toString().trim() : '';
            
            let resolvedName = '';
            if (!isNaN(Number(killerVal)) && Number(killerVal) > 0) {
              resolvedName = playerMapById[Number(killerVal)] || '';
            } else if (killerVal && killerVal !== '0' && killerVal !== 'None' && killerVal !== 'null') {
              resolvedName = killerVal;
            }

            if (resolvedName) {
              killCounts[resolvedName] = (killCounts[resolvedName] || 0) + 1;
            }
          });
        }

        const killList = Object.keys(killCounts)
          .map(k => {
            const pObj = playerMapByName[k.toLowerCase()] || {};
            return {
              name: k,
              username: k,
              skin: Number(pObj.Skin ?? pObj.pSkin ?? 299),
              value: killCounts[k],
              unit: 'Kills'
            };
          })
          .sort((a, b) => b.value - a.value)
          .slice(0, 20);

        if (killList.length > 0) {
          return res.json({ category, highscores: killList });
        }

        // Fallback: list players sorted by Kills or Level
        const fallbackList = players.map(p => ({
          username: p.Username || p.username || 'Unknown',
          level: Number(p.Level ?? p.pLevel ?? 1),
          skin: Number(p.Skin ?? p.pSkin ?? 299),
          value: Number(p.PaintballKills ?? p.pPaintballKills ?? p.PBKills ?? p.pPBKills ?? p.Paintball ?? p.PBK ?? p.Kills ?? p.pKills ?? p.Killed ?? 0),
          unit: 'Kills'
        }));
        fallbackList.sort((a, b) => b.value - a.value);
        return res.json({ category, highscores: fallbackList.slice(0, 20) });
      });
    });
    return;
  }

  if (category === 'arrests') {
    sampDb.query("SELECT * FROM players LIMIT 1000", (errP, players) => {
      if (errP || !players) return res.json({ category, highscores: [] });

      const ranked = players.map(p => {
        const uname = p.Username || p.username || 'Unknown';
        const crimesVal = Number(p.Crimes ?? p.pCrimes ?? p.CrimesCommitted ?? 0);
        const arrestsVal = Number(p.Arrested ?? p.Arrests ?? p.pArrests ?? 0);

        return {
          username: uname,
          level: Number(p.Level ?? p.pLevel ?? 1),
          skin: Number(p.Skin ?? p.pSkin ?? 299),
          crimes: crimesVal,
          arrests: arrestsVal,
          value: crimesVal,
          unit: 'Crimes'
        };
      });

      ranked.sort((a, b) => b.value - a.value);
      const top20 = ranked.slice(0, 20);

      return res.json({ category, highscores: top20 });
    });
    return;
  }

  if (category === 'skins') {
    sampDb.query("SELECT * FROM players LIMIT 1000", (err, players) => {
      if (err || !players) return res.json({ category, highscores: [] });

      const skinCounts = {};
      players.forEach(p => {
        const skinId = Number(p.Skin ?? p.pSkin ?? 0);
        if (skinId >= 0) {
          skinCounts[skinId] = (skinCounts[skinId] || 0) + 1;
        }
      });

      const sorted = Object.keys(skinCounts)
        .map(skin => ({
          name: `Skin ID #${skin}`,
          skin: Number(skin),
          skinId: Number(skin),
          value: skinCounts[skin],
          unit: 'Players'
        }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 20);

      return res.json({ category, highscores: sorted });
    });
    return;
  }

  // Standard Player Leaderboard
  sampDb.query("SELECT * FROM players LIMIT 1000", (err, players) => {
    if (err || !players || players.length === 0) {
      return res.json({ category, highscores: [] });
    }

    const mapPlayerVal = (p) => {
      if (category === 'wealth') {
        const cash = Number(p.Cash ?? p.pMoney ?? p.Money ?? 0);
        const bank = Number(p.Bank ?? p.pBank ?? 0);
        return cash + bank;
      }
      if (category === 'materials') {
        return Number(p.Materials ?? p.pMaterials ?? p.Mats ?? p.pMats ?? 0);
      }
      if (category === 'kills') {
        return Number(p.PaintballKills ?? p.pPaintballKills ?? p.PBKills ?? p.pPBKills ?? p.Paintball ?? p.pPaintball ?? p.PBK ?? p.PaintBallKills ?? p.pPaintBallKills ?? p.Kills ?? p.pKills ?? p.Killed ?? 0);
      }
      if (category === 'hours') {
        return Number(p.ConnectTime ?? p.pConnectTime ?? p.Hours ?? p.pHours ?? 0);
      }
      if (category === 'arrests') {
        return Number(p.Arrests ?? p.Arrested ?? p.pArrests ?? 0);
      }
      if (category === 'lawyer') {
        return Number(p.LawyerFreed ?? p.pLawyerFreed ?? p.Freed ?? p.pFreed ?? p.LawyerFree ?? p.pLawyerFree ?? p.Free ?? p.pFree ?? p.LawyerSkill ?? p.pLawyerSkill ?? p.LawSkill ?? 0);
      }
      if (category === 'detective') {
        return Number(p.DetectiveSkill ?? p.pDetectiveSkill ?? p.Finds ?? p.pFinds ?? p.Found ?? p.pFound ?? p.DetSkill ?? p.pDetSkill ?? 0);
      }
      if (category === 'arms') {
        return Number(p.GunsMade ?? p.pGunsMade ?? p.WeaponsMade ?? p.pWeaponsMade ?? p.ArmsMade ?? p.pArmsMade ?? p.ArmsSkill ?? p.pArmsSkill ?? p.MaterialsSkill ?? p.pMaterialsSkill ?? 0);
      }
      if (category === 'mechanic') {
        return Number(p.Repaired ?? p.pRepaired ?? p.MechanicRepairs ?? p.pMechanicRepairs ?? p.MechRepairs ?? p.pMechRepairs ?? p.Repairs ?? p.pRepairs ?? p.MechSkill ?? p.pMechSkill ?? p.MechanicSkill ?? 0);
      }
      if (category === 'boxing') {
        return Number(p.BoxWins ?? p.pBoxWins ?? p.BoxingWins ?? p.pBoxingWins ?? p.BoxWon ?? p.pBoxWon ?? p.FightsWon ?? p.pFightsWon ?? p.FightWins ?? p.pFightWins ?? p.BoxerWins ?? p.pBoxerWins ?? p.BoxSkill ?? p.pBoxSkill ?? p.BoxingSkill ?? p.pBoxingSkill ?? 0);
      }
      if (category === 'fishing') {
        return Number(p.FishCaught ?? p.pFishCaught ?? p.FishesCaught ?? p.pFishesCaught ?? p.Fishes ?? p.pFishes ?? p.Fish ?? p.pFish ?? p.FishSkill ?? p.pFishSkill ?? p.FishingSkill ?? p.pFishingSkill ?? 0);
      }
      if (category === 'trucker') {
        return Number(p.Deliveries ?? p.pDeliveries ?? p.TruckerRuns ?? p.pTruckerRuns ?? p.TruckRuns ?? p.pTruckRuns ?? p.TruckSkill ?? p.pTruckSkill ?? p.TruckerSkill ?? 0);
      }
      if (category === 'carjacker') {
        return Number(p.CarsStolen ?? p.pCarsStolen ?? p.CarsSold ?? p.pCarsSold ?? p.Carjacker ?? p.pCarjacker ?? p.CarSkill ?? p.pCarSkill ?? p.CarjackerSkill ?? 0);
      }

      // Check job skill columns
      if (jobSkillCols[category]) {
        for (const col of jobSkillCols[category]) {
          if (p[col] !== undefined && p[col] !== null) {
            return Number(p[col]);
          }
        }
      }

      return Number(p.Level ?? 1);
    };

    const unitMap = {
      wealth: '$',
      materials: 'Mats',
      kills: 'Kills',
      hours: 'Hrs',
      arrests: 'Arrests',
      crimes: 'Crimes',
      trucker: '',
      mechanic: '',
      arms: '',
      detective: '',
      lawyer: '',
      drugs: '',
      boxing: '',
      fishing: '',
      carjacker: '',
      smuggler: '',
      prostitute: ''
    };

    const ranked = players.map(p => {
      const item = {
        username: p.Username || p.username || 'Unknown',
        level: Number(p.Level ?? p.pLevel ?? 1),
        skin: Number(p.Skin ?? p.pSkin ?? 299),
        value: mapPlayerVal(p),
        unit: unitMap[category] !== undefined ? unitMap[category] : ''
      };

      if (category === 'crimes' || category === 'arrests') {
        const cName = p.CrimeRecord || p.MainCrime || p.pCrimeRecord || p.Crime || p.ChargesRecord;
        if (cName) item.crimeName = cName;
      }

      return item;
    });
    const sorted = ranked.sort((a, b) => b.value - a.value);
    const nonZero = sorted.filter(p => p.value > 0);
    const finalRanked = (nonZero.length > 0 ? nonZero : sorted).slice(0, 20);

    res.json({ category, highscores: finalRanked });
  });
});

server.listen(5000, () => console.log("Server is running on port 5000"));

app.get('/api/ucp/debug-tables', (req, res) => {
  sampDb.query("SHOW TABLES", (err, tables) => {
    const tableList = tables ? tables.map(t => Object.values(t)[0]) : [];
    sampDb.query("DESCRIBE houses", (errH, houseCols) => {
      sampDb.query("DESCRIBE businesses", (errB, bizzCols) => {
        sampDb.query("SHOW TABLES LIKE '%key%'", (errK, keyTables) => {
          sampDb.query("SELECT * FROM houses LIMIT 1", (errH1, hSample) => {
            sampDb.query("SELECT * FROM businesses LIMIT 1", (errB1, bSample) => {
              res.json({
                tables: tableList,
                keyTables,
                houseColumns: houseCols ? houseCols.map(c => c.Field) : errH ? errH.message : null,
                businessColumns: bizzCols ? bizzCols.map(c => c.Field) : errB ? errB.message : null,
                houseSample: hSample && hSample[0] ? hSample[0] : null,
                businessSample: bSample && bSample[0] ? bSample[0] : null
              });
            });
          });
        });
      });
    });
  });
});

app.get('/api/debug/player-columns', (req, res) => {
  sampDb.query("SHOW TABLES", (errT, tables) => {
    const tableList = tables ? tables.map(t => Object.values(t)[0]) : [];
    sampDb.query("DESCRIBE players", (err, cols) => {
      if (err || !cols) return res.json({ tables: tableList, error: err ? err.message : 'No columns found' });
      const allFields = cols.map(c => c.Field);
      
      sampDb.query("SELECT * FROM players LIMIT 1", (errP, players) => {
        const sample = players && players[0] ? players[0] : {};

        const killTables = tableList.filter(t => /kill|arena|pb|paintball|event|dm|stat|match/i.test(t));
        const killCols = allFields.filter(f => /kill|death|arena|event|match|dm|kd|stat|win/i.test(f));

        sampDb.query("DESCRIBE kills", (errK, kCols) => {
          sampDb.query("SELECT * FROM kills LIMIT 3", (errK1, kSample) => {
            res.json({
              killsTableColumns: kCols ? kCols.map(c => c.Field) : null,
              killsTableSample: kSample || [],
              potentialKillTables: killTables,
              potentialKillColumns: killCols,
              databaseTables: tableList,
              totalPlayerColumns: allFields.length,
              sampleRecord: sample
            });
          });
        });
      });
    });
  });
});

app.get('/api/debug/crime-columns', (req, res) => {
  sampDb.query("SHOW TABLES", (errT, tables) => {
    const tableList = tables ? tables.map(t => Object.values(t)[0]) : [];
    const crimeTables = tableList.filter(t => /crime|arrest|jail|wanted|mdc/i.test(t));
    
    sampDb.query("DESCRIBE players", (err, cols) => {
      if (err || !cols) return res.json({ crimeTables, error: err ? err.message : 'No columns' });
      const allFields = cols.map(c => c.Field);
      const crimeCols = allFields.filter(f => /crime|arrest|jail|wanted|mdc|charge/i.test(f));

      sampDb.query("SELECT Username, Crimes, Arrested, WantedLevel, Jailed, JailTime FROM players LIMIT 10", (errP, players) => {
        res.json({
          crimeAndArrestTables: crimeTables,
          crimeAndArrestColumnsInPlayers: crimeCols,
          playersData: players || [],
        });
      });
    });
  });
});

app.get('/api/debug/factions', (req, res) => {
  sampDb.query("DESCRIBE factions", (errF1, colsF) => {
    sampDb.query("DESCRIBE families", (errFam1, colsFam) => {
      sampDb.query("DESCRIBE gangs", (errG1, colsG) => {
        sampDb.query("SELECT * FROM factions LIMIT 10", (errF, factions) => {
          sampDb.query("SELECT * FROM families LIMIT 10", (errFam, families) => {
            sampDb.query("SELECT * FROM gangs LIMIT 10", (errG, gangs) => {
              res.json({
                factionsColumns: colsF ? colsF.map(c => c.Field) : (errF1 ? errF1.message : null),
                familiesColumns: colsFam ? colsFam.map(c => c.Field) : (errFam1 ? errFam1.message : null),
                gangsColumns: colsG ? colsG.map(c => c.Field) : (errG1 ? errG1.message : null),
                factionsSample: factions || [],
                familiesSample: families || [],
                gangsSample: gangs || []
              });
            });
          });
        });
      });
    });
  });
});

app.get('/api/debug/all-columns', (req, res) => {
  sampDb.query(`
    SELECT TABLE_NAME, COLUMN_NAME 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_SCHEMA = DATABASE() 
    ORDER BY TABLE_NAME, ORDINAL_POSITION
  `, (err, rows) => {
    if (err || !rows) return res.json({ error: err ? err.message : 'Database error' });

    const result = {};
    rows.forEach(r => {
      if (!result[r.TABLE_NAME]) result[r.TABLE_NAME] = [];
      result[r.TABLE_NAME].push(r.COLUMN_NAME);
    });

    res.json({
      totalTables: Object.keys(result).length,
      allTablesAndColumns: result
    });
  });
});
