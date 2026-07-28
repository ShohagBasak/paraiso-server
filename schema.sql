-- ====================================================================
-- PARAISO GAMING PORTAL - MYSQL DATABASE SCHEMA
-- ====================================================================

-- 1. USERS TABLE
-- Stores user accounts and administrative roles
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- 2. BANNER SLIDES TABLE
-- Stores dynamic home page SwiperBanner slides with color/size customization and sort indices
CREATE TABLE IF NOT EXISTS banner_slides (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL DEFAULT '',
  subtitle VARCHAR(255) NOT NULL DEFAULT '',
  image_url TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  sort_order INT DEFAULT 0,
  title_color VARCHAR(50) DEFAULT '#ffffff',
  subtitle_color VARCHAR(50) DEFAULT '#cbd5e1',
  title_size VARCHAR(100) DEFAULT 'text-3xl sm:text-5xl md:text-6xl',
  subtitle_size VARCHAR(100) DEFAULT 'text-base sm:text-xl md:text-2xl'
);


-- 3. ANNOUNCEMENTS TABLE
-- Stores news/updates shown in FeaturesSlider with color/size formatting and ordering
CREATE TABLE IF NOT EXISTS announcements (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  image_url TEXT,
  link TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  sort_order INT DEFAULT 0,
  title_color VARCHAR(50) DEFAULT '#ffffff',
  description_color VARCHAR(50) DEFAULT '#cbd5e1',
  title_size VARCHAR(100) DEFAULT 'text-xl md:text-2xl',
  description_size VARCHAR(100) DEFAULT 'text-sm'
);


-- 4. STAFF ROSTER TABLE
-- Stores dynamic administrative staff roster categorized by departments
CREATE TABLE IF NOT EXISTS staff (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  category VARCHAR(100) NOT NULL, -- e.g. 'Management', 'Assistant Management', 'Head Admin', 'Senior Admin', 'General Admin', 'Junior Admin', 'Developers'
  role VARCHAR(255) DEFAULT '',
  country VARCHAR(10) DEFAULT '', -- e.g. 'us', 'bd', 'ph', etc.
  image_url TEXT,
  sort_order INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- 5. STAFF ROSTER ROLES (DEPARTMENTS) TABLE
-- Stores custom departments/roles, colors, icons, and display ordering
CREATE TABLE IF NOT EXISTS staff_roles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  color VARCHAR(50) DEFAULT '#ffffff',
  icon_name VARCHAR(100) DEFAULT 'FaUserShield',
  sort_order INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- 6. GOVERNMENT ROSTER TABLE
-- Stores faction/government roster members with section grouping
CREATE TABLE IF NOT EXISTS roster_members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  section VARCHAR(100) NOT NULL,          -- e.g. 'FEDERAL GOVERNMENT', 'LAW ENFORCEMENT & EMERGENCY SERVICES', 'AGENCIES'
  section_order INT DEFAULT 0,            -- controls section display order
  title VARCHAR(255) NOT NULL,            -- e.g. 'PRESIDENT', 'CHIEF OF POLICE'
  name VARCHAR(255) DEFAULT 'Vacant',     -- member name or 'Vacant'
  description TEXT,                       -- role description
  sort_order INT DEFAULT 0,               -- within-section order
  color VARCHAR(50) DEFAULT NULL,         -- custom role/text color hex or name
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- 7. ROSTER SECTIONS / FACTIONS TABLE
-- Stores explicit sections/factions for the Government Roster
CREATE TABLE IF NOT EXISTS roster_sections (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  sort_order INT DEFAULT 0,
  color VARCHAR(50) DEFAULT NULL,
  icon VARCHAR(50) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- 8. DONATE CATEGORIES TABLE
CREATE TABLE IF NOT EXISTS donate_categories (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  sort_order INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


-- 9. DONATE ITEMS TABLE
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
);


-- 10. PURCHASE TICKETS TABLE
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
);


-- 11. TICKET MESSAGES TABLE
CREATE TABLE IF NOT EXISTS ticket_messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ticket_id INT NOT NULL,
  sender_id INT NOT NULL,
  message TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (ticket_id) REFERENCES purchase_tickets(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
);

