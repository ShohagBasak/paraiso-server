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
  description TEXT DEFAULT '',            -- role description
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
