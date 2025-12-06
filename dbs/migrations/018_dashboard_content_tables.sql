-- ============================================================================
-- SSH Guardian v3.0 - Dashboard Content Tables
-- Migration: 018
-- Date: 2025-12-06
-- Purpose: Store thesis and user guide content for dashboard home page
-- ============================================================================

-- ============================================================================
-- USER GUIDE STEPS (Wizard Content)
-- ============================================================================
CREATE TABLE IF NOT EXISTS guide_steps (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Step Identification
    step_number INT NOT NULL UNIQUE,
    step_key VARCHAR(50) NOT NULL UNIQUE COMMENT 'Programmatic key e.g., welcome, architecture',

    -- Content
    title VARCHAR(255) NOT NULL,
    subtitle VARCHAR(500) NULL,
    content_html MEDIUMTEXT NOT NULL COMMENT 'HTML content for the step',
    tips_html TEXT NULL COMMENT 'Tips/notes section HTML',

    -- Visual
    icon VARCHAR(50) NULL COMMENT 'Icon class or emoji',
    image_url VARCHAR(500) NULL COMMENT 'Screenshot or diagram URL',

    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    display_order INT DEFAULT 0,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_step_number (step_number),
    KEY idx_display_order (display_order),
    KEY idx_is_active (is_active)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='User guide wizard steps content';

-- ============================================================================
-- THESIS SECTIONS (Research Paper Content)
-- ============================================================================
CREATE TABLE IF NOT EXISTS thesis_sections (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Section Identification
    section_key VARCHAR(100) NOT NULL UNIQUE COMMENT 'Programmatic key e.g., abstract, chapter1_intro',
    parent_key VARCHAR(100) NULL COMMENT 'Parent section key for nesting',

    -- Section Info
    chapter_number VARCHAR(20) NULL COMMENT 'e.g., 1, 2.1, 3.2.1',
    title VARCHAR(500) NOT NULL,

    -- Content
    content_html MEDIUMTEXT NOT NULL COMMENT 'HTML content',

    -- Navigation
    display_order INT DEFAULT 0,
    toc_level INT DEFAULT 1 COMMENT 'TOC indentation level (1-4)',
    show_in_toc BOOLEAN DEFAULT TRUE,

    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,
    word_count INT DEFAULT 0,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_parent (parent_key),
    KEY idx_display_order (display_order),
    KEY idx_chapter (chapter_number),
    KEY idx_is_active (is_active)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Research thesis sections content';

-- ============================================================================
-- THESIS FIGURES (Images, Diagrams, Charts)
-- ============================================================================
CREATE TABLE IF NOT EXISTS thesis_figures (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Figure Identification
    figure_key VARCHAR(100) NOT NULL UNIQUE,
    section_key VARCHAR(100) NULL COMMENT 'Associated thesis section',

    -- Figure Info
    figure_number VARCHAR(20) NOT NULL COMMENT 'e.g., 1.1, 2.3',
    caption VARCHAR(1000) NOT NULL,
    alt_text VARCHAR(500) NULL,

    -- Content Type
    figure_type ENUM('image', 'diagram', 'chart', 'screenshot', 'code') NOT NULL,

    -- Content (one of these should be filled)
    image_url VARCHAR(500) NULL COMMENT 'External or static file URL',
    svg_content MEDIUMTEXT NULL COMMENT 'Inline SVG for diagrams',
    chart_config JSON NULL COMMENT 'Chart.js configuration',
    code_content TEXT NULL COMMENT 'Code snippet',
    code_language VARCHAR(50) NULL COMMENT 'Syntax highlighting language',

    -- Display
    width VARCHAR(50) DEFAULT '100%',
    display_order INT DEFAULT 0,

    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_section (section_key),
    KEY idx_figure_number (figure_number),
    KEY idx_figure_type (figure_type)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Thesis figures, diagrams, and charts';

-- ============================================================================
-- THESIS TABLES (Data Tables)
-- ============================================================================
CREATE TABLE IF NOT EXISTS thesis_tables (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Table Identification
    table_key VARCHAR(100) NOT NULL UNIQUE,
    section_key VARCHAR(100) NULL COMMENT 'Associated thesis section',

    -- Table Info
    table_number VARCHAR(20) NOT NULL COMMENT 'e.g., 1.1, 2.3',
    caption VARCHAR(1000) NOT NULL,

    -- Content
    headers JSON NOT NULL COMMENT 'Array of column headers',
    row_data JSON NOT NULL COMMENT 'Array of row arrays',
    footer_html TEXT NULL COMMENT 'Table footer/notes',

    -- Display
    is_striped BOOLEAN DEFAULT TRUE,
    is_hoverable BOOLEAN DEFAULT TRUE,
    display_order INT DEFAULT 0,

    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_section (section_key),
    KEY idx_table_number (table_number)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Thesis data tables';

-- ============================================================================
-- THESIS REFERENCES (Bibliography)
-- ============================================================================
CREATE TABLE IF NOT EXISTS thesis_references (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Reference Identification
    ref_key VARCHAR(100) NOT NULL UNIQUE COMMENT 'Citation key e.g., [1], [SSH2020]',

    -- Citation Info
    authors VARCHAR(1000) NOT NULL,
    title VARCHAR(1000) NOT NULL,
    publication VARCHAR(500) NULL COMMENT 'Journal, Conference, Website',
    year INT NULL,

    -- Additional Info
    volume VARCHAR(50) NULL,
    issue VARCHAR(50) NULL,
    pages VARCHAR(50) NULL,
    doi VARCHAR(255) NULL,
    url VARCHAR(1000) NULL,
    accessed_date DATE NULL,

    -- Type
    ref_type ENUM('journal', 'conference', 'book', 'website', 'report', 'thesis', 'other') DEFAULT 'other',

    -- Display
    display_order INT DEFAULT 0,
    formatted_citation TEXT NULL COMMENT 'Pre-formatted APA/IEEE citation',

    -- Metadata
    is_active BOOLEAN DEFAULT TRUE,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    KEY idx_ref_type (ref_type),
    KEY idx_year (year),
    KEY idx_display_order (display_order)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Thesis bibliography references';

-- ============================================================================
-- THESIS METADATA (Project Information)
-- ============================================================================
CREATE TABLE IF NOT EXISTS thesis_metadata (
    id INT AUTO_INCREMENT PRIMARY KEY,

    meta_key VARCHAR(100) NOT NULL UNIQUE,
    meta_value TEXT NOT NULL,
    meta_type ENUM('text', 'html', 'json', 'date') DEFAULT 'text',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Thesis metadata like title, author, institution';

-- ============================================================================
-- INSERT DEFAULT METADATA
-- ============================================================================
INSERT INTO thesis_metadata (meta_key, meta_value, meta_type) VALUES
('title', 'Design and Evaluation of a Lightweight SSH Access Behavior Profiling and Anomaly Alerting Agent for Small-Scale Cloud Servers Used by Small and Medium Enterprises', 'text'),
('student_name', 'Md Sohel Rana', 'text'),
('student_id', 'TP086217', 'text'),
('institution', 'Asia Pacific University of Technology & Innovation', 'text'),
('module_code', 'CT095 6 M RMCE', 'text'),
('module_name', 'Research Methodology in Computing and Engineering', 'text'),
('supervisor', 'TS. DR. SE YONG A/L EH NOUM', 'text'),
('submission_date', '2025', 'text')
ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value);
