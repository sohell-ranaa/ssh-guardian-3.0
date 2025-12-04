# SSH Guardian v2.0 - Authentication System Reference

**Purpose:** Complete authentication system documentation from v2.0 for v3.0 development
**Created:** 2025-12-04
**Source:** `/home/rana-workspace/ssh_guardian_2.0/src/dashboard/`

---

## 🔐 v2.0 Authentication Overview

v2.0 uses a **robust two-factor authentication system** with:
- ✅ Password + OTP (One-Time Password via email)
- ✅ Role-Based Access Control (RBAC)
- ✅ Session management with secure HTTP-only cookies
- ✅ Account lockout after failed attempts
- ✅ Audit logging for all security actions
- ✅ Password strength validation

---

## 📁 Authentication Files

### Core Files (v2.0)

1. **`auth.py`** - Authentication system core
   - Location: `/home/rana-workspace/ssh_guardian_2.0/src/dashboard/auth.py`
   - Lines: 727
   - Classes:
     - `EmailService` - OTP email sending
     - `PasswordManager` - Password hashing/validation
     - `OTPManager` - OTP generation/verification
     - `SessionManager` - Session token management
     - `UserManager` - User CRUD operations
     - `AuditLogger` - Security audit logging

2. **`auth_routes.py`** - Flask authentication routes
   - Location: `/home/rana-workspace/ssh_guardian_2.0/src/dashboard/auth_routes.py`
   - Lines: 472
   - Endpoints:
     - `POST /auth/login` - Step 1: Password validation, send OTP
     - `POST /auth/verify-otp` - Step 2: OTP verification, create session
     - `POST /auth/logout` - Logout and delete session
     - `GET /auth/me` - Get current user info
     - `GET /auth/check-session` - Verify session validity
     - `GET /auth/users` - List all users (admin only)
     - `POST /auth/users` - Create new user (admin only)
     - `PUT /auth/users/<id>` - Update user (admin only)
     - `DELETE /auth/users/<id>` - Delete user (admin only)
     - `GET /auth/roles` - List all roles
     - `POST /auth/change-password` - Change own password
     - `GET /auth/audit-logs` - View audit logs (admin only)

3. **`login.html`** - Login page template
   - Location: `/home/rana-workspace/ssh_guardian_2.0/src/dashboard/templates/login.html`
   - Features: Two-step login form (password then OTP)

---

## 🔑 Authentication Flow

### Login Process (2-Step)

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: Password Validation                                 │
├─────────────────────────────────────────────────────────────┤
│ 1. User enters email + password                            │
│ 2. Backend validates password                              │
│ 3. Check account active status                             │
│ 4. Check if account locked (failed attempts)               │
│ 5. Generate 6-digit OTP                                    │
│ 6. Send OTP via email                                      │
│ 7. Return success (don't reveal if password wrong)         │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: OTP Verification                                    │
├─────────────────────────────────────────────────────────────┤
│ 1. User enters 6-digit OTP                                 │
│ 2. Backend verifies OTP (valid & not expired)              │
│ 3. Check OTP not already used                              │
│ 4. Reset failed login attempts                             │
│ 5. Update last_login timestamp                             │
│ 6. Generate secure session token                           │
│ 7. Store session in database                               │
│ 8. Return session cookie (HTTP-only, secure)               │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ AUTHENTICATED SESSION                                       │
├─────────────────────────────────────────────────────────────┤
│ - Session stored in user_sessions table                    │
│ - Session token in HTTP-only cookie                        │
│ - Valid for 30 days (remember me) or 24 hours              │
│ - Validated on every protected request                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Configuration

### Session Settings

```python
SESSION_DURATION_DAYS = 30          # Remember me duration
OTP_VALIDITY_MINUTES = 5            # OTP expires after 5 minutes
MAX_FAILED_ATTEMPTS = 5             # Lock account after 5 failed attempts
LOCKOUT_DURATION_MINUTES = 30       # Account locked for 30 minutes
```

### Password Requirements

- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

### Session Cookie Settings

```python
response.set_cookie(
    'session_token',
    session_token,
    max_age=30*24*60*60 if remember_me else 24*60*60,  # 30 days or 24 hours
    secure=False,      # Set to True in production with HTTPS
    httponly=True,     # Not accessible via JavaScript (XSS protection)
    samesite='Lax',    # CSRF protection
    path='/'           # Available for all paths
)
```

---

## 🎭 Role-Based Access Control (RBAC)

### Database Tables

**roles** - Role definitions
```sql
CREATE TABLE roles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**users** - User accounts with role assignment
```sql
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    is_active TINYINT(1) DEFAULT 1,
    last_login TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);
```

### Default Roles

1. **Super Admin** (role_id: 1)
   ```json
   {
     "dashboard_access": true,
     "user_management": true,
     "simulation_management": true,
     "system_settings": true,
     "audit_logs": true,
     "ip_management": true,
     "agent_management": true
   }
   ```

2. **Admin** (role_id: 2)
   ```json
   {
     "dashboard_access": true,
     "simulation_management": true,
     "ip_management": true,
     "agent_management": true
   }
   ```

3. **Analyst** (role_id: 3)
   ```json
   {
     "dashboard_access": true,
     "simulation_management": false,
     "ip_management": false
   }
   ```

4. **Viewer** (role_id: 4)
   ```json
   {
     "dashboard_access": true
   }
   ```

### Decorators for Protected Routes

```python
@login_required
def protected_route():
    # Requires valid session
    pass

@permission_required('user_management')
def admin_only_route():
    # Requires specific permission
    pass

@role_required('Super Admin', 'Admin')
def multi_role_route():
    # Requires one of specified roles
    pass
```

---

## 📧 Email Service (OTP Delivery)

### Configuration (Environment Variables)

```python
EMAIL_CONFIG = {
    'smtp_host': os.getenv('SMTP_HOST', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', 587)),
    'smtp_user': os.getenv('SMTP_USER', ''),
    'smtp_password': os.getenv('SMTP_PASSWORD', ''),
    'from_email': os.getenv('FROM_EMAIL', ''),
    'from_name': os.getenv('FROM_NAME', 'SSH Guardian')
}
```

### OTP Email Template

The OTP email uses a **modern gradient design** with:
- Purple gradient header (#667eea to #764ba2)
- Large, centered OTP code (32px, letter-spacing)
- 5-minute validity warning
- Security warnings
- Professional footer

**Template Location:** `auth.py:90-150` (EmailService.send_otp_email method)

---

## 🗄️ Database Tables Used

### 1. users
- Primary table for user accounts
- Stores password hash, role, active status
- Tracks failed attempts and lockout

### 2. roles
- Defines available roles
- Stores permissions as JSON

### 3. user_sessions
```sql
CREATE TABLE user_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### 4. user_otps
```sql
CREATE TABLE user_otps (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    purpose ENUM('login', 'password_reset', 'email_verification') DEFAULT 'login',
    expires_at TIMESTAMP NOT NULL,
    is_used TINYINT(1) DEFAULT 0,
    used_at TIMESTAMP NULL,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

### 5. audit_logs
```sql
CREATE TABLE audit_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
```

**Logged Actions:**
- `login_otp_sent`
- `login_otp_failed`
- `login_success`
- `login_failed`
- `logout`
- `password_changed`
- `user_created`
- `user_updated`
- `user_deleted`

---

## 🎨 v2.0 Login UI Design

### Current Design (v2.0)
- Traditional form-based layout
- Two-step process (password → OTP)
- Purple/violet gradient theme
- Centered card design
- Clean and functional

### Design Reference
File: `/home/rana-workspace/ssh_guardian_2.0/src/dashboard/templates/login.html` (20,283 bytes)

---

## 🚀 v3.0 Requirements

### Keep from v2.0:
✅ Two-factor authentication (Password + OTP)
✅ Session management
✅ RBAC with permissions
✅ Account lockout
✅ Audit logging
✅ Password strength validation
✅ Email OTP delivery

### New for v3.0:
🎨 **Azure-style Design:**
- Icon-based UI
- Small, compact fonts
- Clean, minimal design
- Blue color scheme (Azure theme)
- Fluent Design System inspired
- Modern, professional look

**Design Inspiration:** Microsoft Azure Portal
- Clean white background
- Subtle shadows
- Icon buttons
- Compact form fields
- Modern typography (Segoe UI / Roboto)

---

## 🎨 Proposed v3.0 Design Specifications

### Color Palette (Azure-inspired)

```css
/* Primary Colors */
--azure-blue: #0078D4;          /* Microsoft Azure blue */
--azure-dark: #004C87;          /* Darker blue for hover */
--azure-light: #50E6FF;         /* Light accent blue */

/* Neutral Colors */
--background: #F3F2F1;          /* Light gray background */
--surface: #FFFFFF;             /* White cards */
--border: #EDEBE9;              /* Subtle borders */
--text-primary: #323130;        /* Dark gray text */
--text-secondary: #605E5C;      /* Medium gray text */
--text-hint: #A19F9D;           /* Light gray hint text */

/* Status Colors */
--success: #0B7D43;             /* Green */
--warning: #FF8C00;             /* Orange */
--error: #D13438;               /* Red */
```

### Typography

```css
/* Font Stack */
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
             'Helvetica Neue', Arial, sans-serif;

/* Font Sizes (Compact) */
--font-xs: 11px;                /* Hints, labels */
--font-sm: 12px;                /* Form text, buttons */
--font-md: 14px;                /* Body text */
--font-lg: 16px;                /* Card titles */
--font-xl: 20px;                /* Page titles */

/* Font Weights */
--weight-normal: 400;
--weight-medium: 500;
--weight-semibold: 600;
```

### Layout Specifications

```css
/* Login Card */
width: 400px;
padding: 32px;
background: var(--surface);
border-radius: 8px;
box-shadow: 0 2px 4px rgba(0,0,0,0.08);

/* Input Fields */
height: 32px;                   /* Compact height */
padding: 8px 12px;
font-size: 12px;
border: 1px solid var(--border);
border-radius: 2px;             /* Subtle rounding */

/* Buttons */
height: 32px;                   /* Compact height */
padding: 0 16px;
font-size: 12px;
font-weight: 600;
border-radius: 2px;
text-transform: none;           /* No uppercase */

/* Icons */
size: 16px;                     /* Small, consistent */
color: var(--azure-blue);
```

### Component Examples

**Primary Button:**
```css
background: var(--azure-blue);
color: white;
border: none;
box-shadow: 0 2px 4px rgba(0,120,212,0.2);

&:hover {
  background: var(--azure-dark);
  box-shadow: 0 4px 8px rgba(0,120,212,0.3);
}
```

**Input Field:**
```css
border: 1px solid var(--border);
background: white;

&:focus {
  border-color: var(--azure-blue);
  outline: none;
  box-shadow: 0 0 0 2px rgba(0,120,212,0.1);
}
```

---

## 🔨 Implementation Plan for v3.0

### Phase 1: Core Authentication (Copy from v2)
- [x] Document v2 authentication system
- [ ] Copy `auth.py` to v3.0 (`src/core/auth.py`)
- [ ] Copy `auth_routes.py` to v3.0 (`src/dashboard/auth_routes.py`)
- [ ] Update database connection imports
- [ ] Test all authentication functions

### Phase 2: Azure-Style Login UI
- [ ] Create new `login.html` with Azure design
- [ ] Icon-based layout (email icon, password icon, OTP icon)
- [ ] Compact form fields (32px height)
- [ ] Small fonts (12px body, 11px labels)
- [ ] Azure blue color scheme
- [ ] Smooth animations and transitions
- [ ] Responsive design

### Phase 3: Session Management
- [ ] Keep v2.0 session logic (proven and secure)
- [ ] HTTP-only cookies
- [ ] 30-day / 24-hour sessions
- [ ] Automatic session validation

### Phase 4: RBAC Integration
- [ ] Keep v2.0 roles and permissions
- [ ] Same decorator pattern
- [ ] Same permission checks
- [ ] Migrate roles data to v3.0 database

### Phase 5: Testing
- [ ] Test login flow (password + OTP)
- [ ] Test session persistence
- [ ] Test permission checks
- [ ] Test account lockout
- [ ] Test audit logging
- [ ] Cross-browser testing

---

## 📝 API Endpoints Summary

### Authentication Endpoints

```
POST   /auth/login              Step 1: Validate password, send OTP
POST   /auth/verify-otp         Step 2: Verify OTP, create session
POST   /auth/logout             Logout and delete session
GET    /auth/me                 Get current user info
GET    /auth/check-session      Check if session is valid
```

### User Management (Admin Only)

```
GET    /auth/users              List all users
POST   /auth/users              Create new user
PUT    /auth/users/<id>         Update user
DELETE /auth/users/<id>         Delete (deactivate) user
GET    /auth/roles              List all roles
```

### Self-Service

```
POST   /auth/change-password    Change own password
```

### Audit

```
GET    /auth/audit-logs         Get audit logs (Super Admin only)
```

---

## 🔒 Security Best Practices (v2.0 Implementation)

1. ✅ **Password Security**
   - bcrypt hashing with salt
   - Minimum 8 characters with complexity requirements
   - No plain text storage

2. ✅ **Session Security**
   - Cryptographically secure session tokens (secrets.token_urlsafe(32))
   - HTTP-only cookies (no JavaScript access)
   - SameSite=Lax (CSRF protection)
   - Secure flag for HTTPS
   - Session expiration

3. ✅ **Rate Limiting**
   - Account lockout after 5 failed attempts
   - 30-minute lockout duration
   - Resets on successful login

4. ✅ **OTP Security**
   - 6-digit random code
   - 5-minute validity
   - Single-use (marked as used after verification)
   - Stored with expiration timestamp

5. ✅ **Audit Trail**
   - All authentication events logged
   - IP address and user agent tracked
   - Immutable audit log table

6. ✅ **SQL Injection Prevention**
   - Parameterized queries everywhere
   - No string concatenation

7. ✅ **XSS Prevention**
   - HTTP-only cookies
   - Template escaping (Jinja2)

---

## 🎯 Next Steps

### Immediate Actions:
1. Create v3.0 database (`ssh_guardian_v3`)
2. Copy authentication tables from v2
3. Copy `auth.py` to v3.0
4. Copy `auth_routes.py` to v3.0
5. Design Azure-style login UI
6. Implement new login.html
7. Test authentication flow

### Success Criteria:
✅ Same authentication security as v2.0
✅ Azure-style modern UI
✅ Icon-based, compact design
✅ Small fonts (12px)
✅ Clean and professional
✅ All v2.0 features working

---

## 📞 File Locations Reference

**v2.0 Authentication (Source):**
- `/home/rana-workspace/ssh_guardian_2.0/src/dashboard/auth.py` (727 lines)
- `/home/rana-workspace/ssh_guardian_2.0/src/dashboard/auth_routes.py` (472 lines)
- `/home/rana-workspace/ssh_guardian_2.0/src/dashboard/templates/login.html` (20KB)
- `/home/rana-workspace/ssh_guardian_2.0/dbs/migrations/005_authentication_system.sql`

**v3.0 Target Locations:**
- `/home/rana-workspace/ssh_guardian_v3.0/src/core/auth.py` (to create)
- `/home/rana-workspace/ssh_guardian_v3.0/src/dashboard/auth_routes.py` (to create)
- `/home/rana-workspace/ssh_guardian_v3.0/src/dashboard/templates/login.html` (to create with Azure design)

---

**Status:** ✅ v2.0 authentication fully documented and ready for v3.0 implementation with Azure-style UI

**Last Updated:** 2025-12-04
