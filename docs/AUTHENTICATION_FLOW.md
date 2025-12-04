# SSH Guardian v3.0 - Authentication Flow

## Overview
Azure-style 2FA authentication with trusted device support for seamless re-login.

## Authentication Behavior

### First-Time Login (New Device/Browser)
1. User enters **email + password**
2. System validates credentials
3. **OTP sent to email** (6-digit code, 5-minute expiry)
4. User enters OTP
5. Session created (30-day persistent cookie)
6. User redirected to dashboard

### Subsequent Login (Trusted Device)
1. User enters **email + password only**
2. System detects valid session cookie
3. **OTP skipped automatically**
4. User redirected to dashboard immediately

## When OTP is Required Again
- Session cookie expired (30 days)
- User cleared browser cookies
- User logged out manually
- Different browser or device
- Incognito/private browsing mode

## Session Details
- **Duration**: 30 days
- **Storage**: HTTP-only secure cookie
- **Token**: Cryptographically secure random token
- **Validation**: Every request checks session validity

## Security Features
- Password hashing: bcrypt
- Account lockout: 5 failed attempts → 30 min lock
- OTP expiry: 5 minutes
- Session token: 64-char random hex
- Audit logging: All auth events tracked

## API Endpoints

### POST /auth/login
**Request:**
```json
{
  "email": "admin@sshguardian.local",
  "password": "Admin@123"
}
```

**Response (Trusted Device):**
```json
{
  "success": true,
  "skip_otp": true,
  "message": "Login successful",
  "user": {
    "id": 1,
    "email": "admin@sshguardian.local",
    "full_name": "Admin",
    "role": "Super Admin",
    "permissions": [...]
  }
}
```

**Response (New Device):**
```json
{
  "success": true,
  "skip_otp": false,
  "message": "Verification code sent to your email",
  "user_id": 1,
  "email_sent": true,
  "otp_for_dev": "123456"  // Only in development
}
```

### POST /auth/verify-otp
**Request:**
```json
{
  "user_id": 1,
  "otp_code": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {...}
}
```
*Sets session cookie in response*

### POST /auth/logout
Deletes session and clears cookie.

### GET /auth/check-session
Returns authentication status without requiring login.

### GET /auth/me
Returns current user details (requires authentication).

## Test Credentials
- **Email**: admin@sshguardian.local
- **Password**: Admin@123
- **Role**: Super Admin

## Testing the Flow

### Test 1: First Login (OTP Required)
1. Open http://localhost:8081/login in incognito mode
2. Enter: admin@sshguardian.local / Admin@123
3. Check console/email for OTP code
4. Enter 6-digit OTP
5. Should redirect to dashboard

### Test 2: Trusted Device (Skip OTP)
1. Stay logged in from Test 1
2. Visit login page again
3. Enter: admin@sshguardian.local / Admin@123
4. Should skip OTP and go directly to dashboard

### Test 3: After Logout (OTP Required)
1. Click "Sign out" button
2. Login again with same credentials
3. OTP required again (cookie cleared)

## Implementation Details

### Backend Logic (auth_routes.py:25-127)
```python
# Check if user has valid existing session (trusted device)
session_token = request.cookies.get('session_token')

if session_token:
    session_data = SessionManager.validate_session(session_token)

    # If valid session exists and belongs to same user, skip OTP
    if session_data and session_data['id'] == user['id']:
        # Log in directly without OTP
        return jsonify({'success': True, 'skip_otp': True, ...})

# No valid session - require OTP verification
otp_code = OTPManager.create_otp(user['id'], 'login', request.remote_addr)
```

### Frontend Logic (login.html:446-453)
```javascript
if (response.ok) {
    // Check if OTP can be skipped (trusted device)
    if (data.skip_otp) {
        showSuccess('Welcome back! Redirecting...');
        setTimeout(() => {
            window.location.href = '/dashboard';
        }, 800);
        return;
    }
    // Need OTP verification...
}
```

## Audit Trail
All authentication events are logged:
- `login_otp_sent` - OTP sent for new device
- `login_trusted_device` - Logged in via trusted device (skip OTP)
- `login_success` - Successful OTP verification
- `login_failed` - Failed password attempt
- `login_otp_failed` - Failed OTP attempt
- `logout` - User logged out

Check `audit_logs` table for full history.
