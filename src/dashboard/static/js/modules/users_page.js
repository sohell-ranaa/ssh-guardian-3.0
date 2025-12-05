/**
 * Users Management Page Module
 * Handles user CRUD operations
 */

(function() {
    'use strict';

    let users = [];
    let roles = [];
    let currentUserId = null;

    /**
     * Load and display Users page
     */
    window.loadUsersPage = async function() {
        console.log('Loading Users page...');

        try {
            // Load roles first, then users
            await loadRoles();
            await loadUsers();

            // Setup event listeners
            setupUsersEventListeners();

        } catch (error) {
            console.error('Error loading Users page:', error);
            showNotification('Failed to load users', 'error');
        }
    };

    /**
     * Load roles from API
     */
    async function loadRoles() {
        try {
            const response = await fetch('/api/dashboard/users/roles');
            const data = await response.json();

            if (data.success) {
                roles = data.data.roles || [];
            }
        } catch (error) {
            console.error('Error loading roles:', error);
        }
    }

    /**
     * Load users from API
     */
    async function loadUsers() {
        const container = document.getElementById('users-container');
        if (container) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #605E5C;">Loading users...</div>';
        }

        try {
            const response = await fetch('/api/dashboard/users/list');
            const data = await response.json();

            if (data.success) {
                users = data.data.users || [];
                renderUsers(users);
            } else {
                throw new Error(data.error || 'Failed to load users');
            }

        } catch (error) {
            console.error('Error loading users:', error);
            if (container) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #D13438;">Failed to load users. Please try again.</div>';
            }
        }
    }

    /**
     * Render users list
     */
    function renderUsers(usersList) {
        const container = document.getElementById('users-container');

        if (!container) return;

        if (!usersList || usersList.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 60px 20px; color: #605E5C;">
                    <div style="font-size: 48px; margin-bottom: 16px;">👥</div>
                    <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 8px; color: #323130;">No Users</h3>
                    <p style="font-size: 14px; margin-bottom: 24px;">Create your first user to get started</p>
                    <button onclick="showCreateUserModal()" class="btn btn-primary" style="padding: 10px 20px;">
                        + Create User
                    </button>
                </div>
            `;
            return;
        }

        let html = `
            <div style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; overflow: hidden;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #F3F2F1;">
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">User</th>
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Email</th>
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Role</th>
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Status</th>
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Last Login</th>
                            <th style="text-align: center; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        usersList.forEach((user, index) => {
            const isLast = index === usersList.length - 1;
            const borderStyle = isLast ? '' : 'border-bottom: 1px solid #EDEBE9;';

            const statusColor = user.is_active ? '#107C10' : '#D13438';
            const statusText = user.is_active ? 'Active' : 'Inactive';

            const roleColors = {
                'Super Admin': '#0078D4',
                'Admin': '#8764B8',
                'Analyst': '#00B294',
                'Viewer': '#605E5C'
            };
            const roleColor = roleColors[user.role_name] || '#605E5C';

            const isLocked = user.locked_until && new Date(user.locked_until) > new Date();

            html += `
                <tr style="${borderStyle}">
                    <td style="padding: 14px 16px; font-size: 14px; color: #323130;">
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <div style="width: 40px; height: 40px; border-radius: 50%; background: linear-gradient(135deg, #0078D4, #00BCF2); display: flex; align-items: center; justify-content: center; color: white; font-weight: 600; font-size: 16px;">
                                ${getInitials(user.full_name)}
                            </div>
                            <div>
                                <div style="font-weight: 500;">${user.full_name}</div>
                                <div style="font-size: 12px; color: #605E5C;">ID: ${user.id}</div>
                            </div>
                        </div>
                    </td>
                    <td style="padding: 14px 16px; font-size: 14px; color: #605E5C;">
                        <div style="display: flex; align-items: center; gap: 6px;">
                            ${user.email}
                            ${user.is_email_verified ? '<span title="Email Verified" style="color: #107C10;">✓</span>' : ''}
                        </div>
                    </td>
                    <td style="padding: 14px 16px;">
                        <span style="display: inline-block; padding: 4px 12px; background: ${roleColor}15; color: ${roleColor}; border-radius: 12px; font-size: 12px; font-weight: 500;">
                            ${user.role_name || 'Unknown'}
                        </span>
                    </td>
                    <td style="padding: 14px 16px;">
                        <div style="display: flex; flex-direction: column; gap: 4px;">
                            <span style="display: inline-flex; align-items: center; gap: 6px;">
                                <span style="width: 8px; height: 8px; border-radius: 50%; background: ${statusColor};"></span>
                                <span style="font-size: 14px; color: #605E5C;">${statusText}</span>
                            </span>
                            ${isLocked ? '<span style="font-size: 11px; color: #D13438;">🔒 Locked</span>' : ''}
                        </div>
                    </td>
                    <td style="padding: 14px 16px; font-size: 14px; color: #605E5C;">
                        ${formatTimestamp(user.last_login)}
                    </td>
                    <td style="padding: 14px 16px; text-align: center;">
                        <div style="display: flex; gap: 8px; justify-content: center; flex-wrap: wrap;">
                            <button class="btn-edit-user" data-user-id="${user.id}"
                                    style="padding: 6px 12px; font-size: 12px; background: #0078D4; color: white; border: none; border-radius: 4px; cursor: pointer;">
                                Edit
                            </button>
                            ${isLocked ? `
                                <button class="btn-unlock-user" data-user-id="${user.id}"
                                        style="padding: 6px 12px; font-size: 12px; background: #FFB900; color: #323130; border: none; border-radius: 4px; cursor: pointer;">
                                    Unlock
                                </button>
                            ` : ''}
                            <button class="btn-toggle-user" data-user-id="${user.id}" data-active="${user.is_active}"
                                    style="padding: 6px 12px; font-size: 12px; background: ${user.is_active ? '#605E5C' : '#107C10'}; color: white; border: none; border-radius: 4px; cursor: pointer;">
                                ${user.is_active ? 'Deactivate' : 'Activate'}
                            </button>
                            <button class="btn-delete-user" data-user-id="${user.id}" data-email="${user.email}"
                                    style="padding: 6px 12px; font-size: 12px; background: #D13438; color: white; border: none; border-radius: 4px; cursor: pointer;">
                                Delete
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
            </div>
        `;

        // Add modals
        html += renderCreateUserModal();
        html += renderEditUserModal();

        container.innerHTML = html;

        // Setup inline event listeners
        setupInlineEventListeners();
    }

    /**
     * Get initials from name
     */
    function getInitials(name) {
        if (!name) return '?';
        const parts = name.split(' ');
        if (parts.length >= 2) {
            return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
        }
        return name.substring(0, 2).toUpperCase();
    }

    /**
     * Format timestamp
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'Never';
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return 'Never';

        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }

    /**
     * Render Create User Modal
     */
    function renderCreateUserModal() {
        return `
            <div id="create-user-modal" class="modal-overlay" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                <div class="modal-content" style="background: #FFFFFF; border-radius: 8px; width: 100%; max-width: 500px; max-height: 90vh; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.2);">
                    <div class="modal-header" style="padding: 20px 24px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">Create New User</h3>
                        <button id="create-user-close-btn" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #605E5C; padding: 0; line-height: 1;">&times;</button>
                    </div>
                    <div class="modal-body" style="padding: 24px; overflow-y: auto;">
                        <div style="display: flex; flex-direction: column; gap: 20px;">
                            <div class="form-group">
                                <label style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Full Name <span style="color: #D13438;">*</span>
                                </label>
                                <input type="text" id="create-user-name" placeholder="John Doe"
                                       style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div class="form-group">
                                <label style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Email <span style="color: #D13438;">*</span>
                                </label>
                                <input type="email" id="create-user-email" placeholder="user@example.com"
                                       style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div class="form-group">
                                <label style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Password <span style="color: #D13438;">*</span>
                                </label>
                                <input type="password" id="create-user-password" placeholder="Minimum 8 characters"
                                       style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div class="form-group">
                                <label style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Role
                                </label>
                                <select id="create-user-role" style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                                    ${roles.map(r => `<option value="${r.id}">${r.name} - ${r.description}</option>`).join('')}
                                </select>
                            </div>
                            <div class="form-group">
                                <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                    <input type="checkbox" id="create-user-active" checked style="width: 18px; height: 18px;">
                                    <span style="font-size: 14px; color: #323130;">Active</span>
                                </label>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer" style="padding: 16px 24px; border-top: 1px solid #EDEBE9; display: flex; justify-content: flex-end; gap: 12px;">
                        <button id="create-user-cancel-btn" class="btn btn-secondary" style="padding: 10px 20px;">Cancel</button>
                        <button id="create-user-save-btn" class="btn btn-primary" style="padding: 10px 20px;">Create User</button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render Edit User Modal
     */
    function renderEditUserModal() {
        return `
            <div id="edit-user-modal" class="modal-overlay" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                <div class="modal-content" style="background: #FFFFFF; border-radius: 8px; width: 100%; max-width: 500px; max-height: 90vh; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.2);">
                    <div class="modal-header" style="padding: 20px 24px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                        <h3 id="edit-user-title" style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">Edit User</h3>
                        <button id="edit-user-close-btn" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #605E5C; padding: 0; line-height: 1;">&times;</button>
                    </div>
                    <div class="modal-body" style="padding: 24px; overflow-y: auto;">
                        <div style="display: flex; flex-direction: column; gap: 20px;">
                            <div class="form-group">
                                <label style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Full Name <span style="color: #D13438;">*</span>
                                </label>
                                <input type="text" id="edit-user-name"
                                       style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div class="form-group">
                                <label style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Email <span style="color: #D13438;">*</span>
                                </label>
                                <input type="email" id="edit-user-email"
                                       style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div class="form-group">
                                <label style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    New Password <span style="color: #605E5C; font-weight: normal;">(leave blank to keep current)</span>
                                </label>
                                <input type="password" id="edit-user-password" placeholder="Enter new password"
                                       style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div class="form-group">
                                <label style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Role
                                </label>
                                <select id="edit-user-role" style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                                    ${roles.map(r => `<option value="${r.id}">${r.name}</option>`).join('')}
                                </select>
                            </div>
                            <div class="form-group">
                                <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                    <input type="checkbox" id="edit-user-active" style="width: 18px; height: 18px;">
                                    <span style="font-size: 14px; color: #323130;">Active</span>
                                </label>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer" style="padding: 16px 24px; border-top: 1px solid #EDEBE9; display: flex; justify-content: flex-end; gap: 12px;">
                        <button id="edit-user-cancel-btn" class="btn btn-secondary" style="padding: 10px 20px;">Cancel</button>
                        <button id="edit-user-save-btn" class="btn btn-primary" style="padding: 10px 20px;">Save Changes</button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Setup inline event listeners
     */
    function setupInlineEventListeners() {
        // Edit buttons
        document.querySelectorAll('.btn-edit-user').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const userId = e.target.getAttribute('data-user-id');
                openEditUserModal(userId);
            });
        });

        // Toggle active buttons
        document.querySelectorAll('.btn-toggle-user').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const userId = e.target.getAttribute('data-user-id');
                const isActive = e.target.getAttribute('data-active') === 'true';
                const action = isActive ? 'deactivate' : 'activate';

                if (confirm(`Are you sure you want to ${action} this user?`)) {
                    await toggleUserActive(userId);
                }
            });
        });

        // Unlock buttons
        document.querySelectorAll('.btn-unlock-user').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const userId = e.target.getAttribute('data-user-id');
                await unlockUser(userId);
            });
        });

        // Delete buttons
        document.querySelectorAll('.btn-delete-user').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const userId = e.target.getAttribute('data-user-id');
                const email = e.target.getAttribute('data-email');

                if (confirm(`Are you sure you want to delete user "${email}"? This action cannot be undone.`)) {
                    await deleteUser(userId);
                }
            });
        });

        // Setup modal listeners
        setupCreateModalListeners();
        setupEditModalListeners();
    }

    /**
     * Setup Create Modal Event Listeners
     */
    function setupCreateModalListeners() {
        const modal = document.getElementById('create-user-modal');
        if (!modal) return;

        const closeBtn = document.getElementById('create-user-close-btn');
        const cancelBtn = document.getElementById('create-user-cancel-btn');
        const saveBtn = document.getElementById('create-user-save-btn');

        const closeModal = () => {
            modal.style.display = 'none';
            document.getElementById('create-user-name').value = '';
            document.getElementById('create-user-email').value = '';
            document.getElementById('create-user-password').value = '';
            document.getElementById('create-user-active').checked = true;
        };

        if (closeBtn) closeBtn.onclick = closeModal;
        if (cancelBtn) cancelBtn.onclick = closeModal;
        modal.onclick = (e) => {
            if (e.target === modal) closeModal();
        };

        if (saveBtn) {
            saveBtn.onclick = async () => {
                await createUser();
            };
        }
    }

    /**
     * Setup Edit Modal Event Listeners
     */
    function setupEditModalListeners() {
        const modal = document.getElementById('edit-user-modal');
        if (!modal) return;

        const closeBtn = document.getElementById('edit-user-close-btn');
        const cancelBtn = document.getElementById('edit-user-cancel-btn');
        const saveBtn = document.getElementById('edit-user-save-btn');

        const closeModal = () => {
            modal.style.display = 'none';
            currentUserId = null;
        };

        if (closeBtn) closeBtn.onclick = closeModal;
        if (cancelBtn) cancelBtn.onclick = closeModal;
        modal.onclick = (e) => {
            if (e.target === modal) closeModal();
        };

        if (saveBtn) {
            saveBtn.onclick = async () => {
                await updateUser();
            };
        }
    }

    /**
     * Show create user modal
     */
    window.showCreateUserModal = function() {
        const modal = document.getElementById('create-user-modal');
        if (modal) {
            modal.style.display = 'flex';
        }
    };

    /**
     * Open edit user modal
     */
    async function openEditUserModal(userId) {
        try {
            const response = await fetch(`/api/dashboard/users/${userId}`);
            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Failed to load user');
            }

            const user = data.data;
            currentUserId = userId;

            document.getElementById('edit-user-title').textContent = `Edit User: ${user.full_name}`;
            document.getElementById('edit-user-name').value = user.full_name;
            document.getElementById('edit-user-email').value = user.email;
            document.getElementById('edit-user-password').value = '';
            document.getElementById('edit-user-role').value = user.role_id;
            document.getElementById('edit-user-active').checked = user.is_active;

            document.getElementById('edit-user-modal').style.display = 'flex';

        } catch (error) {
            console.error('Error opening edit modal:', error);
            showNotification('Failed to load user details', 'error');
        }
    }

    /**
     * Create new user
     */
    async function createUser() {
        const fullName = document.getElementById('create-user-name').value.trim();
        const email = document.getElementById('create-user-email').value.trim();
        const password = document.getElementById('create-user-password').value;
        const roleId = document.getElementById('create-user-role').value;
        const isActive = document.getElementById('create-user-active').checked;

        if (!fullName || !email || !password) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }

        if (password.length < 8) {
            showNotification('Password must be at least 8 characters', 'error');
            return;
        }

        const saveBtn = document.getElementById('create-user-save-btn');
        saveBtn.textContent = 'Creating...';
        saveBtn.disabled = true;

        try {
            const response = await fetch('/api/dashboard/users/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    full_name: fullName,
                    email: email,
                    password: password,
                    role_id: parseInt(roleId),
                    is_active: isActive
                })
            });

            const data = await response.json();

            if (data.success) {
                showNotification('User created successfully!', 'success');
                document.getElementById('create-user-modal').style.display = 'none';
                await loadUsers();
            } else {
                throw new Error(data.error || 'Failed to create user');
            }

        } catch (error) {
            console.error('Error creating user:', error);
            showNotification(error.message || 'Failed to create user', 'error');
        } finally {
            saveBtn.textContent = 'Create User';
            saveBtn.disabled = false;
        }
    }

    /**
     * Update user
     */
    async function updateUser() {
        if (!currentUserId) return;

        const fullName = document.getElementById('edit-user-name').value.trim();
        const email = document.getElementById('edit-user-email').value.trim();
        const password = document.getElementById('edit-user-password').value;
        const roleId = document.getElementById('edit-user-role').value;
        const isActive = document.getElementById('edit-user-active').checked;

        if (!fullName || !email) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }

        if (password && password.length < 8) {
            showNotification('Password must be at least 8 characters', 'error');
            return;
        }

        const saveBtn = document.getElementById('edit-user-save-btn');
        saveBtn.textContent = 'Saving...';
        saveBtn.disabled = true;

        try {
            const payload = {
                full_name: fullName,
                email: email,
                role_id: parseInt(roleId),
                is_active: isActive
            };

            if (password) {
                payload.password = password;
            }

            const response = await fetch(`/api/dashboard/users/${currentUserId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (data.success) {
                showNotification('User updated successfully!', 'success');
                document.getElementById('edit-user-modal').style.display = 'none';
                await loadUsers();
            } else {
                throw new Error(data.error || 'Failed to update user');
            }

        } catch (error) {
            console.error('Error updating user:', error);
            showNotification(error.message || 'Failed to update user', 'error');
        } finally {
            saveBtn.textContent = 'Save Changes';
            saveBtn.disabled = false;
        }
    }

    /**
     * Toggle user active status
     */
    async function toggleUserActive(userId) {
        try {
            const response = await fetch(`/api/dashboard/users/${userId}/toggle-active`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message, 'success');
                await loadUsers();
            } else {
                throw new Error(data.error || 'Failed to toggle user status');
            }

        } catch (error) {
            console.error('Error toggling user:', error);
            showNotification(error.message || 'Failed to toggle user status', 'error');
        }
    }

    /**
     * Unlock user account
     */
    async function unlockUser(userId) {
        try {
            const response = await fetch(`/api/dashboard/users/${userId}/unlock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                showNotification('User account unlocked', 'success');
                await loadUsers();
            } else {
                throw new Error(data.error || 'Failed to unlock user');
            }

        } catch (error) {
            console.error('Error unlocking user:', error);
            showNotification(error.message || 'Failed to unlock user', 'error');
        }
    }

    /**
     * Delete user
     */
    async function deleteUser(userId) {
        try {
            const response = await fetch(`/api/dashboard/users/${userId}`, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                showNotification('User deleted successfully', 'success');
                await loadUsers();
            } else {
                throw new Error(data.error || 'Failed to delete user');
            }

        } catch (error) {
            console.error('Error deleting user:', error);
            showNotification(error.message || 'Failed to delete user', 'error');
        }
    }

    /**
     * Setup event listeners
     */
    function setupUsersEventListeners() {
        // Create button
        const createBtn = document.getElementById('users-create-btn');
        if (createBtn) {
            createBtn.addEventListener('click', () => {
                showCreateUserModal();
            });
        }

        // Refresh button
        const refreshBtn = document.getElementById('users-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                loadUsers();
                showNotification('Users list refreshed', 'success');
            });
        }
    }

})();
