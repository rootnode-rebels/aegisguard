/**
 * CMS Dashboard Controller
 * Handles logic for the Content Management System and Admin operations.
 */

// Initialize CMS on load or tab switch
document.addEventListener('DOMContentLoaded', () => {
  // Hook into the tab switching mechanism if it exists in app.js
  const cmsTabBtn = document.getElementById('nav-cms-dashboard');
  if (cmsTabBtn) {
    cmsTabBtn.addEventListener('click', () => {
      cmsLoadData();
    });
  }
});

/**
 * Main loader for CMS data
 */
async function cmsLoadData() {
  await cmsFetchStats();
  await cmsFetchUsers();
}

/**
 * Fetch and populate top-level stats
 */
async function cmsFetchStats() {
  try {
    const response = await fetch('/api/cms/stats');
    if (!response.ok) throw new Error('Failed to fetch stats');
    
    const data = await response.json();
    
    document.getElementById('cms-metric-users').innerText = data.total_users || 0;
    document.getElementById('cms-metric-sessions').innerText = data.active_sessions || 0;
    document.getElementById('cms-metric-blocked').innerText = data.blocked_hijacks || 0;
    
    const maintBtn = document.getElementById('cms-btn-maintenance');
    if (data.maintenance_mode) {
      maintBtn.innerText = 'Disable';
      maintBtn.classList.replace('btn-secondary', 'btn-danger');
    } else {
      maintBtn.innerText = 'Enable';
      maintBtn.classList.replace('btn-danger', 'btn-secondary');
    }
  } catch (err) {
    console.error('[CMS] Error fetching stats:', err);
  }
}

/**
 * Fetch and populate the users table
 */
async function cmsFetchUsers() {
  const tbody = document.getElementById('cms-users-tbody');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">Loading users...</td></tr>';
  
  try {
    const response = await fetch('/api/cms/users');
    if (!response.ok) throw new Error('Failed to fetch users');
    
    const users = await response.json();
    
    if (users.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No users found.</td></tr>';
      return;
    }
    
    tbody.innerHTML = ''; // Clear loading
    
    users.forEach(user => {
      const tr = document.createElement('tr');
      
      const mfaEnabled = user.mfa_enabled ? 
        '<span style="color: var(--accent-emerald);">Yes</span>' : 
        '<span style="color: var(--text-muted);">No</span>';
        
      const lastLogin = user.last_login ? new Date(user.last_login).toLocaleString() : 'Never';
      
      tr.innerHTML = `
        <td>${user.name || 'Unknown'}</td>
        <td>${user.email}</td>
        <td>${mfaEnabled}</td>
        <td>${lastLogin}</td>
        <td>
          <button class="btn btn-danger btn-sm" onclick="cmsDeleteUser('${user.email}')">Delete</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('[CMS] Error fetching users:', err);
    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--accent-pink);">Error loading users: ${err.message}</td></tr>`;
  }
}

/**
 * Delete a user by email
 */
async function cmsDeleteUser(email) {
  if (!confirm(`Are you sure you want to delete user ${email}? This action cannot be undone.`)) {
    return;
  }
  
  try {
    const response = await fetch(`/api/cms/users/${encodeURIComponent(email)}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to delete user');
    }
    
    // Refresh the table and stats
    await cmsLoadData();
  } catch (err) {
    alert(`Error deleting user: ${err.message}`);
    console.error('[CMS] Error deleting user:', err);
  }
}

/**
 * Toggle maintenance mode
 */
async function cmsToggleMaintenance() {
  const maintBtn = document.getElementById('cms-btn-maintenance');
  const isEnabling = maintBtn.innerText === 'Enable';
  
  try {
    const response = await fetch(`/api/system/maintenance?enable=${isEnabling}`, {
      method: 'POST'
    });
    
    if (!response.ok) throw new Error('Failed to toggle maintenance mode');
    
    // Update button visually
    if (isEnabling) {
      maintBtn.innerText = 'Disable';
      maintBtn.classList.replace('btn-secondary', 'btn-danger');
      alert("Maintenance Mode is now ENABLED. Non-admin users will be blocked.");
    } else {
      maintBtn.innerText = 'Enable';
      maintBtn.classList.replace('btn-danger', 'btn-secondary');
      alert("Maintenance Mode is now DISABLED. System is back to normal.");
    }
  } catch (err) {
    alert(`Error toggling maintenance mode: ${err.message}`);
    console.error('[CMS] Maintenance mode toggle failed:', err);
  }
}
