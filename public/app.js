// Helper to retrieve cookie value by name
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

// Global Toast System
function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  const icon = document.createElement('span');
  icon.className = 'shrink-0';
  icon.innerHTML = type === 'success' 
    ? `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
         <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
       </svg>`
    : `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
         <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
       </svg>`;
  
  const text = document.createElement('span');
  text.className = 'font-medium text-sm';
  text.textContent = message;

  toast.appendChild(icon);
  toast.appendChild(text);
  container.appendChild(toast);

  // Anim in
  setTimeout(() => toast.classList.add('show'), 20);

  // Remove toast
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 400);
  }, 4000);
}

// API client utility with CSRF injection
async function api(path, options = {}) {
  const csrfToken = getCookie('csrf-token');
  const headers = {
    'Content-Type': 'application/json',
    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
    ...(options.headers || {})
  };

  const response = await fetch(path, {
    credentials: 'include',
    headers,
    ...options,
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || 'Server request failed.');
  }

  return data;
}

// Debounce helper
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Date formatter
function formatDate(value) {
  if (!value) return 'Never';
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value));
}

// Bind Multi-Step Authentication Flow Handlers
function bindAllAuthFlows() {
  let tempEmail = '';
  let tempPassword = '';

  function setLoading(btn, isLoading) {
    if (isLoading) {
      btn.dataset.originalHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = `<div class="spinner border-2 border-t-white"></div><span>Processing...</span>`;
    } else {
      btn.disabled = false;
      btn.innerHTML = btn.dataset.originalHtml || btn.innerHTML;
    }
  }

  // 1. SIGNUP STEP 1: Details Submission
  const signupForm = document.getElementById('signup-form');
  if (signupForm) {
    signupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = signupForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(signupForm).entries());
      try {
        const data = await api('/api/auth/signup', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        showToast(data.message || 'OTP generated.', 'success');
        
        if (data.devOtp) {
          const banner = document.getElementById('dev-otp-banner');
          const codeSpan = document.getElementById('dev-otp-code');
          if (banner && codeSpan) {
            codeSpan.textContent = data.devOtp;
            banner.classList.remove('hidden');
          }
        }
        
        document.getElementById('signup-step').classList.add('hidden');
        document.getElementById('otp-step').classList.remove('hidden');
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // 2. SIGNUP STEP 2: OTP Verification
  const otpForm = document.getElementById('otp-form');
  if (otpForm) {
    otpForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = otpForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(otpForm).entries());
      try {
        const data = await api('/api/auth/verify-otp', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        showToast(data.message || 'OTP verified.', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/mfa-setup';
        }, 1000);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // 3. SIGNUP STEP 3: MFA Setup Verification
  const mfaForm = document.getElementById('mfa-form');
  if (mfaForm) {
    mfaForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = mfaForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(mfaForm).entries());
      try {
        const data = await api('/api/auth/verify-mfa-setup', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        showToast(data.message || 'Account activated.', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/dashboard';
        }, 1000);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // 4. USER LOGIN: Step 1 (Credentials)
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = loginForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(loginForm).entries());
      try {
        const data = await api('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify(payload),
        });

        tempEmail = payload.email;
        tempPassword = payload.password;

        if (data.requiresMfaSetup) {
          showToast(data.message, 'success');
          setTimeout(() => {
            window.location.href = data.redirect || '/mfa-setup';
          }, 1000);
        } else if (data.requiresMfa) {
          document.getElementById('login-credentials-step').classList.add('hidden');
          document.getElementById('login-mfa-step').classList.remove('hidden');
          showToast(data.message, 'success');
        } else {
          showToast('Login successful.', 'success');
          setTimeout(() => {
            window.location.href = data.redirect || '/dashboard';
          }, 1000);
        }
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // 5. USER LOGIN: Step 2 Setup Verification (First login)
  const loginMfaSetupForm = document.getElementById('login-mfa-setup-form');
  if (loginMfaSetupForm) {
    loginMfaSetupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = loginMfaSetupForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(loginMfaSetupForm).entries());
      payload.email = tempEmail;
      payload.password = tempPassword;
      try {
        const data = await api('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        showToast('Login successful (MFA configured).', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/dashboard';
        }, 1000);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // 6. USER LOGIN: Step 3 Challenge Verification (Subsequent logins)
  const loginMfaForm = document.getElementById('login-mfa-form');
  if (loginMfaForm) {
    loginMfaForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = loginMfaForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(loginMfaForm).entries());
      payload.email = tempEmail;
      payload.password = tempPassword;
      try {
        const data = await api('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        showToast('Login successful.', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/dashboard';
        }, 1000);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // 7. ADMIN LOGIN: Step 1 (Credentials)
  const adminLoginForm = document.getElementById('admin-login-form');
  if (adminLoginForm) {
    adminLoginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = adminLoginForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(adminLoginForm).entries());
      try {
        const data = await api('/api/auth/admin-login', {
          method: 'POST',
          body: JSON.stringify(payload),
        });

        tempEmail = payload.email;
        tempPassword = payload.password;

        if (data.requiresMfaSetup) {
          showToast(data.message, 'success');
          setTimeout(() => {
            window.location.href = data.redirect || '/admin-mfa-setup';
          }, 1000);
        } else if (data.requiresMfa) {
          document.getElementById('admin-credentials-step').classList.add('hidden');
          document.getElementById('admin-mfa-challenge-step').classList.remove('hidden');
          showToast(data.message, 'success');
        } else {
          showToast('Login successful.', 'success');
          setTimeout(() => {
            window.location.href = data.redirect || '/admin';
          }, 1000);
        }
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // 8. ADMIN LOGIN: Step 2 Setup Verification (First login)
  const adminMfaSetupForm = document.getElementById('admin-mfa-setup-form');
  if (adminMfaSetupForm) {
    adminMfaSetupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = adminMfaSetupForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(adminMfaSetupForm).entries());
      payload.email = tempEmail;
      payload.password = tempPassword;
      try {
        const data = await api('/api/auth/admin-login', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        showToast('Login successful (Admin MFA configured).', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/admin';
        }, 1000);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }

  // 9. ADMIN LOGIN: Step 3 Challenge Verification (Subsequent logins)
  const adminMfaChallengeForm = document.getElementById('admin-mfa-challenge-form');
  if (adminMfaChallengeForm) {
    adminMfaChallengeForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = adminMfaChallengeForm.querySelector('[type="submit"]');
      setLoading(btn, true);
      const payload = Object.fromEntries(new FormData(adminMfaChallengeForm).entries());
      payload.email = tempEmail;
      payload.password = tempPassword;
      try {
        const data = await api('/api/auth/admin-login', {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        showToast('Login successful.', 'success');
        setTimeout(() => {
          window.location.href = data.redirect || '/admin';
        }, 1000);
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        setLoading(btn, false);
      }
    });
  }
}

// Logout Utility
async function logout() {
  try {
    await api('/api/auth/logout', { method: 'POST' });
    showToast('Logged out successfully.', 'success');
    setTimeout(() => {
      window.location.href = '/login';
    }, 800);
  } catch {
    window.location.href = '/login';
  }
}

// ---- User Dashboard Logic ----
async function loadDashboard() {
  const profileEl = document.querySelector('[data-profile-name]');
  const listEl = document.querySelector('[data-user-list]');
  if (!profileEl || !listEl) return;

  try {
    const [profile, users] = await Promise.all([
      api('/api/users/profile'),
      api('/api/users/list'),
    ]);

    profileEl.textContent = profile.user.fullName;
    
    // Set first letter of full name as avatar initials
    const avatarEl = document.getElementById('profile-avatar');
    if (avatarEl && profile.user.fullName) {
      avatarEl.textContent = profile.user.fullName.trim().charAt(0).toUpperCase();
    }

    listEl.innerHTML = '';
    if (users.users.length === 0) {
      listEl.innerHTML = `<li class="col-span-full py-4 text-center text-slate-500 text-sm">No other registered users.</li>`;
    } else {
      for (const user of users.users) {
        const li = document.createElement('li');
        li.className = 'glass-card rounded-xl p-4 flex items-center gap-3 border border-slate-800/40';
        li.innerHTML = `
          <div class="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center text-indigo-400 font-semibold text-xs border border-indigo-500/10">
            ${user.fullName.trim().charAt(0).toUpperCase()}
          </div>
          <span class="text-sm font-semibold text-slate-200 truncate">${user.fullName}</span>
        `;
        listEl.appendChild(li);
      }
    }
  } catch (error) {
    showToast(error.message, 'error');
    if (error.message.includes('Authentication') || error.message.includes('session')) {
      setTimeout(() => {
        window.location.href = '/login';
      }, 1500);
    }
  }
}

// ---- Admin Panel Logic ----
let adminState = {
  search: '',
  role: 'all',
  status: 'all',
  page: 1,
  limit: 10,
};

async function loadAdmin() {
  const tbody = document.querySelector('[data-admin-users]');
  if (!tbody) return;

  try {
    // Build query params
    const query = new URLSearchParams({
      search: adminState.search,
      role: adminState.role,
      status: adminState.status,
      page: adminState.page,
      limit: adminState.limit,
    });

    const data = await api(`/api/admin/users?${query}`);

    // Update table body
    tbody.innerHTML = '';
    if (data.users.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="py-10 text-center text-slate-500 font-medium">
            No matching accounts found.
          </td>
        </tr>`;
    } else {
      for (const user of data.users) {
        tbody.appendChild(buildAdminRow(user));
      }
    }

    // Update statistics cards
    document.querySelector('[data-stat-total-users]').textContent = data.stats.totalUsers;
    document.querySelector('[data-stat-total-admins]').textContent = data.stats.totalAdmins;
    document.querySelector('[data-stat-active-users]').textContent = data.stats.activeUsers;
    document.querySelector('[data-stat-disabled-users]').textContent = data.stats.disabledUsers;

    // Update pagination controls
    const totalCount = data.pagination.total;
    const startRecord = totalCount === 0 ? 0 : (adminState.page - 1) * adminState.limit + 1;
    const endRecord = Math.min(adminState.page * adminState.limit, totalCount);
    
    document.getElementById('pagination-info').innerHTML = `
      Showing <span class="font-semibold text-white">${startRecord}</span> to <span class="font-semibold text-white">${endRecord}</span> of <span class="font-semibold text-white">${totalCount}</span> records
    `;

    document.getElementById('prev-page-btn').disabled = adminState.page <= 1;
    document.getElementById('next-page-btn').disabled = adminState.page >= data.pagination.pages;

  } catch (error) {
    showToast(error.message, 'error');
    if (error.message.includes('Authentication') || error.message.includes('session')) {
      setTimeout(() => {
        window.location.href = '/admin-login';
      }, 1500);
    }
  }
}

// Build table row for Admin users list
function buildAdminRow(user) {
  const tr = document.createElement('tr');
  tr.className = 'hover:bg-slate-900/25 transition-colors border-b border-slate-800/40';

  function createCell(content, customClass = '') {
    const td = document.createElement('td');
    td.className = `py-3.5 px-6 font-medium text-slate-300 ${customClass}`;
    if (typeof content === 'string') {
      td.textContent = content;
    } else {
      td.appendChild(content);
    }
    return td;
  }

  // Name with initials avatar
  const nameWrapper = document.createElement('div');
  nameWrapper.className = 'flex items-center gap-3';
  nameWrapper.innerHTML = `
    <div class="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center font-bold text-xs border border-indigo-500/10 ${user.role === 'admin' ? 'text-rose-400' : 'text-indigo-400'}">
      ${user.fullName.trim().charAt(0).toUpperCase()}
    </div>
    <span class="font-semibold text-white">${user.fullName}</span>
  `;
  tr.appendChild(createCell(nameWrapper));
  
  // Email
  tr.appendChild(createCell(user.email));

  // Role Badge
  const roleSpan = document.createElement('span');
  roleSpan.className = `inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold ${
    user.role === 'admin' 
      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' 
      : 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'
  }`;
  roleSpan.textContent = user.role.toUpperCase();
  tr.appendChild(createCell(roleSpan));

  // Dates
  tr.appendChild(createCell(formatDate(user.createdAt)));
  tr.appendChild(createCell(formatDate(user.lastLogin)));

  // Status Badge
  const statusSpan = document.createElement('span');
  statusSpan.className = `inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${
    user.isDisabled 
      ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20' 
      : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
  }`;
  statusSpan.innerHTML = user.isDisabled
    ? `<span class="w-1.5 h-1.5 rounded-full bg-rose-400"></span>Disabled`
    : `<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>Active`;
  tr.appendChild(createCell(statusSpan));

  // Actions cell
  const actionsDiv = document.createElement('div');
  actionsDiv.className = 'flex justify-end gap-1.5';

  const statusAction = user.isDisabled ? 'enable' : 'disable';
  const statusBtn = document.createElement('button');
  statusBtn.className = `px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all border ${
    user.isDisabled
      ? 'bg-emerald-500/10 hover:bg-emerald-500/25 border-emerald-500/20 text-emerald-400'
      : 'bg-amber-500/10 hover:bg-amber-500/25 border-amber-500/20 text-amber-400'
  }`;
  statusBtn.dataset.action = statusAction;
  statusBtn.dataset.id = user.id;
  statusBtn.textContent = user.isDisabled ? 'Enable' : 'Disable';
  actionsDiv.appendChild(statusBtn);

  const roleAction = user.role === 'admin' ? 'demote' : 'promote';
  const roleBtn = document.createElement('button');
  roleBtn.className = `px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all border ${
    user.role === 'admin'
      ? 'bg-violet-500/10 hover:bg-violet-500/25 border-violet-500/20 text-violet-400'
      : 'bg-indigo-500/10 hover:bg-indigo-500/25 border-indigo-500/20 text-indigo-400'
  }`;
  roleBtn.dataset.action = roleAction;
  roleBtn.dataset.id = user.id;
  roleBtn.textContent = user.role === 'admin' ? 'Demote' : 'Promote';
  actionsDiv.appendChild(roleBtn);

  const deleteBtn = document.createElement('button');
  deleteBtn.className = 'px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all border bg-rose-500/10 hover:bg-rose-500/25 border-rose-500/20 text-rose-400';
  deleteBtn.dataset.action = 'delete';
  deleteBtn.dataset.id = user.id;
  deleteBtn.textContent = 'Delete';
  actionsDiv.appendChild(deleteBtn);

  tr.appendChild(createCell(actionsDiv, 'text-right'));

  return tr;
}

// Action executor helper
async function runAdminAction(id, action) {
  const method = action === 'delete' ? 'DELETE' : 'PATCH';
  const path = action === 'delete'
    ? `/api/admin/users/${id}`
    : `/api/admin/users/${id}/${action}`;

  await api(path, { method });
  showToast(`Action '${action}' executed successfully.`, 'success');
  await loadAdmin();
}

// Setup Admin Dashboard Listeners
function setupAdminListeners() {
  const tbody = document.querySelector('[data-admin-users]');
  if (!tbody) return;

  // Search input with debounce
  const searchInput = document.getElementById('search-input');
  if (searchInput) {
    searchInput.addEventListener('input', debounce((e) => {
      adminState.search = e.target.value;
      adminState.page = 1;
      loadAdmin();
    }, 350));
  }

  // Filters
  const roleFilter = document.getElementById('role-filter');
  if (roleFilter) {
    roleFilter.addEventListener('change', (e) => {
      adminState.role = e.target.value;
      adminState.page = 1;
      loadAdmin();
    });
  }

  const statusFilter = document.getElementById('status-filter');
  if (statusFilter) {
    statusFilter.addEventListener('change', (e) => {
      adminState.status = e.target.value;
      adminState.page = 1;
      loadAdmin();
    });
  }

  // Pagination buttons
  document.getElementById('prev-page-btn')?.addEventListener('click', () => {
    if (adminState.page > 1) {
      adminState.page--;
      loadAdmin();
    }
  });

  document.getElementById('next-page-btn')?.addEventListener('click', () => {
    adminState.page++;
    loadAdmin();
  });

  // Table action clicks
  tbody.addEventListener('click', async (event) => {
    const button = event.target.closest('button[data-action]');
    if (!button) return;

    const action = button.dataset.action;
    const id = button.dataset.id;
    
    const confirmed = action !== 'delete' || window.confirm('Are you absolutely sure you want to permanently delete this account?');
    if (!confirmed) return;

    const btnOriginalText = button.textContent;
    button.disabled = true;
    button.textContent = '...';

    try {
      await runAdminAction(id, action);
    } catch (error) {
      showToast(error.message, 'error');
      button.disabled = false;
      button.textContent = btnOriginalText;
    }
  });

  // Modal setup helper function
  function setupModal(modalId, openBtnId, closeBtnId, cancelBtnId, formId, apiEndpoint) {
    const modal = document.getElementById(modalId);
    const openBtn = document.getElementById(openBtnId);
    const closeBtn = document.getElementById(closeBtnId);
    const cancelBtn = document.getElementById(cancelBtnId);
    const closeBg = document.getElementById(`close-${modalId.replace('-modal', '')}-modal-bg`);
    const form = document.getElementById(formId);

    if (!modal) return;

    function openModal() {
      modal.classList.remove('hidden');
    }

    function closeModal() {
      modal.classList.add('hidden');
      form?.reset();
    }

    openBtn?.addEventListener('click', openModal);
    closeBtn?.addEventListener('click', closeModal);
    cancelBtn?.addEventListener('click', closeModal);
    closeBg?.addEventListener('click', closeModal);

    form?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = form.querySelector('[type="submit"]');
      const originalText = submitBtn.innerHTML;
      submitBtn.disabled = true;
      submitBtn.innerHTML = 'Saving...';

      const payload = Object.fromEntries(new FormData(form).entries());
      try {
        const data = await api(apiEndpoint, {
          method: 'POST',
          body: JSON.stringify(payload),
        });
        showToast(data.message, 'success');
        closeModal();
        await loadAdmin();
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
      }
    });
  }

  // Bind modals
  setupModal(
    'create-user-modal',
    'open-create-user',
    'close-user-modal-btn',
    'cancel-user-modal',
    'create-user-form',
    '/api/admin/create-user'
  );

  setupModal(
    'create-admin-modal',
    'open-create-admin',
    'close-admin-modal-btn',
    'cancel-admin-modal',
    'create-admin-form',
    '/api/admin/create-admin'
  );
}

// Global initialization on DOM Load
document.addEventListener('DOMContentLoaded', () => {
  // Create toast container dynamically if not present
  if (!document.getElementById('toast-container')) {
    const container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  // Bind Auth Flows
  bindAllAuthFlows();

  // Bind logout events
  document.querySelectorAll('[data-logout]').forEach((button) => {
    button.addEventListener('click', logout);
  });

  // Init sections
  loadDashboard();
  if (document.querySelector('[data-admin-users]')) {
    setupAdminListeners();
    loadAdmin();
  }

  // Init dedicated MFA setups
  if (window.location.pathname === '/mfa-setup') {
    initMfaSetupPage(false);
  } else if (window.location.pathname === '/admin-mfa-setup') {
    initMfaSetupPage(true);
  }
});

// Init Dedicated MFA Setup page
async function initMfaSetupPage(isAdmin) {
  const formId = isAdmin ? 'admin-mfa-setup-form' : 'mfa-setup-form';
  const qrImgId = isAdmin ? 'admin-qr-img' : 'mfa-qr-img';
  const secretId = isAdmin ? 'admin-manual-secret' : 'mfa-manual-secret';
  const submitBtnId = isAdmin ? 'admin-mfa-setup-submit-btn' : 'mfa-setup-submit-btn';

  const form = document.getElementById(formId);
  const qrImg = document.getElementById(qrImgId);
  const secretEl = document.getElementById(secretId);
  const copyBtn = document.getElementById('copy-secret-btn');

  if (!form) return;

  // 1. Fetch details
  try {
    const data = await api('/api/auth/mfa-setup-details');
    if (qrImg) qrImg.src = data.qrCodeDataUrl;
    if (secretEl) secretEl.textContent = data.manualSecret;

    // Set copy listener
    if (copyBtn && data.manualSecret) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(data.manualSecret)
          .then(() => showToast('Secret key copied to clipboard!', 'success'))
          .catch(() => showToast('Failed to copy secret key.', 'error'));
      });
    }
  } catch (error) {
    showToast(error.message, 'error');
    // Redirect back to login if session is invalid
    setTimeout(() => {
      window.location.href = isAdmin ? '/admin-login' : '/login';
    }, 1500);
    return;
  }

  // 2. Form submission
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById(submitBtnId);
    if (!btn) return;

    // Set loading
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<div class="spinner border-2 border-t-white"></div><span>Verifying...</span>`;

    const payload = Object.fromEntries(new FormData(form).entries());
    try {
      const data = await api('/api/auth/verify-mfa-setup', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      showToast(data.message || 'MFA enabled successfully.', 'success');
      setTimeout(() => {
        window.location.href = data.redirect || (isAdmin ? '/admin' : '/dashboard');
      }, 1000);
    } catch (error) {
      showToast(error.message, 'error');
      btn.disabled = false;
      btn.innerHTML = originalHtml;
    }
  });
}
