const API_BASE = window.location.origin;

let token = localStorage.getItem('token');
let username = localStorage.getItem('username');
let role = localStorage.getItem('role');

const authSection       = document.getElementById('authSection');
const dashboardSection  = document.getElementById('dashboardSection');
const usernameDisplay   = document.getElementById('usernameDisplay');
const dropZone          = document.getElementById('dropZone');
const fileInput         = document.getElementById('fileInput');
const progressBar       = document.getElementById('progressBar');
const uploadProgress    = document.getElementById('uploadProgress');
const uploadStatus      = document.getElementById('uploadStatus');
const storageProgress   = document.getElementById('storageProgress');
const activityList      = document.getElementById('activityList');
const fileSections      = document.getElementById('fileSections');
const sharedWithMe      = document.getElementById('sharedWithMe');
const folderSelect      = document.getElementById('folderSelect');
const createFolderBtn   = document.getElementById('createFolderBtn');
const folderCreateForm  = document.getElementById('folderCreateForm');
const newFolderName     = document.getElementById('newFolderName');
const saveFolderBtn     = document.getElementById('saveFolderBtn');
const profileImage      = document.getElementById('profileImage');
const profileUsedMB     = document.getElementById('profileUsedMB');
const loginHistoryList  = document.getElementById('loginHistoryList');
const adminTab          = document.getElementById('adminTab');

// Auto-login
if (token && username) {
  showDashboard();
}

// Login
document.getElementById('loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const loginUsername = document.getElementById('loginUsername').value.trim();
  const loginPassword = document.getElementById('loginPassword').value;

  try {
    const res = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: loginUsername, password: loginPassword })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');

    localStorage.setItem('token', data.token);
    localStorage.setItem('username', data.username);
    localStorage.setItem('role', data.role);
    token = data.token;
    username = data.username;
    role = data.role;
    showDashboard();
  } catch (err) {
    document.getElementById('authMessage').textContent = err.message;
  }
});

// Register
document.getElementById('registerForm').addEventListener('submit', async e => {
  e.preventDefault();
  const regUsername = document.getElementById('regUsername').value.trim();
  const regPassword = document.getElementById('regPassword').value;

  try {
    const res = await fetch(`${API_BASE}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: regUsername, password: regPassword })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Registration failed');

    document.getElementById('authMessage').textContent = 'Account created — please sign in now.';
  } catch (err) {
    document.getElementById('authMessage').textContent = err.message;
  }
});

// Logout
document.getElementById('logoutBtn').addEventListener('click', () => {
  localStorage.clear();
  token = username = role = null;
  authSection.classList.remove('d-none');
  dashboardSection.classList.add('d-none');
});

// Tab switching
document.getElementById('dashboardTab').addEventListener('click', () => {
  document.getElementById('dashboardContent').style.display = 'block';
  document.getElementById('profileContent').style.display = 'none';
  document.getElementById('adminContent').style.display = 'none';
  document.getElementById('dashboardTab').classList.add('active');
  document.getElementById('profileTab').classList.remove('active');
  document.getElementById('adminTab').classList.remove('active');
  document.getElementById('pageTitle').textContent = `Welcome, ${username}`;
  loadFolders();
  loadFiles();
  loadSharedWithMe();
  loadStorageUsage();
  loadRecentActivity();
});

document.getElementById('profileTab').addEventListener('click', () => {
  document.getElementById('dashboardContent').style.display = 'none';
  document.getElementById('profileContent').style.display = 'block';
  document.getElementById('adminContent').style.display = 'none';
  document.getElementById('dashboardTab').classList.remove('active');
  document.getElementById('profileTab').classList.add('active');
  document.getElementById('adminTab').classList.remove('active');
  document.getElementById('pageTitle').textContent = 'Profile';
  loadProfile();
  loadLoginHistory();
});

adminTab.addEventListener('click', () => {
  if (role !== 'admin') {
    document.getElementById('dashboardTab').click();
    return;
  }

  document.getElementById('dashboardContent').style.display = 'none';
  document.getElementById('profileContent').style.display = 'none';
  document.getElementById('adminContent').style.display = 'block';
  document.getElementById('dashboardTab').classList.remove('active');
  document.getElementById('profileTab').classList.remove('active');
  adminTab.classList.add('active');
  document.getElementById('pageTitle').textContent = 'Admin Panel';
  loadUsers();
});

function showDashboard() {
  authSection.classList.add('d-none');
  dashboardSection.classList.remove('d-none');
  usernameDisplay.textContent = username;

  const adminTab = document.getElementById('adminTab');
  const adminContent = document.getElementById('adminContent');

  if (role === 'admin') {
    adminTab.style.display = 'inline-block';
  } else {
    adminTab.style.display = 'none';
    adminContent.style.display = 'none';
  }

  document.getElementById('dashboardContent').style.display = 'block';
  document.getElementById('profileContent').style.display = 'none';
  document.getElementById('adminContent').style.display = 'none';
  document.getElementById('dashboardTab').classList.add('active');
  document.getElementById('profileTab').classList.remove('active');
  document.getElementById('adminTab').classList.remove('active');

  loadFolders();
  loadFiles();
  loadSharedWithMe();
  loadStorageUsage();
  loadRecentActivity();
}

// Load folders
async function loadFolders() {
  try {
    const res = await fetch(`${API_BASE}/folders`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Failed to load folders');
    const folders = await res.json();

    folderSelect.innerHTML = '<option value="">Root (no folder)</option>';
    folders.forEach(folder => {
      const option = document.createElement('option');
      option.value = folder.id;
      option.textContent = folder.name;
      folderSelect.appendChild(option);
    });
  } catch (err) {
    console.error('Folders load error:', err);
  }
}

// Create folder
createFolderBtn.addEventListener('click', () => {
  folderCreateForm.style.display = 'flex';
  newFolderName.focus();
});

saveFolderBtn.addEventListener('click', async () => {
  const name = newFolderName.value.trim();
  if (!name) return alert('Enter a folder name');

  try {
    const res = await fetch(`${API_BASE}/folders`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ name })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to create folder');

    folderCreateForm.style.display = 'none';
    newFolderName.value = '';
    loadFolders();
    loadFiles();
    uploadStatus.textContent = `Folder "${name}" created`;
    uploadStatus.className = 'alert alert-success';
  } catch (err) {
    uploadStatus.textContent = 'Error: ' + err.message;
    uploadStatus.className = 'alert alert-danger';
  }
});

// Load storage usage (current user)
async function loadStorageUsage() {
  try {
    const res = await fetch(`${API_BASE}/storage`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error(await res.text());
    const { usedMB } = await res.json();

    const percent = Math.min((usedMB / 10000) * 100, 100);
    storageProgress.style.width = percent + '%';
    storageProgress.textContent = `${usedMB} MB used (${percent.toFixed(0)}%)`;
  } catch (err) {
    storageProgress.parentElement.innerHTML = '<div class="text-danger">Error loading storage</div>';
  }
}

// Load recent activity
async function loadRecentActivity() {
  try {
    const res = await fetch(`${API_BASE}/recent-activity`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error(await res.text());
    const activity = await res.json();

    activityList.innerHTML = '';
    activity.forEach(item => {
      const li = document.createElement('li');
      li.className = 'list-group-item';
      li.innerHTML = `
        <strong>${item.username}</strong> uploaded <strong>${item.filename}</strong><br>
        <small>${item.upload_time} • ${item.sizeMB} MB</small>
      `;
      activityList.appendChild(li);
    });
  } catch (err) {
    activityList.innerHTML = '<li class="list-group-item text-danger">Error loading recent activity</li>';
  }
}

// Load own files
async function loadFiles() {
  try {
    const res = await fetch(`${API_BASE}/files`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Failed to load files');
    const files = await res.json();

    fileSections.innerHTML = '';

    const grouped = {};
    files.forEach(file => {
      const key = file.folder_id || 'root';
      if (!grouped[key]) grouped[key] = { name: file.folder_name || 'Root Files', files: [] };
      grouped[key].files.push(file);
    });

    Object.keys(grouped).forEach(key => {
      const group = grouped[key];
      const accordionItem = document.createElement('div');
      accordionItem.className = 'accordion-item';
      accordionItem.innerHTML = `
        <h2 class="accordion-header">
          <button class="accordion-button ${key === 'root' ? '' : 'collapsed'}" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-${key}">
            ${group.name} (${group.files.length})
          </button>
        </h2>
        <div id="collapse-${key}" class="accordion-collapse collapse ${key === 'root' ? 'show' : ''}">
          <div class="accordion-body p-0">
            <ul class="list-group list-group-flush"></ul>
          </div>
        </div>
      `;
      const ul = accordionItem.querySelector('ul');

      group.files.forEach(file => {
        const li = document.createElement('li');
        li.className = 'list-group-item d-flex justify-content-between align-items-center py-3';
        li.innerHTML = `
          <div>
            <div class="fw-bold">${file.filename}</div>
            <small class="text-muted">
              ${file.upload_time} • ${(file.size / 1024 / 1024).toFixed(2)} MB
            </small>
          </div>
          <div>
            <a href="${API_BASE}${file.downloadUrl}" class="btn btn-sm btn-outline-primary me-2" download>Download</a>
            <button class="btn btn-sm btn-outline-info share-btn me-2" data-file-id="${file.id}">Share Link</button>
            <button class="btn btn-sm btn-outline-success share-user-btn me-2" data-file-id="${file.id}">Share with User</button>
            <button class="btn btn-sm btn-outline-secondary move-btn me-2" data-file-id="${file.id}">Move</button>
            <button class="btn btn-sm btn-outline-warning rename-btn me-2" data-file-id="${file.id}">Rename</button>
            <button class="btn btn-sm btn-outline-danger delete-btn" data-id="${file.id}">Delete</button>
          </div>
        `;
        ul.appendChild(li);
      });

      fileSections.appendChild(accordionItem);
    });

    // Attach handlers for own files
    document.querySelectorAll('.delete-btn').forEach(btn => {
      btn.onclick = async () => {
        if (!confirm('Delete this file?')) return;
        const id = btn.dataset.id;
        try {
          const res = await fetch(`${API_BASE}/files/${id}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${token}` }
          });
          if (res.ok) {
            uploadStatus.textContent = 'File deleted';
            uploadStatus.className = 'alert alert-success';
            loadFiles();
          } else {
            throw new Error('Delete failed');
          }
        } catch (err) {
          uploadStatus.textContent = err.message;
          uploadStatus.className = 'alert alert-danger';
        }
      };
    });

    document.querySelectorAll('.share-btn').forEach(btn => {
      btn.onclick = async () => {
        const fileId = btn.dataset.fileId;
        try {
          const res = await fetch(`${API_BASE}/files/${fileId}/share`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}` }
          });
          if (!res.ok) throw new Error(await res.text());
          const { shareLink } = await res.json();

          await navigator.clipboard.writeText(shareLink);
          uploadStatus.textContent = `Share link copied! ${shareLink}`;
          uploadStatus.className = 'alert alert-success';
        } catch (err) {
          uploadStatus.textContent = 'Failed to generate link: ' + err.message;
          uploadStatus.className = 'alert alert-danger';
        }
      };
    });

    document.querySelectorAll('.share-user-btn').forEach(btn => {
      btn.onclick = async () => {
        const fileId = btn.dataset.fileId;
        const targetUsername = prompt('Enter username to share this file with:');
        if (!targetUsername || !targetUsername.trim()) return;

        try {
          const res = await fetch(`${API_BASE}/files/${fileId}/share-with-user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ username: targetUsername.trim() })
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Share failed');

          alert(data.message);
        } catch (err) {
          alert('Error sharing file: ' + err.message);
        }
      };
    });

    document.querySelectorAll('.move-btn').forEach(btn => {
      btn.onclick = async () => {
        const fileId = btn.dataset.fileId;
        const foldersRes = await fetch(`${API_BASE}/folders`, { headers: { Authorization: `Bearer ${token}` } });
        const folders = await foldersRes.json();

        let options = '0 - Root\n';
        folders.forEach(f => options += `${f.id} - ${f.name}\n`);

        const choice = prompt(`Move file to folder:\n\n${options}\n\nEnter number (0 for root):`);
        if (choice === null) return;

        const targetFolderId = choice.trim() === '0' ? null : parseInt(choice);
        if (isNaN(targetFolderId) && targetFolderId !== null) {
          alert('Invalid choice');
          return;
        }

        try {
          const res = await fetch(`${API_BASE}/files/${fileId}/move`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ folderId: targetFolderId })
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Move failed');
          alert(data.message);
          loadFiles();
        } catch (err) {
          alert('Error moving file: ' + err.message);
        }
      };
    });

    document.querySelectorAll('.rename-btn').forEach(btn => {
      btn.onclick = async () => {
        const fileId = btn.dataset.fileId;
        const currentName = btn.closest('li').querySelector('.fw-bold').textContent.trim();
        const newName = prompt(`Rename file:\nCurrent: ${currentName}\nNew name:`, currentName);

        if (newName === null || !newName.trim()) return;

        try {
          const res = await fetch(`${API_BASE}/files/${fileId}/rename`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ newName: newName.trim() })
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Rename failed');
          alert(data.message);
          loadFiles();
        } catch (err) {
          alert('Error renaming file: ' + err.message);
        }
      };
    });
  } catch (err) {
    uploadStatus.textContent = err.message;
    uploadStatus.className = 'alert alert-danger';
  }
}

// Load files shared with me
async function loadSharedWithMe() {
  try {
    const res = await fetch(`${API_BASE}/files/shared-with-me`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Failed to load shared files');
    const sharedFiles = await res.json();

    sharedWithMe.innerHTML = '';

    if (sharedFiles.length === 0) {
      sharedWithMe.innerHTML = '<p class="text-muted">No files have been shared with you yet.</p>';
      return;
    }

    const accordionItem = document.createElement('div');
    accordionItem.className = 'accordion-item';
    accordionItem.innerHTML = `
      <h2 class="accordion-header">
        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#sharedCollapse">
          Shared with Me (${sharedFiles.length})
        </button>
      </h2>
      <div id="sharedCollapse" class="accordion-collapse collapse">
        <div class="accordion-body p-0">
          <ul class="list-group list-group-flush"></ul>
        </div>
      </div>
    `;
    const ul = accordionItem.querySelector('ul');

    sharedFiles.forEach(file => {
      const li = document.createElement('li');
      li.className = 'list-group-item d-flex justify-content-between align-items-center py-3';
      li.innerHTML = `
        <div>
          <div class="fw-bold">${file.filename}</div>
          <small class="text-muted">
            Shared by ${file.shared_by} • ${file.upload_time} • ${(file.size / 1024 / 1024).toFixed(2)} MB
          </small>
        </div>
        <a href="${API_BASE}${file.downloadUrl}" class="btn btn-sm btn-outline-primary" download>Download</a>
      `;
      ul.appendChild(li);
    });

    sharedWithMe.appendChild(accordionItem);
  } catch (err) {
    console.error('Error loading shared files:', err);
    sharedWithMe.innerHTML = '<p class="text-danger">Error loading shared files</p>';
  }
}

// Load profile
async function loadProfile() {
  try {
    const res = await fetch(`${API_BASE}/profile`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Failed to load profile');
    const data = await res.json();

    usernameDisplay.textContent = data.username;
    if (data.profileImage) {
      profileImage.src = data.profileImage + '?' + new Date().getTime();
    }
    profileUsedMB.textContent = data.usedMB + ' MB';
  } catch (err) {
    console.error('Profile load error:', err);
  }
}

// Profile image upload
document.getElementById('profileImageForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const fileInput = document.getElementById('profileImageInput');
  if (!fileInput.files.length) return alert('Select an image');

  const formData = new FormData();
  formData.append('image', fileInput.files[0]);

  try {
    const res = await fetch(`${API_BASE}/profile/image`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: formData
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Upload failed');

    alert(data.message);
    loadProfile();
  } catch (err) {
    alert('Error: ' + err.message);
  }
});

// Change password
document.getElementById('changePasswordForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const oldPassword = document.getElementById('oldPassword').value;
  const newPassword = document.getElementById('newPassword').value;

  try {
    const res = await fetch(`${API_BASE}/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ oldPassword, newPassword })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Change failed');

    alert(data.message);
  } catch (err) {
    alert('Error: ' + err.message);
  }
});

// Load login history
async function loadLoginHistory() {
  try {
    const res = await fetch(`${API_BASE}/login-history`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) throw new Error('Failed to load history');
    const history = await res.json();

    loginHistoryList.innerHTML = '';
    history.forEach(item => {
      const li = document.createElement('li');
      li.className = 'list-group-item';
      li.innerHTML = `
        Login from IP: ${item.ip}<br>
        <small>${item.login_time}</small>
      `;
      loginHistoryList.appendChild(li);
    });
  } catch (err) {
    loginHistoryList.innerHTML = '<li class="list-group-item text-danger">Error loading login history</li>';
  }
}

// Load users + global stats (admin only)
async function loadUsers() {
  try {
    // Global stats
    const globalRes = await fetch(`${API_BASE}/admin/storage/global`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!globalRes.ok) throw new Error('Failed to load global stats');
    const globalStats = await globalRes.json();

    document.getElementById('totalUsers').textContent = globalStats.totalUsers;
    document.getElementById('totalAdmins').textContent = globalStats.totalAdmins;
    document.getElementById('totalFiles').textContent = globalStats.totalFiles.toLocaleString();
    document.getElementById('totalUsedSpace').innerHTML = 
      `${globalStats.totalUsedMB} MB <small>(${globalStats.totalUsedGB} GB)</small>`;

    // User list
    const usersRes = await fetch(`${API_BASE}/admin/users`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!usersRes.ok) throw new Error('Failed to load users');
    const users = await usersRes.json();

    // Per-user storage
    const statsRes = await fetch(`${API_BASE}/admin/users/storage`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!statsRes.ok) throw new Error('Failed to load storage stats');
    const storageStats = await statsRes.json();

    const statsMap = {};
    storageStats.forEach(stat => {
      statsMap[stat.id] = stat.usedMB;
    });

    const userList = document.getElementById('userList');
    userList.innerHTML = '';

    users.forEach(user => {
      const usedMB = statsMap[user.id] || '0.00';

      const li = document.createElement('li');
      li.className = 'list-group-item d-flex justify-content-between align-items-center';
      li.innerHTML = `
        <div>
          <strong>${user.username}</strong> (${user.role})<br>
          <small>Created: ${new Date(user.created_at).toLocaleString()}</small><br>
          <small class="text-muted">Used: ${usedMB} MB</small>
        </div>
        <div>
          <button class="btn btn-sm btn-outline-danger reset-password-btn me-2" data-user-id="${user.id}">
            Reset Password
          </button>
          <button class="btn btn-sm btn-danger delete-user-btn" data-user-id="${user.id}" data-username="${user.username}">
            Delete User
          </button>
        </div>
      `;
      userList.appendChild(li);
    });

    // Reset password
    document.querySelectorAll('.reset-password-btn').forEach(btn => {
      btn.onclick = async () => {
        const userId = btn.dataset.userId;
        const newPassword = prompt('New password:');
        if (!newPassword) return;

        try {
          const res = await fetch(`${API_BASE}/admin/users/${userId}/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify({ newPassword })
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Reset failed');
          alert(data.message);
        } catch (err) {
          alert('Error: ' + err.message);
        }
      };
    });

    // Delete user
    document.querySelectorAll('.delete-user-btn').forEach(btn => {
      btn.onclick = async () => {
        const userId = btn.dataset.userId;
        const username = btn.dataset.username;

        if (!confirm(`PERMANENTLY delete user "${username}" and ALL their data?`)) return;

        try {
          const res = await fetch(`${API_BASE}/admin/users/${userId}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${token}` }
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || 'Delete failed');
          alert(data.message);
          loadUsers();
        } catch (err) {
          alert('Error: ' + err.message);
        }
      };
    });
  } catch (err) {
    alert('Error loading admin panel: ' + err.message);
  }
}

// Create user
document.getElementById('createUserForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  const username = document.getElementById('newUserUsername').value.trim();
  const password = document.getElementById('newUserPassword').value;
  const role = document.getElementById('newUserRole').value;

  try {
    const res = await fetch(`${API_BASE}/admin/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ username, password, role })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Create failed');

    alert(data.message);
    loadUsers();
    document.getElementById('newUserUsername').value = '';
    document.getElementById('newUserPassword').value = '';
  } catch (err) {
    alert('Error: ' + err.message);
  }
});

// Upload handling
dropZone.onclick = () => fileInput.click();

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragenter', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  if (e.dataTransfer.files.length) uploadFiles(e.dataTransfer.files);
});

fileInput.onchange = e => {
  if (e.target.files.length) uploadFiles(e.target.files);
};

async function uploadFiles(files) {
  uploadStatus.className = 'd-none';
  uploadProgress.classList.remove('d-none');
  progressBar.style.width = '0%';

  const folderId = folderSelect.value || null;

  for (const file of files) {
    const formData = new FormData();
    formData.append('file', file);
    if (folderId) formData.append('folderId', folderId);

    try {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${API_BASE}/upload`, true);
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);

      xhr.upload.onprogress = e => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          progressBar.style.width = pct + '%';
          progressBar.textContent = pct + '%';
        }
      };

      xhr.onload = () => {
        if (xhr.status === 200) {
          const response = JSON.parse(xhr.responseText);
          uploadStatus.innerHTML = `Uploaded: ${file.name}<br>Share link: <strong>${response.shareLink}</strong> (copied)`;
          uploadStatus.className = 'alert alert-success';
          navigator.clipboard.writeText(response.shareLink).catch(() => {});
          loadFiles();
          loadStorageUsage();
          loadRecentActivity();
        } else {
          uploadStatus.textContent = 'Upload failed: ' + xhr.statusText;
          uploadStatus.className = 'alert alert-danger';
        }
        uploadProgress.classList.add('d-none');
      };

      xhr.onerror = () => {
        uploadStatus.textContent = 'Network error during upload';
        uploadStatus.className = 'alert alert-danger';
        uploadProgress.classList.add('d-none');
      };

      xhr.send(formData);
    } catch (err) {
      uploadStatus.textContent = 'Upload error: ' + err.message;
      uploadStatus.className = 'alert alert-danger';
      uploadProgress.classList.add('d-none');
      console.error('Upload exception:', err);
    }
  }
}

// Dark mode toggle
const toggleBtn = document.getElementById('darkModeToggle');
const body = document.body;

if (localStorage.getItem('darkMode') === 'enabled') {
  body.classList.add('dark-mode');
  if (toggleBtn) toggleBtn.innerHTML = '<i class="bi bi-sun-fill"></i>';
}

if (toggleBtn) {
  toggleBtn.addEventListener('click', () => {
    body.classList.toggle('dark-mode');
    if (body.classList.contains('dark-mode')) {
      localStorage.setItem('darkMode', 'enabled');
      toggleBtn.innerHTML = '<i class="bi bi-sun-fill"></i>';
    } else {
      localStorage.setItem('darkMode', 'disabled');
      toggleBtn.innerHTML = '<i class="bi bi-moon-stars-fill"></i>';
    }
  });
}