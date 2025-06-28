const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');

const baseDir = 'custom specify your desired path on any drive C or D etc. where you want to create folders or upload files';
const uploadDir = path.join(baseDir, 'reqrFolder');
//const uploadDir = path.join(__dirname, 'reqFolder'); // Want to store in current directory where this files runs then comment or remove above two lines and uncomment this line
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

function safePath(subPath = '') {
  const normalizedSubPath = path.normalize(subPath).replace(/^(\.\.[\\/])+/, '');
  const resolvedPath = path.resolve(uploadDir, normalizedSubPath);
  if (!resolvedPath.startsWith(uploadDir + path.sep) && resolvedPath !== uploadDir) {
    throw new Error('Invalid path: Attempted directory traversal detected.');
  }
  return resolvedPath;
}

function getFolders(dir = '') {
  const dirPath = safePath(dir);
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  let folders = [];
  entries.forEach(entry => {
    if (entry.isDirectory()) {
      const sub = path.join(dir, entry.name);
      const nfolder = sub.replace(/\\/g, '/');
      folders.push(nfolder);
      folders.push(...getFolders(nfolder));
    }
  });
  return folders;
}

function parseMultipart(req, boundary, callback) {
  let data = Buffer.alloc(0); // Accumulate all incoming data chunks
  req.on('data', chunk => {
    data = Buffer.concat([data, chunk]);
  });
  req.on('end', () => {
    const boundaryString = '--' + boundary;
    const parts = data.toString('latin1').split(new RegExp(boundaryString + '(?:--)?\\r\\n', 'g'));
    let fileFound = false;
    for (const part of parts) {
      if (!part.trim()) continue;
        const headerEnd = part.indexOf('\r\n\r\n');
        if (headerEnd === -1) continue; 
        const header = part.substring(0, headerEnd);
        const content = part.substring(headerEnd + 4);
        const filenameMatch = header.match(/filename="([^"]+)"/);
        if (filenameMatch) {
          let filename = filenameMatch[1];
          filename = path.basename(filename);
          const fileBuffer = Buffer.from(content.replace(/\r\n$/, ''), 'latin1');
          callback(filename, fileBuffer);
          fileFound = true;
          break;
        }
      }
      if (!fileFound) {
        callback(null, null);
      }
  });
}

const mimeTypes = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.wav': 'audio/wav',
  '.mp4': 'video/mp4',
  '.woff': 'application/font-woff',
  '.ttf': 'application/font-ttf',
  '.eot': 'application/vnd.ms-fontobject',
  '.otf': 'application/font-otf',
  '.ico': 'image/x-icon'
};

// --- Configuration ---
const PASSWORD = 'hello'; // CHANGE THIS TO A STRONG PASSWORD
const SESSION_SECRET = crypto.randomBytes(32).toString('hex'); // Generate a random secret for session cookie
const SESSION_COOKIE_NAME = 'auth_token';
const SESSION_EXPIRY_MS = 3600 * 1000; // 1 hour

function parseCookies(request) {
  const list = {},
    rc = request.headers.cookie;
    rc && rc.split(';').forEach(function(cookie) {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  return list;
}

function generateSessionToken(passwordHash) {
  const timestamp = Date.now();
  const dataToHash = `${passwordHash}-${timestamp}`; // Data to be hashed includes the timestamp
  const hmac = crypto.createHmac('sha256', SESSION_SECRET);
  hmac.update(dataToHash);
  const hash = hmac.digest('hex');
  return `${hash}-${timestamp}`;
}

function verifySessionToken(token, passwordHash) {
  try {
    const parts = token.split('-');
    if (parts.length !== 2) return false; // Token should have two parts: hash and timestamp
    const receivedHash = parts[0];
    const timestamp = parseInt(parts[1], 10);
    
    if (isNaN(timestamp) || Date.now() - timestamp > SESSION_EXPIRY_MS) {
      return false; // Token expired or invalid timestamp
    }
    const dataToHash = `${passwordHash}-${timestamp}`;
    const hmac = crypto.createHmac('sha256', SESSION_SECRET);
    hmac.update(dataToHash);
    const expectedHash = hmac.digest('hex');
    return crypto.timingSafeEqual(Buffer.from(receivedHash), Buffer.from(expectedHash));
  } catch (e) {
    console.error("Session token verification error:", e);
    return false;
  }
}

const loginHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <title>Login</title>
    <style>
      body {
        font-family: sans-serif;
        background: #f4f4f4;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        margin: 0;
      }
      .login-container {
        background: #fff;
        padding: 30px;
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.12);
        text-align: center;
        width: 100%;
        max-width: 350px;
        box-sizing: border-box;
      }
      .login-container h2 {
        margin-bottom: 20px;
        color: #3a3a3a;
      }
      .login-container input[type="password"] {
        width: calc(100% - 20px);
        padding: 10px;
        margin-bottom: 20px;
        border: 1px solid #ddd;
        border-radius: 5px;
        font-size: 1em;
      }
      .login-container button {
        background: #1976d2;
        color: #fff;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        cursor: pointer;
        font-size: 1.1em;
        transition: background 0.2s;
        width: 100%;
      }
      .login-container button:hover {
        background: #1565c0;
      }
      .error-message {
        color: red;
        margin-top: 10px;
        display: none;
      }
    </style>
</head>
<body>
    <div class="login-container">
      <h2>Secure File Manager Login</h2>
      <input type="password" id="password" placeholder="Enter password" />
      <div id="turnstile-widget" style="margin: 15px 0;"></div>
      <button id="loginBtn" onclick="login()" disabled>Login</button>
      <p id="errorMessage" class="error-message"></p>
    </div>
    <script>
      let turnstileToken = null;
      window.onload = function() {
        turnstile.render('#turnstile-widget', {
          sitekey: 'enter your cloudflare turnstile widget sitekey',
          size: 'compact',
          callback: function(token) {
            turnstileToken = token;
            document.getElementById('loginBtn').disabled = false;
          },
          'expired-callback': function() {
            turnstileToken = null;
            document.getElementById('loginBtn').disabled = true;
          },
          'error-callback': function() {
            turnstileToken = null;
            document.getElementById('loginBtn').disabled = true;
          }
        });
      };

      async function login() {
        const password = document.getElementById('password').value;
        const errorMessage = document.getElementById('errorMessage');
        errorMessage.style.display = 'none';

        if (!turnstileToken) {
          errorMessage.style.display = 'block';
          errorMessage.textContent = 'Please complete the Turnstile challenge.';
          return;
        }

        try {
          const response = await fetch('/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              password: password,
              'cf-turnstile-response': turnstileToken
            })
          });

          if (response.ok) {
            window.location.href = '/'; // Redirect to the file manager
          } else {
            const errorData = await response.json();
            errorMessage.style.display = 'block';
            errorMessage.textContent = errorData.error || 'Login failed.';
            turnstile.reset('#turnstile-widget');
            document.getElementById('loginBtn').disabled = true;
            turnstileToken = null;
          }
        } catch (error) {
          console.error('Login error:', error);
          errorMessage.style.display = 'block';
          errorMessage.textContent = 'An error occurred during login.';
        }
      }

      document.getElementById('password').addEventListener('keypress', function(event) {
        if (event.key === 'Enter' && !document.getElementById('loginBtn').disabled) {
          login();
        }
      });
    </script>
</body>
</html>
`;

const fileManagerHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure File Manager</title>
  <style>
    body { font-family: sans-serif; background: #f4f4f4; margin: 0; }
    .file-manager {
      width: 100%;
      margin: 40px auto;
      background: #fff;
      border-radius: 10px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.12);
      padding: 30px;
      box-sizing: border-box;
    }
    .file-manager h2 {
      margin-top: 0;
      color: #3a3a3a;
    }
    .toolbar {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }
    .toolbar select {
      min-width: 120px;
    }
    .toolbar input[type="file"] {
      flex: 1;
    }
    .toolbar button {
      background: #1976d2;
      color: #fff;
      border: none;
      padding: 8px 16px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 1em;
      transition: all 0.2s;
      min-width: 100px;
      box-sizing: border-box;
    }
    .toolbar button:hover {
      background: silver;
      color: black;
    }
    .file-list {
      list-style: none;
      padding: 0;
      margin: 0;
    }
    .file-item {
      display: flex;
      align-items: center;
      padding: 10px 0;
      border-bottom: 1px solid #ececec;
    }
    .file-icon {
      width: 32px;
      height: 32px;
      background: #e3eafc;
      color: #1976d2;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 6px;
      margin-right: 15px;
      font-size: 1.4em;
    }
    .file-name {
      flex: 1;
      color: #333;
      font-weight: 500;
    }
    .file-actions button {
      background: #eee;
      color: #444;
      border: none;
      padding: 5px 10px;
      border-radius: 4px;
      margin-left: 6px;
      cursor: pointer;
      font-size: 0.95em;
      transition: background 0.2s;
    }
    .file-actions button:hover { background: #ccc; }
    .up-folder { color: #1976d2; cursor: pointer; text-decoration: underline; }

    /* Responsive styles */
    @media (max-width: 600px) {
      .file-manager {
        padding: 15px;
      }
      .toolbar {
        flex-direction: column;
        gap: 8px;
        align-items: center;
      }
      .toolbar select,
      .toolbar input[type="file"],
      .toolbar button {
        width: 70%;
        min-width: 0;
        box-sizing: border-box;
      }
    }
    .loading-overlay {
      position: fixed; /* Fixes it to the viewport */
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(255, 255, 255, 0.8); /* Semi-transparent white background */
      display: flex; /* Uses flexbox for easy centering */
      justify-content: center; /* Centers horizontally */
      align-items: center; /* Centers vertically */
      z-index: 1000; /* Ensures it's on top of other content */
      display: none; /* IMPORTANT: Hidden by default */
    }
    .spinner {
      border: 8px solid #f3f3f3; /* Light grey base for the spinner */
      border-top: 8px solid #1976d2; /* Blue top border to create the spinning effect */
      border-radius: 50%; /* Makes it a circle */
      width: 60px;
      height: 60px;
      animation: spin 2s linear infinite; /* Applies the spinning animation */
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    #logoutButton {
      background: red;
      color: white;
      margin-bottom: 1em;
      border: none;
      padding: 8px 16px;
      border-radius: 5px;
      cursor: pointer;
      font-size: 1em;
      transition: background 0.2s;
      min-width: 100px;
      box-sizing: border-box;
      transition all 0.2s;
    }
    #logoutButton:hover {
      background: silver;
      color: black;
    }
  </style>
</head>
<body>
  <div class="file-manager">
    <button id="logoutButton" onclick="logout()">Logout</button>
    <h2>Secure File Manager</h2>
    <div class="toolbar">
      <select id="dirSelect"></select> <input type="file" id="fileInput" />
      <button onclick="uploadFile()">Upload</button>
      <button onclick="fetchFiles()">Refresh</button>
      <button onclick="addNewFolder()">New Folder</button>
    </div>
    <p id="dirmo"></p>
    <ul class="file-list" id="fileList"></ul>
  </div>
  <div class="loading-overlay" id="loadingOverlay">
    <div class="spinner"></div>
  </div>
  <script>
    let currentDir = "";
    async function fetchDirs() {
      showLoading();
      try {
        const resp = await fetch('/folders');
        if (!resp.ok) {
          const errorData = await resp.json();
          throw new Error(errorData.error || \`HTTP error! status: \${resp.status}\`);
        }
        const folders = await resp.json();
        const select = document.getElementById('dirSelect');
        select.innerHTML = ''; // Clear existing options
        select.innerHTML += '<option value="">/</option>'; 
        folders.forEach(folder => {
          select.innerHTML += '<option value="' + folder + '">' + folder + '</option>';
        });
        select.value = currentDir;
        hideLoading();
      } catch (error) {
        hideLoading();
        console.error("Error fetching directories:", error);
        alert("Failed to load directories: " + error.message);
      }
    }

    async function fetchFiles() {
      showLoading();
      try {
        // Use the currentDir state variable to fetch files
        const resp = await fetch('/files' + (currentDir ? '?dir=' + encodeURIComponent(currentDir) : ''));
        if (!resp.ok) {
          const errorData = await resp.json();
          throw new Error(errorData.error || \`HTTP error! status: \${resp.status}\`);
        }
        const items = await resp.json();
        const fileList = document.getElementById('fileList');
        fileList.innerHTML = '';
        // Add 'Go up' folder link if not at the root directory
        if (currentDir) {
          const upDir = currentDir.split('/').slice(0, -1).join('/'); // Calculate parent directory path
          fileList.innerHTML += \`
            <li class="file-item">
              <span class="file-icon">⬆️</span>
              <span class="file-name"><span class="up-folder" onclick="goUpFolder('\${upDir}')">.. (up)</span></span>
              <span class="file-actions"></span>
            </li>\`;
        }

        items.forEach(item => {
          if (item.type === 'folder') {
            fileList.innerHTML += \`
              <li class="file-item">
                <span class="file-icon">📁</span>
                <span class="file-name"><span class="up-folder" onclick="enterFolder('\${item.name}')">\${item.name}</span></span>
                <span class="file-actions"></span>
              </li>\`;
          } else {
            fileList.innerHTML += \`
              <li class="file-item">
                <span class="file-icon">\${item.name.endsWith('.jpg') || item.name.endsWith('.png') ? '🖼️' : '📄'}</span>
                <span class="file-name">\${item.name}</span>
                <span class="file-actions">
                  <button onclick="downloadFile('\${item.name}')">Download</button>
                  <button onclick="deleteFile('\${item.name}')">Delete</button>
                </span>
              </li>\`;
          }
        });
        hideLoading();
      } catch (error) {
        hideLoading();
        console.error("Error fetching files:", error);
        alert("Failed to load files: " + error.message);
      }
    }

    function enterFolder(folderName) {
      // Update currentDir by appending the new folder name
      currentDir = currentDir ? currentDir + '/' + folderName : folderName;
      document.getElementById('dirSelect').value = currentDir;
      updatePathDisplay();
      fetchFiles();
    }

    function goUpFolder(up_dir) {
      if (!currentDir) return;
      currentDir = up_dir;
      document.getElementById('dirSelect').value = currentDir;
      updatePathDisplay();
      fetchFiles();
    }

    async function uploadFile() {
      const input = document.getElementById('fileInput');
      if (!input.files.length) return alert('Please select a file to upload!');
      
      const file = input.files[0];
      const formData = new FormData();
      formData.append('file', file);
      showLoading();
      try {
        const resp = await fetch('/upload' + (currentDir ? '?dir=' + encodeURIComponent(currentDir) : ''), {
          method: 'POST',
          body: formData // FormData handles setting the correct Content-Type header for multipart/form-data
        });
        
        if (!resp.ok) {
          const errorData = await resp.json();
          throw new Error(errorData.error || \`HTTP error! status: \${resp.status}\`);
        }
        
        input.value = ''; // Clear the file input field
        fetchFiles(); // Refresh the file list to show the newly uploaded file
        hideLoading();
      } catch (error) {
        hideLoading();
        console.error("Error uploading file:", error);
        alert("File upload failed: " + error.message);
      }
    }

    function downloadFile(filename) {
      window.open('/download/' + encodeURIComponent(filename) + (currentDir ? '?dir=' + encodeURIComponent(currentDir) : ''), '_blank');
    }

    async function deleteFile(filename) {
      if (!confirm(\`Are you sure you want to delete "\${filename}"?\`)) return; // Confirmation dialog
      showLoading();
      try {
        const resp = await fetch('/delete/' + encodeURIComponent(filename) + (currentDir ? '?dir=' + encodeURIComponent(currentDir) : ''), { method: 'DELETE' });
        if (!resp.ok) {
          const errorData = await resp.json();
          throw new Error(errorData.error || \`HTTP error! status: \${resp.status}\`);
        }
        fetchFiles(); // Refresh the file list after deletion
        hideLoading();
      } catch (error) {
        hideLoading();
        console.error("Error deleting file:", error);
        alert("File deletion failed: " + error.message);
      }
    }

    async function addNewFolder() {
      const folderName = prompt("Enter new folder name:");
      if (!folderName) return; // User cancelled or entered an empty name
      showLoading();
      try {
        const resp = await fetch('/newfolder?dir=' + encodeURIComponent(currentDir || '') + '&name=' + encodeURIComponent(folderName));
        if (!resp.ok) {
          const errorData = await resp.json();
          throw new Error(errorData.error || \`HTTP error! status: \${resp.status}\`);
        }
        fetchDirs().then(fetchFiles); // Refresh both folders (dropdown) and files
        hideLoading();
      } catch (error) {
        hideLoading();
        console.error("Error creating new folder:", error);
        alert("Folder creation failed: " + error.message);
      }
    }

    document.addEventListener('DOMContentLoaded', () => {
      fetchDirs().then(() => {
        document.getElementById('dirSelect').value = currentDir;
        updatePathDisplay();
        fetchFiles();
      });
      document.getElementById('dirSelect').addEventListener('change', (event) => {
        currentDir = event.target.value;
        updatePathDisplay();
        fetchFiles();
      });
    });

    function updatePathDisplay() {
      document.getElementById('dirmo').innerHTML = "path: " + (currentDir || "/");
    }

    function showLoading() {
      loadingOverlay.style.display = 'flex'; // Change display to flex to make it visible
    }
    function hideLoading() {
      loadingOverlay.style.display = 'none'; // Change display to none to hide it
    }

    async function logout() {
      try {
        const response = await fetch('/logout');
        if (response.ok) {
          window.location.href = '/login'; // Redirect to the login page after successful logout
        } else {
          const errorData = await response.json();
          console.error('Logout failed:', errorData.error || 'Unknown error');
          alert('Logout failed: ' + (errorData.error || 'Please try again.'));
        }
      } catch (error) {
        console.error('Logout error:', error);
        alert('An error occurred during logout. Please try again.');
      }
    }
    document.getElementById('logoutButton').addEventListener('click', logout);
  </script>
</body>
</html>
`;

const server = http.createServer(async (req, res) => {
  const urlObj = new URL(req.url, `http://${req.headers.host}`);
  const dir = urlObj.searchParams.get('dir') || '';
  const cookies = parseCookies(req);
  const isAuthenticated = cookies[SESSION_COOKIE_NAME] && verifySessionToken(cookies[SESSION_COOKIE_NAME], crypto.createHash('sha256').update(PASSWORD).digest('hex'));
  
  if (req.method === 'GET' && urlObj.pathname === '/login') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(loginHtml);
    return;
  }

  if (req.method === 'POST' && urlObj.pathname === '/login') {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        const password = parsed.password;
        const turnstileToken = parsed['cf-turnstile-response'];

        if (!turnstileToken) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Turnstile token missing.' }));
          return;
        }
        const TURNSTILE_SECRET_KEY = 'enter your cloudflare turnstile widget secret key';
        const verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        const params = new URLSearchParams();
        params.append('secret', TURNSTILE_SECRET_KEY);
        params.append('response', turnstileToken);
        // Optionally: params.append('remoteip', req.socket.remoteAddress);

        let cfResponse;
        try {
          cfResponse = await axios.post(verifyUrl, params,
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
          );
          // console.log('Turnstile verification response:', cfResponse.data);
        } catch (err) {
          console.error('Error contacting Turnstile verification server:', err.message || err); 
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Failed to contact Turnstile verification server.' }));
          return;
        }
        if (!cfResponse.data.success) {
          console.log('Turnstile verification failed, response data:', cfResponse.data);
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Turnstile verification failed.' }));
          return;
        }

        if (password === PASSWORD) {
          const passwordHash = crypto.createHash('sha256').update(PASSWORD).digest('hex');
          const token = generateSessionToken(passwordHash);
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': `${SESSION_COOKIE_NAME}=${token}; HttpOnly; Max-Age=${SESSION_EXPIRY_MS / 1000}; Path=/;`
          });
          res.end(JSON.stringify({ success: true }));
          } else {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Incorrect password.' }));
          }
        } catch (error) {
          console.error('Login parsing error:', error);
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid request body.' }));
        }
      });
      return;
  }

  if (req.method === 'GET' && urlObj.pathname === '/logout') {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': `${SESSION_COOKIE_NAME}=; HttpOnly; Max-Age=0; Path=/;` // Clear the cookie
    });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  if (!isAuthenticated) {
    //res.writeHead(401, { 'Content-Type': 'application/json' });
    //res.end(JSON.stringify({ error: 'Unauthorized: Please log in.' }));
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(loginHtml);
    return;
  }

  try {
    if (req.method === 'GET' && (req.url === '/' || urlObj.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(fileManagerHtml);
    }

    else if (req.method === 'GET' && urlObj.pathname === '/folders') {
      try {
        const folders = getFolders();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(folders));
      } catch (error) {
        console.error("Server Error: /folders -", error);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message || 'Internal Server Error' }));
      }
    }

    else if (req.method === 'GET' && urlObj.pathname === '/files') {
      try {
        const dirPath = safePath(dir);
        const items = fs.readdirSync(dirPath, { withFileTypes: true }).map(d => d.isDirectory() ? { name: d.name, type: 'folder' } : { name: d.name, type: 'file' });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(items));
      } catch (error) {
        console.error(`Server Error: /files?dir=${dir} -`, error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message || 'Bad Request: Could not list files.' }));
      }
    }
          
    else if (req.method === 'GET' && urlObj.pathname.startsWith('/download/')) {
      const filename = decodeURIComponent(urlObj.pathname.split('/download/')[1]);
      try {
        const filepath = safePath(path.join(dir, filename)); 
        if (fs.existsSync(filepath) && fs.statSync(filepath).isFile()) {
          const ext = path.extname(filepath).toLowerCase();
          const contentType = mimeTypes[ext] || 'application/octet-stream';
          res.writeHead(200, {
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Type': contentType
          });
          fs.createReadStream(filepath).pipe(res);
        } else {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'File not found or is not a file.' }));
        }
      } catch (error) {
        console.error(`Server Error: /download/${filename}?dir=${dir} -`, error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message || 'Invalid path or file access error.' }));
      }
    }

    else if (req.method === 'POST' && urlObj.pathname === '/upload') {
      const contentType = req.headers['content-type'];
      if (!contentType || !contentType.startsWith('multipart/form-data')) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Bad Request: Content-Type must be multipart/form-data.' }));
        return;
      }
      const boundary = contentType.split('boundary=')[1];
      parseMultipart(req, boundary, (filename, fileBuffer) => {
        if (filename && fileBuffer) {
          try {
            let dest = safePath(path.join(dir, filename));
            if (fs.existsSync(dest)) {
              const ext = path.extname(filename);
              const base = path.basename(filename, ext);
              let n = 1, newName;
              do {
                newName = `${base}(${n})${ext}`;
                dest = safePath(path.join(dir, newName));
                n++;
              } while (fs.existsSync(dest));
            }
            fs.writeFileSync(dest, fileBuffer);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true, filename: path.basename(dest) }));
          } catch (error) {
            console.error(`Server Error: /upload file processing -`, error);
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: error.message || 'Upload failed due to invalid path or server error.' }));
          }
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No file data found in the request.' }));
        }
      });
    }
          
    else if (req.method === 'DELETE' && urlObj.pathname.startsWith('/delete/')) {
      const filename = decodeURIComponent(urlObj.pathname.split('/delete/')[1]);
      try {
        const filepath = safePath(path.join(dir, filename));
        if (fs.existsSync(filepath) && fs.statSync(filepath).isFile()) {
          fs.unlinkSync(filepath); // Delete the file
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true }));
        } else {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'File not found or is a directory.' }));
        }
      } catch (error) {
        console.error(`Server Error: /delete/${filename}?dir=${dir} -`, error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message || 'Invalid path or deletion failed.' }));
      }
    }

    else if (req.method === 'GET' && urlObj.pathname === '/newfolder') {
      const folderName = urlObj.searchParams.get('name');
      const sanitizedFolderName = path.basename(folderName || '');
      if (!sanitizedFolderName || sanitizedFolderName === '.' || sanitizedFolderName === '..') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid folder name. Cannot be empty, "." or "..".' }));
        return;
      }
      try {
        const parent = safePath(dir); 
        const newFolder = path.join(parent, sanitizedFolderName);
        if (!fs.existsSync(newFolder)) {
          fs.mkdirSync(newFolder);
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, folder: sanitizedFolderName }));
        } else {
          res.writeHead(409, { 'Content-Type': 'application/json' }); 
          res.end(JSON.stringify({ error: 'Folder with that name already exists.' }));
        }
      } catch (error) {
        console.error(`Server Error: /newfolder?dir=${dir}&name=${folderName} -`, error);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message || 'Failed to create folder.' }));
      }
    }
    else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    }
  } catch (error) {
    console.error("Unhandled request error (top-level catch):", error);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal server error occurred.' }));
  }
});

const PORT = 8080; // Use environment variable for port or default to 8080
const HOST = '0.0.0.0'; // Listen on all available network interfaces

server.listen(PORT, HOST, () => {
  console.log(`Secure file manager running at http://${HOST}:${PORT}/`);
  console.log('Press Ctrl+C to stop the server.');
});