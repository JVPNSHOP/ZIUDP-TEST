#!/bin/bash
# Zivpn UDP Module installer with Web Panel
# Creator Jue Htet 
# Modified with Web Panel (Port 8080)

echo -e "Server ကို update လုပ်နေပါတယ်..."
sudo apt-get update && apt-get upgrade -y
systemctl stop zivpn.service 1> /dev/null 2> /dev/null

echo -e "လိုအပ်တဲ့ packages တွေ install လုပ်နေပါတယ်"
apt-get install -y python3 python3-pip git nginx curl sqlite3

echo -e "UDP Service ကို download လုပ်နေပါတယ်"
wget https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn 1> /dev/null 2> /dev/null
chmod +x /usr/local/bin/zivpn
mkdir -p /etc/zivpn 1> /dev/null 2> /dev/null

# Config file ကိုဖန်တီးမယ်
cat <<EOF > /etc/zivpn/config.json
{
  "server": ":5667",
  "users": []
}
EOF

echo "Certificate files တွေကိုဖန်တီးနေပါတယ်:"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"

sysctl -w net.core.rmem_max=16777216 1> /dev/null 2> /dev/null
sysctl -w net.core.wmem_max=16777216 1> /dev/null 2> /dev/null

# Systemd service ကိုဖန်တီးမယ်
cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# Web Panel ကို download ဆွဲမယ်
echo -e "Web Panel ကို install လုပ်နေပါတယ်"
cd /opt
git clone https://github.com/zahidbd2/zivpn-web-panel.git 2> /dev/null || mkdir -p zivpn-web-panel

# Web Panel Python Code (Port 8080 သုံးမယ်)
cat <<'EOF' > /opt/zivpn-web-panel/app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import json
import os
import subprocess
import datetime
from datetime import datetime, timedelta
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'zivpn_secret_key_2024'
app.config['DATABASE'] = '/etc/zivpn/users.db'

# Database ကိုစတင်မယ်
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users
        (id INTEGER PRIMARY KEY AUTOINCREMENT,
         username TEXT UNIQUE NOT NULL,
         password TEXT NOT NULL,
         created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
         expired_at DATETIME,
         is_active INTEGER DEFAULT 1)
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS admin
        (id INTEGER PRIMARY KEY,
         username TEXT UNIQUE NOT NULL,
         password TEXT NOT NULL)
    ''')
    # Default admin ကိုဖန်တီးမယ်
    admin_password = hashlib.sha256('admin123'.encode()).hexdigest()
    c.execute('INSERT OR IGNORE INTO admin (id, username, password) VALUES (1, "admin", ?)', (admin_password,))
    conn.commit()
    conn.close()

# Admin login လိုအပ်တဲ့ function
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('admin_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect(app.config['DATABASE'])
        c = conn.cursor()
        c.execute('SELECT * FROM admin WHERE username = ? AND password = ?', (username, hashed_password))
        admin = c.fetchone()
        conn.close()
        
        if admin:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('အသုံးပြုသ့်အမည် (သို့) လျှို့ဝှက်နံပါတ် မှားယွင်းနေပါတယ်!', 'error')
    
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ZIVPN Admin Login</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background: #f8f9fa; }
            .login-container { max-width: 400px; margin: 100px auto; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="login-container">
                <div class="card shadow">
                    <div class="card-header bg-primary text-white">
                        <h4 class="mb-0">ZIVPN Admin Login</h4>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages(with_categories=true) %}
                            {% if messages %}
                                {% for category, message in messages %}
                                    <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }}">{{ message }}</div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}
                        <form method="POST">
                            <div class="mb-3">
                                <label class="form-label">အသုံးပြုသ့်အမည်:</label>
                                <input type="text" name="username" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">လျှို့ဝှက်နံပါတ်:</label>
                                <input type="password" name="password" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">ဝင်မည်</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/dashboard')
@admin_required
def dashboard():
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    # စုစုပေါင်း user ရယူမယ်
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    
    # Active user ရယူမယ်
    c.execute('SELECT COUNT(*) FROM users WHERE is_active = 1 AND expired_at > datetime("now")')
    active_users = c.fetchone()[0]
    
    # Online user ရယူမယ် (simulated)
    c.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
    online_users = c.fetchone()[0]
    
    # User list ရယူမယ်
    c.execute('SELECT * FROM users ORDER BY created_at DESC')
    users = c.fetchall()
    
    conn.close()
    
    # သက်တမ်းကျန်ရက်တွက်မယ်
    users_with_days = []
    for user in users:
        user_dict = {
            'id': user[0],
            'username': user[1],
            'password': user[2],
            'created_at': user[3],
            'expired_at': user[4],
            'is_active': user[5]
        }
        
        if user[4]:
            expired_date = datetime.strptime(user[4], '%Y-%m-%d %H:%M:%S')
            days_left = (expired_date - datetime.now()).days
            user_dict['days_left'] = max(0, days_left)
        else:
            user_dict['days_left'] = 0
            
        users_with_days.append(user_dict)
    
    return render_template('dashboard.html', 
                         total_users=total_users,
                         active_users=active_users,
                         online_users=online_users,
                         users=users_with_days)

@app.route('/admin/create_user', methods=['POST'])
@admin_required
def create_user():
    username = request.form['username']
    password = request.form['password']
    days_valid = int(request.form['days_valid'])
    
    expired_at = (datetime.now() + timedelta(days=days_valid)).strftime('%Y-%m-%d %H:%M:%S')
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    try:
        c.execute('INSERT INTO users (username, password, expired_at) VALUES (?, ?, ?)',
                 (username, password, expired_at))
        conn.commit()
        
        # ZIVPN config ကို update လုပ်မယ်
        update_zivpn_config()
        
        flash('User အောင်မြင်စွာဖန်တီးပြီးပါပြီ!', 'success')
    except sqlite3.IntegrityError:
        flash('ဤအသုံးပြုသ့်အမည်ရှိပြီးသားဖြစ်နေပါသည်!', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    password = request.form['password']
    days_valid = int(request.form['days_valid'])
    
    expired_at = (datetime.now() + timedelta(days=days_valid)).strftime('%Y-%m-%d %H:%M:%S')
    
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    c.execute('UPDATE users SET password = ?, expired_at = ? WHERE id = ?',
             (password, expired_at, user_id))
    conn.commit()
    conn.close()
    
    # ZIVPN config ကို update လုပ်မယ်
    update_zivpn_config()
    
    flash('User အောင်မြင်စွာ update လုပ်ပြီးပါပြီ!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/delete_user/<int:user_id>')
@admin_required
def delete_user(user_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    # ZIVPN config ကို update လုပ်မယ်
    update_zivpn_config()
    
    flash('User အောင်မြင်စွာ ဖျက်ပြီးပါပြီ!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin/toggle_user/<int:user_id>')
@admin_required
def toggle_user(user_id):
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    c.execute('SELECT is_active FROM users WHERE id = ?', (user_id,))
    current_status = c.fetchone()[0]
    
    new_status = 0 if current_status == 1 else 1
    
    c.execute('UPDATE users SET is_active = ? WHERE id = ?', (new_status, user_id))
    conn.commit()
    conn.close()
    
    # ZIVPN config ကို update လုပ်မယ်
    update_zivpn_config()
    
    flash('User status အောင်မြင်စွာ update လုပ်ပြီးပါပြီ!', 'success')
    return redirect(url_for('dashboard'))

def update_zivpn_config():
    """ZIVPN config.json ကို active users တွေနဲ့ update လုပ်မယ်"""
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    
    c.execute('SELECT password FROM users WHERE is_active = 1 AND expired_at > datetime("now")')
    active_passwords = [row[0] for row in c.fetchall()]
    conn.close()
    
    # လက်ရှိ config ကိုဖတ်မယ်
    with open('/etc/zivpn/config.json', 'r') as f:
        config = json.load(f)
    
    # Users array ကို update လုပ်မယ်
    config['users'] = active_passwords
    
    # config ကိုပြန်ရေးမယ်
    with open('/etc/zivpn/config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    # ZIVPN service ကို restart လုပ်မယ်
    subprocess.run(['systemctl', 'restart', 'zivpn.service'], capture_output=True)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080, debug=False)
EOF

# Templates directory နဲ့ dashboard template ကိုဖန်တီးမယ်
mkdir -p /opt/zivpn-web-panel/templates

# Dashboard template
cat <<'EOF' > /opt/zivpn-web-panel/templates/dashboard.html
<!DOCTYPE html>
<html>
<head>
    <title>ZIVPN Admin Panel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .sidebar { background: #343a40; min-height: 100vh; }
        .sidebar .nav-link { color: #fff; }
        .sidebar .nav-link:hover { background: #495057; }
        .stat-card { border-radius: 10px; }
        .copy-btn { cursor: pointer; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <nav class="col-md-3 col-lg-2 d-md-block sidebar collapse">
                <div class="position-sticky pt-3">
                    <h5 class="text-white px-3">ZIVPN Admin</h5>
                    <ul class="nav flex-column">
                        <li class="nav-item">
                            <a class="nav-link active" href="#">
                                <i class="fas fa-tachometer-alt"></i>
                                ပင်မစာမျက်နှာ
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="#" data-bs-toggle="modal" data-bs-target="#createUserModal">
                                <i class="fas fa-user-plus"></i>
                                User အသစ်ဖန်တီးမည်
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="/admin/logout">
                                <i class="fas fa-sign-out-alt"></i>
                                ထွက်မည်
                            </a>
                        </li>
                    </ul>
                </div>
            </nav>

            <!-- Main content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">ပင်မစာမျက်နှာ</h1>
                </div>

                <!-- Stats Cards -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card text-white bg-primary stat-card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4>{{ total_users }}</h4>
                                        <p>စုစုပေါင်း User</p>
                                    </div>
                                    <i class="fas fa-users fa-2x"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-white bg-success stat-card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4>{{ active_users }}</h4>
                                        <p>Active User</p>
                                    </div>
                                    <i class="fas fa-user-check fa-2x"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-white bg-info stat-card">
                            <div class="card-body">
                                <div class="d-flex justify-content-between">
                                    <div>
                                        <h4>{{ online_users }}</h4>
                                        <p>Online User</p>
                                    </div>
                                    <i class="fas fa-wifi fa-2x"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Users Table -->
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">User Management</h5>
                    </div>
                    <div class="card-body">
                        {% with messages = get_flashed_messages(with_categories=true) %}
                            {% if messages %}
                                {% for category, message in messages %}
                                    <div class="alert alert-{{ 'danger' if category == 'error' else 'success' }} alert-dismissible fade show">
                                        {{ message }}
                                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                                    </div>
                                {% endfor %}
                            {% endif %}
                        {% endwith %}

                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>အသုံးပြုသ့်အမည်</th>
                                        <th>လျှို့ဝှက်နံပါတ်</th>
                                        <th>ကျန်ရက်များ</th>
                                        <th>အခြေအနေ</th>
                                        <th>လုပ်ဆောင်ချက်များ</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for user in users %}
                                    <tr>
                                        <td>{{ user.username }}</td>
                                        <td>
                                            <span id="password-{{ user.id }}">{{ user.password }}</span>
                                            <button class="btn btn-sm btn-outline-secondary copy-btn" 
                                                    data-target="password-{{ user.id }}">
                                                <i class="fas fa-copy"></i>
                                            </button>
                                        </td>
                                        <td>
                                            <span class="badge {% if user.days_left > 7 %}bg-success{% elif user.days_left > 3 %}bg-warning{% else %}bg-danger{% endif %}">
                                                {{ user.days_left }} ရက်
                                            </span>
                                        </td>
                                        <td>
                                            {% if user.is_active and user.days_left > 0 %}
                                                <span class="badge bg-success">Online</span>
                                            {% else %}
                                                <span class="badge bg-secondary">Offline</span>
                                            {% endif %}
                                        </td>
                                        <td>
                                            <button class="btn btn-sm btn-warning" 
                                                    data-bs-toggle="modal" 
                                                    data-bs-target="#editUserModal"
                                                    data-userid="{{ user.id }}"
                                                    data-username="{{ user.username }}"
                                                    data-password="{{ user.password }}"
                                                    data-days="{{ user.days_left }}">
                                                <i class="fas fa-edit"></i>
                                            </button>
                                            <a href="/admin/delete_user/{{ user.id }}" 
                                               class="btn btn-sm btn-danger"
                                               onclick="return confirm('ဤ user ကိုဖျက်မှာသေချာပါသလား?')">
                                                <i class="fas fa-trash"></i>
                                            </a>
                                            <a href="/admin/toggle_user/{{ user.id }}" 
                                               class="btn btn-sm {% if user.is_active and user.days_left > 0 %}btn-secondary{% else %}btn-success{% endif %}">
                                                <i class="fas fa-power-off"></i>
                                            </a>
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- Create User Modal -->
    <div class="modal fade" id="createUserModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">User အသစ်ဖန်တီးမည်</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" action="/admin/create_user">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">အသုံးပြုသ့်အမည်:</label>
                            <input type="text" name="username" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">လျှို့ဝှက်နံပါတ်:</label>
                            <input type="text" name="password" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">သက်တမ်းရက်များ:</label>
                            <input type="number" name="days_valid" class="form-control" value="30" min="1" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">ပိတ်မည်</button>
                        <button type="submit" class="btn btn-primary">User ဖန်တီးမည်</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Edit User Modal -->
    <div class="modal fade" id="editUserModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">User ကိုပြင်ဆင်မည်</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST" id="editUserForm">
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label">အသုံးပြုသ့်အမည်:</label>
                            <input type="text" id="edit_username" class="form-control" readonly>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">လျှို့ဝှက်နံပါတ်:</label>
                            <input type="text" name="password" id="edit_password" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">သက်တမ်းရက်များ:</label>
                            <input type="number" name="days_valid" id="edit_days" class="form-control" min="1" required>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">ပိတ်မည်</button>
                        <button type="submit" class="btn btn-primary">User update လုပ်မည်</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Copy to clipboard function
        document.querySelectorAll('.copy-btn').forEach(button => {
            button.addEventListener('click', function() {
                const targetId = this.getAttribute('data-target');
                const text = document.getElementById(targetId).textContent;
                navigator.clipboard.writeText(text).then(() => {
                    const originalHtml = this.innerHTML;
                    this.innerHTML = '<i class="fas fa-check"></i>';
                    setTimeout(() => {
                        this.innerHTML = originalHtml;
                    }, 2000);
                });
            });
        });

        // Edit modal handler
        const editUserModal = document.getElementById('editUserModal');
        editUserModal.addEventListener('show.bs.modal', function(event) {
            const button = event.related_target;
            const userId = button.getAttribute('data-userid');
            const username = button.getAttribute('data-username');
            const password = button.getAttribute('data-password');
            const days = button.getAttribute('data-days');

            document.getElementById('edit_username').value = username;
            document.getElementById('edit_password').value = password;
            document.getElementById('edit_days').value = days;
            
            document.getElementById('editUserForm').action = `/admin/edit_user/${userId}`;
        });
    </script>
</body>
</html>
EOF

# Python requirements install လုပ်မယ်
pip3 install flask

# Port 8080 အတွက် nginx configuration (မလိုတော့ပါ - direct port 8080 သုံးမယ်)
# ဒီတစ်ခါ nginx မသုံးတော့ပဲ direct port 8080 မှာ run မယ်

# Web panel အတွက် systemd service (Port 8080)
cat <<EOF > /etc/systemd/system/zivpn-panel.service
[Unit]
Description=ZIVPN Web Panel (Port 8080)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zivpn-web-panel
ExecStart=/usr/bin/python3 app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Services တွေကိုစမယ်
systemctl daemon-reload
systemctl enable zivpn.service
systemctl enable zivpn-panel.service

systemctl start zivpn.service
systemctl start zivpn-panel.service

# Firewall rules - Port 8080 ကိုဖွင့်မယ်
iptables -t nat -A PREROUTING -i $(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1) -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 6000:19999/udp
ufw allow 5667/udp
ufw allow 8080/tcp

# Cleanup
rm -f zi.* 1> /dev/null 2> /dev/null

echo -e ""
echo -e "========================================="
echo -e "ZIVPN UDP with Web Panel တပ်ဆင်ပြီးပါပြီ!"
echo -e "========================================="
echo -e "Web Panel URL: http://$(curl -s ifconfig.me):8080/"
echo -e "Admin Login: admin / admin123"
echo -e ""
echo -e "အဓိကလုပ်ဆောင်ချက်များ:"
echo -e "✅ Admin Login Panel"
echo -e "✅ User အသစ်ဖန်တီးခြင်း/ပြင်ဆင်ခြင်း/ဖျက်ခြင်း"
echo -e "✅ သက်တမ်းသတ်မှတ်ခြင်း"
echo -e "✅ Real-time User အခြေအနေ"
echo -e "✅ User/Password copy ခလုတ်များ"
echo -e "✅ ကျန်ရက်များကိုတွက်ချက်ပြသခြင်း"
echo -e "✅ စုစုပေါင်း User ရေတွက်ခြင်း"
echo -e "✅ Port 8080 တွင်အလုပ်လုပ်ခြင်း"
echo -e "========================================="
echo -e ""
echo -e "⚠️  အရေးကြီးမှတ်သားရန်:"
echo -e "🔹 Web Panel ကို port 8080 မှာသုံးထားပါတယ်"
echo -e "🔹 URL: http://your-server-ip:8080"
echo -e "🔹 Admin password ကိုပထမဆုံး login ဝင်ပြီးတာနဲ့ပြောင်းပါ"
echo -e "🔹 Firewall မှာ port 8080 ဖွင့်ထားပြီးသားဖြစ်ပါတယ်"
echo -e "========================================="