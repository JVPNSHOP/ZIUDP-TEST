cat > zi.sh <<'BASH'
#!/bin/bash
# ZIVPN UDP + Tailwind Web Panel (Graceful Reload Only, Admin-Menu)
# - Save  : config.json write-only (no reload/restart)
# - Apply : reload (HUP) only (never restart) -> existing UDP sessions stay up
# - NAT   : REDIRECT 6000-19999/udp -> 5667/udp via systemd helper
# - FW    : UFW opens 5667/udp and 6000-19999/udp
# - Admin : Credentials stored in SQLite (hashed), changeable via CLI menu (no restart)
# Credit  : Zivpn Owner | Rebuild : Jue Htet | Hardened: ChatGPT

set -euo pipefail

ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_DIR="/etc/zivpn"
ZIVPN_CFG="${ZIVPN_DIR}/config.json"
ZIVPN_SVC="zivpn.service"

ADMIN_DIR="/opt/zivpn-admin"
APP_PY="${ADMIN_DIR}/app.py"
SYNC_PY="${ADMIN_DIR}/sync.py"
VENV="${ADMIN_DIR}/venv"
ENV_FILE="${ADMIN_DIR}/.env"
PANEL_SVC="zivpn-admin.service"
SYNC_SVC="zivpn-sync.service"
SYNC_TIMER="zivpn-sync.timer"

NAT_SVC="zivpn-nat.service"   # ensure NAT+FW each boot

echo "==> Updating packages..."
apt-get update -y && apt-get upgrade -y
apt-get install -y python3-venv python3-pip openssl ufw curl jq conntrack iproute2 iptables sqlite3 > /dev/null

echo "==> Installing ZIVPN binary..."
systemctl stop ${ZIVPN_SVC} 2>/dev/null || true
wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O "${ZIVPN_BIN}"
chmod +x "${ZIVPN_BIN}"

mkdir -p "${ZIVPN_DIR}"
cat > "${ZIVPN_CFG}" <<'JSON'
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {"mode": "passwords", "config": ["zi"]},
  "config": ["zi"]
}
JSON

echo "==> Generating TLS certificate..."
openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
  -subj "/C=US/ST=CA/L=LA/O=ZIVPN/CN=zivpn" \
  -keyout "${ZIVPN_DIR}/zivpn.key" -out "${ZIVPN_DIR}/zivpn.crt" > /dev/null 2>&1

# --- systemd unit for ZIVPN (reload only; never restart on Apply) ---
cat >/etc/systemd/system/${ZIVPN_SVC} <<'EOF'
[Unit]
Description=ZIVPN UDP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root
KillMode=mixed
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ${ZIVPN_SVC}

# --- UDP stability sysctls ---
cat > /etc/sysctl.d/99-zivpn-udp.conf <<'SYS'
net.netfilter.nf_conntrack_udp_timeout=300
net.netfilter.nf_conntrack_udp_timeout_stream=1800
net.core.rmem_max=26214400
net.core.wmem_max=26214400
SYS
sysctl --system > /dev/null

# --- NAT+FW helper (runs each boot & now) ---
cat >/usr/local/sbin/zivpn-nat-ensure.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
IFC=$(ip -4 route ls | awk '/default/ {print $5; exit}')
# Remove old DNAT rules if any
iptables -t nat -S PREROUTING | awk '/--dport 6000:19999/ {print $0}' | sed 's/^-A /-D /' | while read -r r; do iptables -t nat $r || true; done
# Ensure REDIRECT -> 5667 exists only once
if ! iptables -t nat -C PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667 2>/dev/null; then
  iptables -t nat -A PREROUTING -i "$IFC" -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667
fi

# UFW rules (add if UFW is active)
if ufw status | grep -qi "Status: active"; then
  ufw allow 5667/udp || true
  ufw allow 8088/tcp || true
  ufw allow 6000:19999/udp || true
fi
SH
chmod +x /usr/local/sbin/zivpn-nat-ensure.sh

cat >/etc/systemd/system/${NAT_SVC} <<'EOF'
[Unit]
Description=Ensure ZIVPN NAT/Firewall rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/zivpn-nat-ensure.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now ${NAT_SVC}

# If UFW is active on this machine, open the ports now (safe even if already allowed)
if ufw status | grep -qi "Status: active"; then
  ufw allow 5667/udp || true
  ufw allow 8088/tcp || true
  ufw allow 6000:19999/udp || true
fi

echo "==> Setting up Web Admin Panel..."
mkdir -p "${ADMIN_DIR}"
python3 -m venv "${VENV}"
# Werkzeug needed for password hashing
"${VENV}/bin/pip" install flask waitress werkzeug > /dev/null

read -rp "Admin username [default: admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}
read -rp "Admin password [default: change-me]: " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-change-me}

cat > "${ENV_FILE}" <<EOF
# Seed only; app will migrate to DB on first run
ADMIN_USER=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
BIND_HOST=0.0.0.0
BIND_PORT=8088
ZIVPN_CONFIG=${ZIVPN_CFG}
ZIVPN_SERVICE=${ZIVPN_SVC}
EOF

# ------------------- app.py (DB-based admin; Save=write only, Apply=reload only) -------------------
cat > "${APP_PY}" <<'PY'
#!/usr/bin/env python3
import os, json, sqlite3, tempfile, subprocess, time
from subprocess import DEVNULL
from datetime import date, datetime
from flask import Flask, request, redirect, url_for, session, render_template_string, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

DB="/var/lib/zivpn-admin/zivpn.db"
os.makedirs("/var/lib/zivpn-admin", exist_ok=True)
ZIVPN_CFG=os.getenv("ZIVPN_CONFIG","/etc/zivpn/config.json")
ZIVPN_SVC=os.getenv("ZIVPN_SERVICE","zivpn.service")
SEED_USER=os.getenv("ADMIN_USER","admin")
SEED_PASS=os.getenv("ADMIN_PASSWORD","change-me")
app=Flask(__name__)
app.secret_key=os.urandom(24)

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

# ---- DB schema + seed admin into settings table (hashed) ----
with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        expires DATE
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS settings(
        k TEXT PRIMARY KEY,
        v TEXT
    )""")
    cur = con.execute("SELECT COUNT(*) FROM settings").fetchone()[0]
    if cur == 0:
        con.executemany("INSERT INTO settings(k,v) VALUES(?,?)", [
            ("admin_user", SEED_USER),
            ("admin_pass_hash", generate_password_hash(SEED_PASS))
        ])

def get_admin():
    with db() as con:
        u = con.execute("SELECT v FROM settings WHERE k='admin_user'").fetchone()[0]
        p = con.execute("SELECT v FROM settings WHERE k='admin_pass_hash'").fetchone()[0]
    return u, p

def set_admin(new_user, new_plain_password=None):
    with db() as con:
        if new_user:
            con.execute("UPDATE settings SET v=? WHERE k='admin_user'", (new_user,))
        if new_plain_password:
            con.execute("UPDATE settings SET v=? WHERE k='admin_pass_hash'",
                        (generate_password_hash(new_plain_password),))

def logs():
    try:
        return subprocess.check_output(["journalctl","-u",ZIVPN_SVC,"--since","-15min","-o","cat"]).decode().lower()
    except Exception:
        return ""

def days_left(expires_str):
    try:
        exp=datetime.strptime(expires_str,"%Y-%m-%d").date()
        return (exp - date.today()).days
    except Exception:
        return None

def active_rows():
    log=logs()
    today=date.today()
    rows=[]
    with db() as con:
        for r in con.execute("SELECT * FROM users"):
            exp=datetime.strptime(r["expires"],"%Y-%m-%d").date()
            expired=exp<today
            online=(not expired) and (r["password"].lower() in log)
            rows.append({
                "id":r["id"], "username":r["username"], "password":r["password"],
                "expires":r["expires"], "expired":expired, "online":online,
                "days_left": days_left(r["expires"])
            })
    return rows

def write_cfg(passwords):
    cfg={}
    try:
        cfg=json.load(open(ZIVPN_CFG))
    except Exception:
        pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=passwords
    cfg["config"]=passwords
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,ZIVPN_CFG)

def sync():
    # Save-time: only write config (no reload/restart)
    with db() as con:
        pw=[r[0] for r in con.execute(
            "SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    if not pw: pw=["zi"]
    write_cfg(pw)

def login_required(f):
    @wraps(f)
    def w(*a,**kw):
        if not session.get("ok"): return redirect(url_for("login"))
        return f(*a,**kw)
    return w

# ---------- Login ----------
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u_in = request.form.get("u","")
        p_in = request.form.get("p","")
        admin_user, admin_hash = get_admin()
        if u_in == admin_user and check_password_hash(admin_hash, p_in):
            session["ok"]=True; return redirect("/")
        flash("Invalid credentials")
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen grid place-items-center bg-slate-900 text-white">
<div class="w-[360px] bg-slate-800/70 backdrop-blur p-6 rounded-2xl shadow-2xl ring-1 ring-white/10">
  <h2 class="text-xl font-bold mb-2">ZIVPN Login</h2>
  <form method=post class="space-y-3">
    <input name=u class="w-full p-2 rounded bg-slate-700/80 outline-none" placeholder="👤 Username">
    <input name=p type=password class="w-full p-2 rounded bg-slate-700/80 outline-none" placeholder="🔒 Password">
    <button class="w-full bg-emerald-600 hover:bg-emerald-500 transition py-2 rounded-xl shadow">Login</button>
  </form>
</div></body></html>''')

# ---------- Dashboard ----------
@app.route("/")
@login_required
def index():
    rows=active_rows()
    total_users=len(rows)
    total_online=sum(1 for r in rows if not r["expired"])
    total_offline=sum(1 for r in rows if r["expired"])
    default_exp=date.today().isoformat()
    try:
        vps_ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception:
        vps_ip=request.host.split(":")[0]
    server_ts=int(time.time())
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-50">
<header class="bg-slate-900 text-white">
  <div class="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
    <h1 class="text-xl font-bold">ZIVPN</h1>
    <div class="flex gap-2">
      <a href="/settings" class="bg-emerald-600 hover:bg-emerald-500 px-3 py-1 rounded">Settings</a>
      <a href="/logout" class="bg-slate-700 hover:bg-slate-600 px-3 py-1 rounded">Logout</a>
    </div>
  </div>
</header>
<main class="max-w-5xl mx-auto px-4 py-4 space-y-4">
  {% with msgs = get_flashed_messages(with_categories=true) %}
  {% if msgs %}
    {% for cat, msg in msgs %}
      <div class="bg-emerald-50 ring-1 ring-emerald-200 text-emerald-900 rounded-xl p-3 text-sm whitespace-pre-wrap">{{ msg }}</div>
    {% endfor %}
  {% endif %}
  {% endwith %}

  <section class="grid sm:grid-cols-2 gap-3">
    <div class="bg-white rounded-xl p-3 ring-1 ring-slate-200">VPS IP: <b>{{ vps_ip }}</b></div>
    <div class="bg-white rounded-xl p-3 ring-1 ring-slate-200">Users: <b>{{ total_users }}</b> | Online: <b class="text-emerald-600">{{ total_online }}</b></div>
  </section>

  <section class="flex gap-2">
    <form method="post" action="/apply">
      <button class="bg-slate-900 hover:bg-slate-800 text-white rounded px-3 py-2 text-sm">⚙️ Apply (Reload only)</button>
    </form>
  </section>

  <section class="grid md:grid-cols-[320px_1fr] gap-3">
    <div class="bg-white p-3 rounded-xl ring-1 ring-slate-200">
      <h3 class="font-semibold mb-2 text-sm">Add / Update User</h3>
      <form method=post action="/save" class="space-y-2">
        <input name=username placeholder="👤 Username" class="w-full border rounded-lg p-2 text-sm">
        <input name=password placeholder="🔒 Password" class="w-full border rounded-lg p-2 text-sm">
        <label class="text-[11px] text-slate-600">Expires</label>
        <input type=date name=expires value="{{default_exp}}" class="w-full border rounded-lg p-2 text-sm">
        <button class="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded-lg text-sm">💾 Save & Sync</button>
      </form>
      <p class="text-[11px] text-slate-500 mt-3">Save = write-only, Apply = reload (no restart).</p>
    </div>
    <div class="bg-white p-3 rounded-xl ring-1 ring-slate-200 overflow-x-auto">
      <table class="w-full text-left text-sm">
        <thead><tr class="text-slate-600 border-b">
          <th class="py-2 px-2">User</th><th class="py-2 px-2">Password</th><th class="py-2 px-2">Expires</th><th class="py-2 px-2">Status</th><th class="py-2 px-2">Actions</th>
        </tr></thead>
        <tbody>
        {% for r in rows %}
          <tr class="border-b">
            <td class="py-2 px-2">{{r['username']}}</td>
            <td class="py-2 px-2"><code class="bg-slate-100 px-2 py-1 rounded">{{r['password']}}</code>
              {% if r['days_left'] is not none %}
                {% if r['days_left'] >= 0 %}
                  <span class="ml-1 text-emerald-600 text-xs">{{r['days_left']}} days left</span>
                {% else %}
                  <span class="ml-1 text-rose-600 text-xs">Expired {{-r['days_left']}}d</span>
                {% endif %}
              {% endif %}
            </td>
            <td class="py-2 px-2">{{r['expires']}}</td>
            <td class="py-2 px-2">{% if not r['expired'] %}<span class="text-emerald-600">Online</span>{% else %}<span class="text-slate-500">Offline</span>{% endif %}</td>
            <td class="py-2 px-2">
              <form method=post action="/del/{{r['id']}}" onsubmit="return confirm('Delete {{r['username']}}?')" class="inline">
                <button class="bg-rose-600 hover:bg-rose-500 text-white px-2 py-1 rounded text-xs">🗑️</button>
              </form>
            </td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </section>
</main>
</body></html>''',
        rows=rows, total_users=total_users, total_online=total_online, total_offline=total_offline,
        default_exp=default_exp, vps_ip=vps_ip, server_ts=server_ts)

# ---------- Save (no reload) ----------
@app.route("/save",methods=["POST"])
@login_required
def save():
    u=request.form["username"].strip()
    p=request.form["password"].strip()
    e=request.form["expires"].strip()
    if not u or not p or not e:
        flash("Please fill all fields"); return redirect("/")
    with db() as con:
        con.execute("""INSERT INTO users(username,password,expires)
                       VALUES(?,?,?)
                       ON CONFLICT(username) DO UPDATE SET password=?, expires=?""",(u,p,e,p,e))
    try:
        ip=subprocess.check_output(["hostname","-I"]).decode().split()[0]
    except Exception:
        ip=request.host.split(":")[0]
    msg=f"IP : {ip}\nUsers : {u}\nPassword : {p}\nExpired Date : {e}\n1 User For 1 Device"
    flash(msg, "ok")
    sync();return redirect("/")

# ---------- Apply (reload only) ----------
@app.route("/apply", methods=["POST"])
@login_required
def apply():
    try:
        rc = subprocess.call(["systemctl","reload",ZIVPN_SVC], stdout=DEVNULL, stderr=DEVNULL)
        if rc != 0:
            subprocess.check_call(["pkill","-HUP","-f","zivpn server"], stdout=DEVNULL, stderr=DEVNULL)
        flash("✅ Config reloaded (no restart) – existing connections preserved", "ok")
    except Exception as e:
        flash(f"❌ Reload failed: {str(e)}", "err")
    return redirect("/")

@app.route("/del/<int:uid>",methods=["POST"])
@login_required
def delete(uid):
    with db() as con:
        con.execute("DELETE FROM users WHERE id=?",(uid,))
    sync();return redirect("/")

# ---------- Admin Settings (UI) ----------
@app.route("/settings", methods=["GET","POST"])
@login_required
def settings_page():
    if request.method=="POST":
        new_u = request.form.get("user","").strip()
        new_p = request.form.get("pass","").strip()
        if not new_u:
            flash("Username cannot be empty"); return redirect("/settings")
        set_admin(new_u, new_p if new_p else None)
        flash("✅ Admin credentials updated (effective immediately). Please login again.")
        session.clear(); return redirect("/login")
    u,_ = get_admin()
    return render_template_string('''<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-slate-50">
<div class="max-w-md mx-auto mt-10 bg-white rounded-xl p-6 ring-1 ring-slate-200">
  <h2 class="text-xl font-semibold mb-4">Admin Settings</h2>
  <form method="post" class="space-y-3">
    <div><label class="text-sm text-slate-600">New Admin Username</label>
      <input name="user" value="{{u}}" class="w-full border rounded-lg p-2 focus:ring-2 focus:ring-emerald-500"/></div>
    <div><label class="text-sm text-slate-600">New Password (leave blank to keep)</label>
      <input name="pass" type="password" placeholder="••••••••" class="w-full border rounded-lg p-2 focus:ring-2 focus:ring-emerald-500"/></div>
    <div class="flex gap-2">
      <a href="/" class="px-3 py-2 rounded bg-slate-200">Back</a>
      <button class="flex-1 bg-emerald-600 hover:bg-emerald-500 text-white py-2 rounded">Save</button>
    </div>
  </form>
</div>
</body></html>''', u=u)

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

if __name__=="__main__":
    from waitress import serve
    serve(app,host=os.getenv("BIND_HOST","0.0.0.0"),port=int(os.getenv("BIND_PORT","8088")))
PY

# --- Auto Sync Script (write-only; no reload) ---
cat > "${SYNC_PY}" <<'PY'
import os, json, sqlite3, tempfile
DB="/var/lib/zivpn-admin/zivpn.db"
CFG="/etc/zivpn/config.json"
def actives():
    with sqlite3.connect(DB) as con:
        pw=[r[0] for r in con.execute("SELECT DISTINCT password FROM users WHERE DATE(expires)>=DATE('now')")]
    return pw or ["zi"]
def write_cfg(passwords):
    cfg={}
    try:
        cfg=json.load(open(CFG))
    except Exception:
        pass
    cfg.setdefault("auth",{})["mode"]="passwords"
    cfg["auth"]["config"]=passwords
    cfg["config"]=passwords
    with tempfile.NamedTemporaryFile("w",delete=False) as f:
        json.dump(cfg,f,indent=2); tmp=f.name
    os.replace(tmp,CFG)
if __name__=="__main__":
    write_cfg(actives())
PY

chmod +x "${APP_PY}" "${SYNC_PY}"

# --- Panel service & timer ---
cat >/etc/systemd/system/${PANEL_SVC} <<EOF
[Unit]
Description=ZIVPN Web Panel
After=network.target
[Service]
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${ADMIN_DIR}
ExecStart=${VENV}/bin/python ${APP_PY}
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/${SYNC_SVC} <<EOF
[Unit]
Description=ZIVPN Daily Sync
[Service]
ExecStart=${VENV}/bin/python ${SYNC_PY}
EOF

cat >/etc/systemd/system/${SYNC_TIMER} <<'EOF'
[Unit]
Description=Run ZIVPN daily sync
[Timer]
OnCalendar=*-*-* 00:10:00
Persistent=true
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now ${PANEL_SVC}
systemctl enable --now ${SYNC_TIMER}
systemctl restart ${NAT_SVC}

# --- OPTIONAL: server-side UDP keepalive ---
cat >/usr/local/sbin/zivpn-udp-keepalive.sh <<'SH'
#!/usr/bin/env bash
set -euo pipefail
PORT=5667
command -v conntrack >/dev/null 2>&1 || exit 0
conntrack -L -p udp 2>/dev/null | awk -v p="dport=${PORT}" '$0 ~ p {print}' | \
  sed -n 's/.*src=\([0-9\.]\+\).*sport=\([0-9]\+\).*/\1 \2/p' | \
  while read SRC SPORT; do printf '.' >/dev/udp/${SRC}/${SPORT} || true; done
SH
chmod +x /usr/local/sbin/zivpn-udp-keepalive.sh
echo '* * * * * root /usr/local/sbin/zivpn-udp-keepalive.sh >/dev/null 2>&1' > /etc/cron.d/zivpn-keepalive
systemctl restart cron

# --- ZIVPN Admin Menu (CLI) ---
cat >/usr/local/sbin/zivpn-menu <<'SH'
#!/usr/bin/env bash
set -euo pipefail
DB="/var/lib/zivpn-admin/zivpn.db"
VENV="/opt/zivpn-admin/venv"
PY="${VENV}/bin/python"
[ -x "${PY}" ] || PY="$(command -v python3)"

hash_pass() {
  "${PY}" - "$1" <<'PY'
import sys
from werkzeug.security import generate_password_hash
print(generate_password_hash(sys.argv[1]))
PY
}

chg_admin() {
  [ -f "$DB" ] || { echo "DB not found at $DB"; exit 1; }
  read -rp "New admin username: " NU
  [ -z "${NU}" ] && { echo "Username cannot be empty"; return; }
  read -rsp "New admin password (leave blank = keep): " NP; echo
  if [ -n "${NP}" ]; then
    HP="$(hash_pass "${NP}")"
    sqlite3 "$DB" "UPDATE settings SET v='${NU}' WHERE k='admin_user'; \
                   UPDATE settings SET v='${HP}' WHERE k='admin_pass_hash';"
    echo "✔ Admin user & password updated. (effective immediately)"
  else
    sqlite3 "$DB" "UPDATE settings SET v='${NU}' WHERE k='admin_user';"
    echo "✔ Admin username updated. (password unchanged)"
  fi
}

add_user() {
  [ -f "$DB" ] || { echo "DB not found at $DB"; exit 1; }
  read -rp "Username: " U
  read -rp "Password: " P
  read -rp "Expires (YYYY-MM-DD): " E
  [ -z "$U" ] || [ -z "$P" ] || [ -z "$E" ] && { echo "All fields required"; return; }
  sqlite3 "$DB" "INSERT INTO users(username,password,expires) VALUES('${U}','${P}','${E}')
                 ON CONFLICT(username) DO UPDATE SET password='${P}', expires='${E}';"
  "${PY}" /opt/zivpn-admin/sync.py
  echo "✔ Saved. Use 'Apply' (option 5) if you need immediate reload."
}

list_users() {
  sqlite3 -header -column "$DB" "SELECT id,username,password,expires FROM users ORDER BY username;"
}

apply_reload() {
  if systemctl reload zivpn.service 2>/dev/null; then
    echo "✔ Config reloaded via systemctl (HUP)"
  else
    pkill -HUP -f "zivpn server" && echo "✔ Config reloaded via pkill (HUP)"
  fi
}

panel_url() {
  IP=$(hostname -I | awk '{print $1}')
  echo "Panel: http://${IP}:8088/login"
}

while true; do
  clear
  echo "==============================="
  echo " ZIVPN ADMIN MENU (no-restart)"
  echo "==============================="
  echo "1) Show panel URL"
  echo "2) Change Admin username/password"
  echo "3) Add/Update VPN user (no-restart)"
  echo "4) List VPN users"
  echo "5) Apply (reload only, keep sessions)"
  echo "6) Exit"
  read -rp "Select: " CH
  case "$CH" in
    1) panel_url; read -rp "Enter to continue..." _ ;;
    2) chg_admin; read -rp "Enter to continue..." _ ;;
    3) add_user; read -rp "Enter to continue..." _ ;;
    4) list_users; read -rp "Enter to continue..." _ ;;
    5) apply_reload; read -rp "Enter to continue..." _ ;;
    6) exit 0 ;;
    *) echo "Invalid"; sleep 1 ;;
  esac
done
SH
chmod +x /usr/local/sbin/zivpn-menu
ln -sf /usr/local/sbin/zivpn-menu /usr/local/bin/zivpn-menu

IP=$(hostname -I | awk '{print $1}')
echo
echo "✅ INSTALL COMPLETE"
echo "======================================"
echo "📊 Web Panel: http://${IP}:8088/login"
echo "👤 Admin Username (initial): ${ADMIN_USER}"
echo "🔑 Admin Password (initial): ${ADMIN_PASSWORD}"
echo "🛠  CLI Menu: sudo zivpn-menu"
echo "======================================"
echo "Credit : Zivpn Owner"
echo "Rebuild By : Jue Htet"
echo "======================================"
BASH

chmod +x zi.sh
sudo ./zi.sh
