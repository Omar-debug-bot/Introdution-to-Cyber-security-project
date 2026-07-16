from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from crypto import aes_encrypt, aes_decrypt, hash_password
from datetime import datetime
import os, secrets

app = Flask(__name__, static_folder='.')
app.config['SECRET_KEY'] = secrets.token_hex(32)
socketio = SocketIO(app, cors_allowed_origins="*")

# ─── In-memory storage ────────────────────────────────────────────────────────
users = {}        # username -> {password_hash, salt}
messages = {}     # room_id -> [encrypted message dicts]
online_users = {} # sid -> username


def room_id(*members):
    """Deterministic room ID for any number of members."""
    return "_".join(sorted(set(m.lower() for m in members)))


def auth(token):
    """Decode token → username, raises on failure."""
    return aes_decrypt(token).split(':')[0]


# ─── REST routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/api/register', methods=['POST'])
def register():
    d = request.json
    username = d.get('username', '').strip().lower()
    password = d.get('password', '')
    if not username or not password:
        return jsonify(ok=False, msg='Username and password required'), 400
    if len(username) < 3:
        return jsonify(ok=False, msg='Username must be at least 3 chars'), 400
    if username in users:
        return jsonify(ok=False, msg='Username already taken'), 409
    salt = os.urandom(16)
    users[username] = {'password_hash': hash_password(password, salt), 'salt': salt.hex()}
    return jsonify(ok=True, msg='Account created!')


@app.route('/api/login', methods=['POST'])
def login():
    d = request.json
    username = d.get('username', '').strip().lower()
    password = d.get('password', '')
    if username not in users:
        return jsonify(ok=False, msg='User not found'), 401
    u = users[username]
    if hash_password(password, bytes.fromhex(u['salt'])) != u['password_hash']:
        return jsonify(ok=False, msg='Wrong password'), 401
    token = aes_encrypt(f"{username}:{secrets.token_hex(16)}")
    return jsonify(ok=True, token=token, username=username)


@app.route('/api/users', methods=['GET'])
def list_users():
    try:
        me = auth(request.headers.get('X-Token', ''))
    except Exception:
        return jsonify(ok=False, msg='Unauthorized'), 401
    return jsonify(ok=True, users=[u for u in users if u != me])


@app.route('/api/check_users', methods=['POST'])
def check_users():
    """Validate that a list of usernames all exist."""
    try:
        auth(request.headers.get('X-Token', ''))
    except Exception:
        return jsonify(ok=False, msg='Unauthorized'), 401
    names = request.json.get('usernames', [])
    missing = [n for n in names if n not in users]
    if missing:
        return jsonify(ok=False, missing=missing,
                       msg=f"User(s) not found: {', '.join(missing)}")
    return jsonify(ok=True)


@app.route('/api/history', methods=['GET'])
def get_history():
    try:
        me = auth(request.headers.get('X-Token', ''))
    except Exception:
        return jsonify(ok=False, msg='Unauthorized'), 401
    members_raw = request.args.get('with', '')
    members = [m.strip().lower() for m in members_raw.split(',') if m.strip()]
    if not members:
        return jsonify(ok=False, msg='No members specified'), 400
    rid = room_id(me, *members)
    history = []
    for m in messages.get(rid, []):
        try:
            plain = aes_decrypt(m['cipher'])
        except Exception:
            plain = '[decryption error]'
        history.append({'from': m['from'], 'text': plain, 'time': m['time']})
    return jsonify(ok=True, history=history)


# ─── WebSocket events ─────────────────────────────────────────────────────────

@socketio.on('join')
def on_join(data):
    try:
        username = auth(data.get('token', ''))
    except Exception:
        return
    online_users[request.sid] = username
    join_room(username)
    emit('status', {'msg': f'Connected as {username}'})
    socketio.emit('online', {'users': list(online_users.values())})


@socketio.on('send_message')
def on_message(data):
    try:
        sender = auth(data.get('token', ''))
    except Exception:
        return
    recipients = [r.lower() for r in data.get('to', [])]  # list of usernames
    text = data.get('text', '').strip()

    # Validate recipients
    missing = [r for r in recipients if r not in users]
    if missing or not text:
        emit('error', {'msg': f"User(s) not found: {', '.join(missing)}"})
        return

    all_members = list(set([sender] + recipients))
    rid = room_id(*all_members)
    if rid not in messages:
        messages[rid] = []

    ts = datetime.now().strftime('%H:%M')
    messages[rid].append({'from': sender, 'cipher': aes_encrypt(text), 'time': ts})

    payload = {'from': sender, 'text': text, 'time': ts,
               'room': rid, 'members': all_members}
    for member in all_members:
        socketio.emit('new_message', payload, to=member)


@socketio.on('disconnect')
def on_disconnect():
    username = online_users.pop(request.sid, None)
    if username:
        socketio.emit('online', {'users': list(online_users.values())})


if __name__ == '__main__':
    print("🎙️  Woki Toki Server on http://localhost:5000")
    socketio.run(app, debug=True, port=5000)
