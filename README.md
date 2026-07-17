# Woki Toki 🎙️

A real-time encrypted chat application supporting both direct messages and 
group chats. Messages are encrypted with AES-256 before being stored or 
transmitted, and user passwords are secured with salted PBKDF2 hashing.

## Tech Stack
- Python
- Flask
- Flask-SocketIO (real-time messaging)
- `cryptography` library (AES-256-CBC encryption)
- Vanilla JavaScript, HTML, CSS (frontend)

## Security Features
- **AES-256-CBC encryption** for all message content, both in transit and in 
  server-side history storage
- **PBKDF2-HMAC-SHA256 password hashing** with a unique per-user salt and 
  100,000 iterations
- Session tokens generated with `secrets.token_hex` and encrypted before 
  being sent to the client

## Features
- User registration and login
- Real-time messaging via WebSockets (Socket.IO)
- Direct messages (1-on-1) and group chats — just enter multiple 
  comma-separated usernames to start a group
- Deterministic room IDs so the same group always lands in the same chat
- Encrypted message history, restored on reopening a chat
- Live online/offline status indicators
- Minimal terminal-style UI

## About This Project
This was built as a team project for the Cybersecurity course at AAST 
(Arab Academy for Science, Technology and Maritime Transport). My primary 
contributions were the backend (Flask + SocketIO) and the AES/password 
encryption implementation.

**Team members:** [Omar](https://github.com/Omar-debug-bot), [Seif Yasser](https://github.com/seifyasser264-ship-it)

## How to Run
1. Clone this repo
2. Install dependencies: `pip install flask flask-socketio cryptography`
3. Navigate to the `Code` folder
4. Run: `python app.py`
5. Open your browser at `http://localhost:5000`
