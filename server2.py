import os
import random
import string
import logging
import winreg as reg
from flask import Flask, jsonify, make_response, request, session
import json
import hashlib
import base64
import subprocess
import sys
import socket
import threading
import time


app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

# Flags for different levels
FLAG_0 = "42"
FLAG_1 = "FileSystemMasterKey2024!"
FLAG_2 = "AccessLevelUnlocked2024!"
FLAG_3 = "AdminPrivilegeEscalation2024!"
FLAG_4 = "ProcessSandboxEscape2024!"
FLAG_5 = "EncryptedLogAccess2024!"

AcssesCounter = 0
challenge_process = None
socket_server_running = False
socket_server_thread = None

@app.before_request
def initialize():
    setup_level1_registry()
    setup_level2_registry()


def setup_level5_encrypted_log():
    """Create an encrypted log file using XOR encryption."""
    key_path = r"SOFTWARE\CTF_Simulation"
    xor_key = os.urandom(16)  # Generate a random XOR key
    reg_key = reg.CreateKey(reg.HKEY_CURRENT_USER, key_path)
    reg.SetValueEx(reg_key, "XOR_Key", 0, reg.REG_BINARY, xor_key)
    reg.CloseKey(reg_key)

    log_path = r"C:\ProgramData\CTF_Challenge\logs\security_log.enc"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    # Example log content
    log_content = FLAG_5
    encrypted_content = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(log_content.encode())])

    with open(log_path, 'wb') as f:
        f.write(encrypted_content)

    return log_path

def setup_level1_registry():
    key_path = r"SOFTWARE\CTF_Simulation"
    try:
        ctf_key = reg.CreateKey(reg.HKEY_CURRENT_USER, key_path)
        reg.SetValueEx(ctf_key, "LockAdministrator", 0, reg.REG_SZ, "1")
        reg.CloseKey(ctf_key)
    except PermissionError:
        print("Error: Registry setup failed! Ensure admin privileges.")
    except Exception as e:
        print(f"Registry setup error: {e}")

def setup_level2_registry():
    key_path = r"SOFTWARE\CTF_Simulation"
    try:
        ctf_key = reg.CreateKey(reg.HKEY_CURRENT_USER, key_path)
        reg.SetValueEx(ctf_key, "UserAccessLevel", 0, reg.REG_SZ, "8")
        reg.CloseKey(ctf_key)
    except Exception as e:
        print(f"Stage 2 Registry error: {e}")

def get_registry_value(key_path, value_name):
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_READ)
        value, _ = reg.QueryValueEx(key, value_name)
        reg.CloseKey(key)
        return str(value)
    except FileNotFoundError:
        setup_level1_registry()
        return '1'
    except Exception as e:
        logging.error(f"Registry read error: {e}")
        return '1'
    
def caesar_encrypt(text, shift=12):
    encrypted = []
    for char in text:
        if char.isalpha():
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            else:
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted.append(chr(shifted))
        else:
            encrypted.append(char)
    return ''.join(encrypted)

# ========== LEVEL 0-1 ENDPOINTS (UNTOUCHED) ==========
@app.route('/get-level0', methods=["GET"])
def get_level0():
    return jsonify({"binary": "101010"})

@app.route('/solve-level0', methods=["POST"])
def solve_level0():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_0:
        return make_response(jsonify({"message": "Level 0 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect answer. Try again."}), 400)

@app.route('/solve-level1', methods=["POST"])
def solve_level1():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_1:
        return make_response(jsonify({"message": "Level 1 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect answer. Try again."}), 400)

def setup_level1_filesystem():
    base_path = os.path.join(os.path.expanduser(r"C:\Program Files"), "CTF_Challenge")
    os.makedirs(base_path, exist_ok=True)

    hidden_dirs = [
        os.path.join(base_path, "System", "hidden_config"),
        os.path.join(base_path, "Users", "Administrator", "secret_logs"),
        os.path.join(base_path, ".system_data"),
    ]

    for dir_path in hidden_dirs:
        os.makedirs(dir_path, exist_ok=True)
        if os.name == 'nt':
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(dir_path, 0x02)
            except Exception as e:
                logging.error(f"Directory hide error: {e}")

    flag_location = os.path.join(base_path, "Users", "Administrator", "secret_logs", "system_log.txt")
    WriteAcsses(flag_location, base_path)
    return base_path

def WriteAcsses(flag_location, base_path):
    global AcssesCounter
    if AcssesCounter == 0:
        with open(flag_location, 'w') as f:
            f.write("Access denied: LockAdministrator set to '1'")
        AcssesCounter += 1

@app.route('/get-level1', methods=["GET"])
def get_level1():
    base_path = setup_level1_filesystem()
    return jsonify({
        "challenge": "Unlock the Administrator directory by changing the LockAdministrator registry value",
        "base_directory": base_path,
        "registry_key": r"HKEY_CURRENT_USER\SOFTWARE\CTF_Simulation",
        "value_name": "LockAdministrator"
    })

# ========== LEVEL 2-3 ENDPOINTS ==========

def ensure_admin_exists():
    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    user_db_path = os.path.join(documents_path, "user_db.json")
    default_admin_hash = hashlib.sha256("admin123".encode()).hexdigest()

    # Check if the user database exists
    if not os.path.exists(user_db_path):
        user_db = {"users": []}
    else:
        with open(user_db_path, 'r') as f:
            user_db = json.load(f)
    
    # Check if Admin user exists
    if not any(user['username'] == "Admin" for user in user_db['users']):
        admin_user = {
            "username": "Admin",
            "password_hash": default_admin_hash,
            "access_level": 15,
            "permissions": ["full"]
        }
        user_db['users'].append(admin_user)
        
        with open(user_db_path, 'w') as f:
            json.dump(user_db, f, indent=4)
        print("Admin user added.")
    else:
        print("Admin user already exists.")


@app.route('/get-level2', methods=["GET"])
def get_level2():
    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    os.makedirs(documents_path, exist_ok=True)
    
    user_db_path = os.path.join(documents_path, "user_db.json")
    default_admin_hash = hashlib.sha256("admin123".encode()).hexdigest()

    ensure_admin_exists()
    
    if not os.path.exists(user_db_path):
        user_db = {
            "users": [{
                "username": "Admin",
                "password_hash": default_admin_hash,
                "access_level": 15,
                "permissions": ["full"]
            }]
        }
        with open(user_db_path, 'w') as f:
            json.dump(user_db, f, indent=4)

    return jsonify({
        "challenge": "Modify your access level to 15 in user_db.json after authentication",
        "file_path": user_db_path,
        "target_access_level": 15,
        "hint": "Sign up, log in, then edit your access_level"
    })

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    hashed_pw = hashlib.sha256(password.encode()).hexdigest()
    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    user_db_path = os.path.join(documents_path, "user_db.json")
    
    user_db = {"users": []}
    if os.path.exists(user_db_path):
        with open(user_db_path, 'r') as f:
            user_db = json.load(f)

    if any(u['username'] == username for u in user_db['users']):
        return jsonify({"message": "Username exists"}), 400

    user_db['users'].append({
        "username": username,
        "password_hash": hashed_pw,
        "access_level": 8,
        "permissions": []
    })

    with open(user_db_path, 'w') as f:
        json.dump(user_db, f, indent=4)

    return jsonify({"message": "Signup successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    hashed_pw = hashlib.sha256(password.encode()).hexdigest()

    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    user_db_path = os.path.join(documents_path, "user_db.json")
    
    if not os.path.exists(user_db_path):
        return jsonify({"message": "User not found"}), 404

    with open(user_db_path, 'r') as f:
        user_db = json.load(f)

    user = next((u for u in user_db['users'] if u['username'] == username and u['password_hash'] == hashed_pw), None)
    if user:
        session['username'] = username
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({"message": "Logged out"}), 200

@app.route('/check-admin-status', methods=['GET'])
def check_admin_status():
    if 'username' not in session:
        return jsonify({"is_admin": False})
    
    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    user_db_path = os.path.join(documents_path, "user_db.json")
    
    with open(user_db_path, 'r') as f:
        user_db = json.load(f)
    
    user = next((u for u in user_db['users'] if u['username'] == session['username']), None)
    return jsonify({
        "is_admin": user and user['username'] == "Admin",
        "status": "Admin" if user and user['username'] == "Admin" else "Regular User"
    })

@app.route('/solve-level2', methods=["POST"])
def solve_level2():
    if 'username' not in session:
        return jsonify({"message": "Authentication required"}), 401

    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    user_db_path = os.path.join(documents_path, "user_db.json")
    
    with open(user_db_path, 'r') as f:
        user_db = json.load(f)

    user = next((u for u in user_db['users'] if u['username'] == session['username']), None)
    if not user:
        return jsonify({"message": "User not found"}), 404

    if user['access_level'] == 15:
        return jsonify({"message": "Level 2 solved!", "flag": FLAG_2}), 200
    return jsonify({"message": "Access level insufficient"}), 400

@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    data = request.get_json()
    text = data.get('text', '')
    encrypted_text = caesar_encrypt(text)
    return jsonify({"encrypted_text": encrypted_text})

@app.route('/get-encrypted-flag', methods=['GET'])
def get_encrypted_flag():
    encrypted_flag = caesar_encrypt(FLAG_3)
    return jsonify({"encrypted_flag": encrypted_flag})

@app.route('/solve-level3', methods=['POST'])
def solve_level3():
    data = request.get_json()
    answer = data.get('answer', '').strip()
    if answer == FLAG_3:
        return jsonify({"message": f"Level 3 solved!"}), 200
    else:
        return jsonify({"message": "Incorrect answer."}), 400
    
# ========== LEVEL 4 ENDPOINTS (MODIFIED) ==========
               

def get_challenge_info():
    """
    Mimics your /get-level4 endpoint: if a challenge process is already running, returns its info;
    otherwise, starts a new process and returns its details.
    """
    global challenge_process
    if challenge_process and challenge_process.poll() is None:
        info = {
            "challenge": "Process Sandbox Escape Challenge",
            "instructions": "Find and terminate the Python process that was launched",
            "process_name": "python.exe (running challenge_script.py)",
            "process_id": challenge_process.pid,
            "hint": "Use Task Manager or taskkill to terminate the process with the given PID"
        }
    else:
        try:
            script_path = os.path.join(os.path.expanduser("~"), "Documents", "challenge_script.py")
            with open(script_path, 'w') as f:
                f.write("import time\n")
                f.write("import os\n")
                f.write("print('CTF Challenge Process Running - PID:', os.getpid())\n")
                f.write("print('This process must be terminated to complete Level 4')\n")
                f.write("time.sleep(3600)  # Sleep for 1 hour\n")

            # Start the challenge process
            challenge_process = subprocess.Popen([sys.executable, script_path],
                                                 stdout=subprocess.DEVNULL,
                                                 stderr=subprocess.DEVNULL,
                                                 creationflags=subprocess.CREATE_NO_WINDOW)
            info = {
                "challenge": "Process Sandbox Escape Challenge",
                "instructions": "Find and terminate the Python process that was just launched",
                "process_name": "python.exe (running challenge_script.py)",
                "process_id": challenge_process.pid,
                "hint": "Use Task Manager or taskkill to terminate the process with the given PID"
            }
        except Exception as e:
            info = {
                "error": str(e),
                "message": "Failed to start challenge process"
            }
    return info

def check_process_status():
    """
    Mimics the /check-process-status endpoint.
    """
    global challenge_process
    if not challenge_process:
        return {"status": "No process launched", "message": "Start the challenge first using option 1."}
    try:
        if challenge_process.poll() is None:
            return {
                "status": "running",
                "process_id": challenge_process.pid,
                "message": "Process is still running. Terminate it to proceed to Part 2."
            }
        else:
            return {
                "status": "terminated",
                "message": "Process successfully terminated! You may now request Part 2."
            }
    except Exception:
        return {
            "status": "terminated",
            "message": "Process is terminated or inaccessible. You may now request Part 2."
        }

def get_level4_part2():
    """
    Mimics the /get-level4-part2 endpoint: returns the base64 encoded flag challenge.
    """
    encoded_flag = base64.b64encode(FLAG_4.encode()).decode()
    return {
        "challenge": "Decode the base64-encoded flag",
        "encoded_flag": encoded_flag,
        "hint": "Use a base64 decoder to reveal the flag"
    }

def interactive_level4_session(conn):
    """
    Provides an interactive menu for Level 4 over the socket.
    """
    welcome = (
        "Welcome to Level 4 Challenge (Process Sandbox Escape) via Socket!\n"
        "Select an option by typing the corresponding number and pressing Enter:\n"
        "1. Get Challenge Info (Start challenge process if needed)\n"
        "2. Check Process Status\n"
        "3. Get Part 2 Challenge (if process terminated)\n"
        "4. Exit\n"
    )
    conn.sendall(welcome.encode())

    while True:
        try:
            data = conn.recv(1024).decode().strip()
            if not data:
                break  # connection closed

            if data == "1":
                info = get_challenge_info()
                response = json.dumps(info, indent=2) + "\n"
                conn.sendall(response.encode())

            elif data == "2":
                status = check_process_status()
                response = json.dumps(status, indent=2) + "\n"
                conn.sendall(response.encode())

            elif data == "3":
                # Only allow Part 2 if the process is terminated.
                status = check_process_status()
                if status.get("status") == "terminated":
                    part2 = get_level4_part2()
                    response = json.dumps(part2, indent=2) + "\n"
                else:
                    response = json.dumps({
                        "message": "Challenge process is still running. Please terminate it before requesting Part 2."
                    }, indent=2) + "\n"
                conn.sendall(response.encode())

            elif data == "4":
                goodbye = "Exiting Level 4 session. Goodbye!\n"
                conn.sendall(goodbye.encode())
                break

            else:
                msg = "Invalid option. Please select 1, 2, 3, or 4.\n"
                conn.sendall(msg.encode())

            # Re-send the menu prompt after each action
            conn.sendall(welcome.encode())
        except Exception as e:
            error_msg = f"Error: {e}\n"
            conn.sendall(error_msg.encode())
            break

    conn.close()

def level4_socket_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 6000))
    server_socket.listen(5)
    print("Interactive Level 4 socket server listening on port 6000...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected to {addr}")
        threading.Thread(target=interactive_level4_session, args=(conn,), daemon=True).start()

def start_level4_socket_server():
    socket_thread = threading.Thread(target=level4_socket_server, daemon=True)
    socket_thread.start()

@app.route('/get-level5', methods=["GET"])
def get_level5():
    """Retrieve challenge for Stage 5"""
    log_path = setup_level5_encrypted_log()
    return jsonify({
        "challenge": "Decrypt the security log file to access the flag.",
        "file_path": log_path,
        "hint": "Use the XOR key stored in the registry to decrypt the log."
    })

@app.route('/solve-level5', methods=["POST"])
def solve_level5():
    """Validate Stage 5 solution"""
    data = request.get_json()
    decrypted_log = data.get("decrypted_log")

    if decrypted_log == FLAG_5:
        return make_response(jsonify({"message": "Level 5 solved!"}), 200)

    return make_response(jsonify({"message": "Incorrect log content."}), 400)

if __name__ == "__main__":
    # Start the interactive socket server alongside your Flask app (if needed)
    start_level4_socket_server()
    app.run(debug=True, port=5000)
    while True:
        time.sleep(1)

