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

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

# Flags for different levels
FLAG_0 = "42"
FLAG_1 = "FileSystemMasterKey2024!"
FLAG_2 = "AccessLevelUnlocked2024!"
FLAG_3 = "AdminPrivilegeEscalation2024!"
FLAG_4 = "ProcessSandboxEscape2024!"

AcssesCounter = 0
challenge_process = None
socket_server_running = False
socket_server_thread = None

@app.before_request
def initialize():
    setup_level1_registry()
    setup_level2_registry()

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
               
@app.route('/get-level4', methods=["GET"])
def get_level4():
    global challenge_process
    
    # Check if a process is already running
    if challenge_process and challenge_process.poll() is None:
        # Process already running, return its info
        return jsonify({
            "challenge": "Process Sandbox Escape Challenge",
            "instructions": "Find and terminate the Python process that was launched",
            "process_name": "python.exe (running challenge_script.py)",
            "process_id": challenge_process.pid,
            "hint": "Use Task Manager or taskkill to terminate the process with the given PID"
        })
    
    # Start a new separate Python process for the challenge
    try:
        # Create a simple Python script that just sleeps
        script_path = os.path.join(os.path.expanduser("~"), "Documents", "challenge_script.py")
        with open(script_path, 'w') as f:
            f.write("import time\n")
            f.write("import os\n")
            f.write("print('CTF Challenge Process Running - PID:', os.getpid())\n")
            f.write("print('This process must be terminated to complete Level 4')\n")
            f.write("time.sleep(3600)  # Sleep for 1 hour\n")
        
        # Start a completely separate Python process
        challenge_process = subprocess.Popen([sys.executable, script_path], 
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
        
        return jsonify({
            "challenge": "Process Sandbox Escape Challenge",
            "instructions": "Find and terminate the Python process that was just launched",
            "process_name": "python.exe (running challenge_script.py)",
            "process_id": challenge_process.pid,
            "hint": "Use Task Manager or taskkill to terminate the process with the given PID"
        })
    except Exception as e:
        return jsonify({
            "error": str(e),
            "message": "Failed to start challenge process"
        }), 500
    
@app.route('/check-process-status', methods=["GET"])
def check_process_status():
    global challenge_process
    
    if not challenge_process:
        return jsonify({"status": "No process launched"}), 404
    
    # Check if process is still running
    try:
        # Poll the process (returns None if still running, or returncode if terminated)
        if challenge_process.poll() is None:
            return jsonify({
                "status": "running",
                "pid": challenge_process.pid,
                "message": "Process is still running. Terminate it to continue."
            })
        else:
            # Process has been terminated by external means (not by us)
            return jsonify({
                "status": "terminated",
                "message": "Process successfully terminated! Proceed to the next part."
            })
    except Exception:
        # Process has been terminated or can't be accessed
        return jsonify({
            "status": "terminated",
            "message": "Process successfully terminated! Proceed to the next part."
        })

@app.route('/get-level4-part2', methods=["GET"])
def get_level4_part2():
    # Encode the flag with base64
    encoded_flag = base64.b64encode(FLAG_4.encode()).decode()
    
    return jsonify({
        "challenge": "Decode the base64-encoded flag",
        "encoded_flag": encoded_flag,
        "hint": "Use a base64 decoder to reveal the flag"
    })

@app.route('/solve-level4', methods=["POST"])
def solve_level4():
    data = request.get_json()
    answer = data.get('answer', '').strip()
    
    if answer == FLAG_4:
        return jsonify({"message": "Level 4 solved! Congratulations!"}), 200
    else:
        return jsonify({"message": "Incorrect answer. Try again."}), 400


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True, port=5000)
