import os
import random
import string
import logging
import winreg as reg
from flask import Flask, jsonify, make_response, request, session
import json
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

# Flags for different levels
FLAG_0 = "42"
FLAG_1 = "FileSystemMasterKey2024!"
FLAG_2 = "AccessLevelUnlocked2024!"
FLAG_3 = "AdminPrivilegeEscalation2024!"

AcssesCounter = 0

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

# Original Level 0-1 Endpoints (Unchanged)
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

# New Level 2-3 Endpoints
@app.route('/get-level2', methods=["GET"])
def get_level2():
    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    os.makedirs(documents_path, exist_ok=True)
    
    user_db_path = os.path.join(documents_path, "user_db.json")
    default_admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
    
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

@app.route('/get-level3', methods=["GET"])
def get_level3():
    return jsonify({
        "challenge": "Change the Admin user's password in the database",
        "requirements": [
            "1. Locate the Admin user in user_db.json",
            "2. Generate SHA-256 hash of a new password",
            "3. Replace existing password_hash with new hash"
        ],
        "hint": "Default Admin password is 'admin123'"
    })

@app.route('/solve-level3', methods=["POST"])
def solve_level3():
    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    user_db_path = os.path.join(documents_path, "user_db.json")
    
    try:
        with open(user_db_path, 'r') as f:
            user_db = json.load(f)
    except FileNotFoundError:
        return jsonify({"message": "User database missing"}), 400

    admin_user = next((u for u in user_db['users'] if u['username'] == "Admin"), None)
    if not admin_user:
        return jsonify({"message": "Admin account missing"}), 400

    default_hash = hashlib.sha256("admin123".encode()).hexdigest()
    if admin_user['password_hash'] != default_hash:
        return jsonify({
            "message": "Level 3 solved!",
            "flag": FLAG_3
        }), 200
    
    return jsonify({"message": "Admin password not modified"}), 400

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True, port=5000)
