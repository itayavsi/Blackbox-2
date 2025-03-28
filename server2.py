import os
import random
import string
import logging
import winreg as reg
from flask import Flask, jsonify, make_response, request
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

# Flags for different levels
FLAG_0 = "42"
FLAG_1 = "FileSystemMasterKey2024!"
FLAG_2 = "AccessLevelUnlocked2024!"  # New flag for Stage 2

AcssesCounter = 0

@app.before_request
def initialize():
    setup_level1_registry()
    setup_level2_registry()


def setup_level1_registry():
    key_path = r"SOFTWARE\CTF_Simulation"
    try:
        # Create or open the key
        ctf_key = reg.CreateKey(reg.HKEY_CURRENT_USER, key_path)
        
        # Set the LockAdministrator value, defaulting to '1' (locked)
        reg.SetValueEx(ctf_key, "LockAdministrator", 0, reg.REG_SZ, "1")
        
        # Close the key
        reg.CloseKey(ctf_key)
    except PermissionError:
        print("Error: Registry setup failed! Ensure the server is running with admin privileges.")
    except Exception as e:
        print(f"Unexpected error during registry setup: {e}")

def setup_level2_registry():
    """Setup registry for Stage 2 level"""
    key_path = r"SOFTWARE\CTF_Simulation"
    try:
        ctf_key = reg.CreateKey(reg.HKEY_CURRENT_USER, key_path)
        # Initialize with low access level
        reg.SetValueEx(ctf_key, "UserAccessLevel", 0, reg.REG_SZ, "8")
        reg.CloseKey(ctf_key)
    except Exception as e:
        print(f"Stage 2 Registry setup error: {e}")


def get_registry_value(key_path, value_name):
    """Retrieve a value from the Windows Registry."""
    try:
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_READ)
        value, _ = reg.QueryValueEx(key, value_name)
        reg.CloseKey(key)
        return str(value)
    except FileNotFoundError:
        # If key doesn't exist, create it and return default value
        setup_level1_registry()
        return '1'
    except Exception as e:
        logging.error(f"Registry read error: {e}")
        return '1'

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
    """
    Create a complex file system environment for Level 1 challenge
    """
    base_path = os.path.join(os.path.expanduser(r"C:\Program Files"), "CTF_Challenge")
    os.makedirs(base_path, exist_ok=True)

    # Create nested directories
    hidden_dirs = [
        os.path.join(base_path, "System", "hidden_config"),
        os.path.join(base_path, "Users", "Administrator", "secret_logs"),
        os.path.join(base_path, ".system_data"),
    ]

    for dir_path in hidden_dirs:
        os.makedirs(dir_path, exist_ok=True)
        
        # Hide directories on Windows
        if os.name == 'nt':
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(dir_path, 0x02)  # FILE_ATTRIBUTE_HIDDEN
            except Exception as e:
                logging.error(f"Could not hide directory {dir_path}: {e}")

    # Create initial flag file in Administrator directory
    flag_location = os.path.join(base_path, "Users", "Administrator", "secret_logs", "system_log.txt")
    WriteAcsses(flag_location,base_path)

    return base_path

def WriteAcsses(flag_location,base_path):
    if AcssesCounter == 0:
        flag_location = os.path.join(base_path, "Users", "Administrator", "secret_logs", "system_log.txt")
        with open(flag_location, 'w') as f:
            f.write("Access denied: LockAdministrator set to '1'")
        AcssesCounter+1
    else:
        return True


@app.route('/get-level1', methods=["GET"])
def get_level1():
    base_path = setup_level1_filesystem()
    return jsonify({
        "challenge": "Unlock the Administrator directory by changing the LockAdministrator registry value",
        "base_directory": base_path,
        "registry_key": r"HKEY_CURRENT_USER\SOFTWARE\CTF_Simulation",
        "value_name": "LockAdministrator"
    })

@app.route('/get-level2', methods=["GET"])
def get_level2():
    """Retrieve challenge for Stage 2"""
    # Ensure Documents directory exists
    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    os.makedirs(documents_path, exist_ok=True)
    
    # Create user database JSON file
    user_db_path = os.path.join(documents_path, "user_db.json")
    
    # Initial user database content
    user_db = {
        "users": [
            {
                "username": "default_user",
                "access_level": 8,
                "permissions": []
            }
        ]
    }
    
    # Write the user database
    with open(user_db_path, 'w') as f:
        json.dump(user_db, f, indent=4)
    
    return jsonify({
        "challenge": "Modify your access level from 8 to 15 in the user_db.json file",
        "file_path": user_db_path,
        "current_access_level": 8,
        "target_access_level": 15,
        "hint": "Edit the 'access_level' in the JSON file to 15"
    })

@app.route('/solve-level2', methods=["POST"])
def solve_level2():
    """Validate Stage 2 solution"""
    data = request.get_json()
    answer = data.get("answer")
    
    # Check user database
    documents_path = os.path.join(os.path.expanduser("~"), "Documents")
    user_db_path = os.path.join(documents_path, "user_db.json")
    
    try:
        # Read the user database
        with open(user_db_path, 'r') as f:
            user_db = json.load(f)
        
        # Check if access level is 15
        current_level = user_db['users'][0]['access_level']
        
        if current_level == 15 and answer == FLAG_2:
            return make_response(jsonify({"message": "Level 2 solved!"}), 200)
    except Exception as e:
        logging.error(f"Error reading user database: {e}")
    
    return make_response(jsonify({"message": "Access level not unlocked or incorrect flag"}), 400)

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Run the Flask app
    app.run(debug=True, port=5000)
