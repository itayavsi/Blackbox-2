 return make_response(jsonify({"message": "Level 1 solved!"}), 200)import os
import random
import string
import logging
from flask import Flask, jsonify, make_response, request
import subprocess


app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

# Flags for different levels
FLAG_0 = "42"
FLAG_1 = "FileSystemMasterKey2024!"

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
    
    # Check if environment variable is correctly set
    lock_status = get_env_var()
    print("Current LockAdministrator:", get_env_var("LockAdministrator"))

    
    # Setup the flag location
    base_path = os.path.join(os.path.expanduser(r"C:\Program Files"), "CTF_Challenge")
    flag_location = os.path.join(base_path, "Users", "Administrator", "secret_logs", "system_log.txt")
    
    if lock_status == '0': 
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(flag_location), exist_ok=True)
            with open(flag_location, 'w') as f:
                f.write("FLAG_1")                           
            if answer == FLAG_1:
                return make_response(jsonify({"message": "Level 1 solved!"}), 200)
            else:
                return make_response(jsonify({"message": "Unlock Administrator directory! Flag revealed!"}), 200)
        except Exception as e:
            logging.error(f"Error writing flag file: {e}")
            return make_response(jsonify({"message": "Error accessing file system."}), 500)
    
    return make_response(jsonify({"message": "Incorrect answer or Administrator directory still locked."}), 400)

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
    with open(flag_location, 'w') as f:
        f.write("Access denied: LockAdministrator set to '1'")

    return base_path

@app.route('/get-level1', methods=["GET"])
def get_level1():
    base_path = setup_level1_filesystem()
    return jsonify({
        "challenge": "Unlock the Administrator directory by changing the LockAdministrator environment variable",
        "base_directory": base_path,
        "environment_variable": "LockAdministrator"
    })

    data = request.get_json()
    answer = data.get("answer")
    
    # Check if environment variable is correctly set
    lock_status = os.environ.get('LockAdministrator')
    
    # Setup the flag location
    base_path = os.path.join(os.path.expanduser(r"C:\Program Files"), "CTF_Challenge")
    flag_location = os.path.join(base_path, "Users", "Administrator", "secret_logs", "system_log.txt")
    
    if lock_status == '0':
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(flag_location), exist_ok=True)
            
            # Write the flag to the file when lock is removed
            with open(flag_location, 'w') as f:
                f.write(FLAG_1)
            
            if answer == FLAG_1:
                return make_response(jsonify({"message": "Level 1 solved!"}), 200)
            else:
                return make_response(jsonify({"message": "Unlock Administrator directory! Flag revealed!"}), 200)
        except Exception as e:
            logging.error(f"Error writing flag file: {e}")
            return make_response(jsonify({"message": "Error accessing file system."}), 500)
    
    return make_response(jsonify({"message": "Incorrect answer or Administrator directory still locked."}), 400)


def get_env_var():
    """Fetch updated environment variable value."""
    result = subprocess.run(['cmd.exe', '/c', f'echo %LockAdministrator%'], capture_output=True, text=True)
    return result.stdout.strip()


if __name__ == "__main__":
    # Set initial lock status
    logging.basicConfig(level=logging.INFO)
    print(f"LockAdministrator: {os.environ.get('LockAdministrator')}")
    app.run(debug=True, port=5000)
