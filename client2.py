import os
import requests
import winreg
import logging
import json
import hashlib
import socket
import base64
import subprocess

BASE_URL = "http://127.0.0.1:5000"

def get_registry_value(key_path, value_name):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return str(value)
    except Exception as e:
        print(f"Registry error: {e}")
        return '1'

def set_registry_value(key_path, value_name, value):
    try:
        key, _ = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, str(value))
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Registry write error: {e}")
        return False

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


# ========== LEVEL 0-1 FUNCTIONS (UNTOUCHED) ==========
def solve_level_0():
    print("\nLevel 0: Binary-to-Decimal Challenge")
    response = requests.get(f"{BASE_URL}/get-level0")
    if response.status_code == 200:
        binary_str = response.json().get("binary")
        print("Binary number:", binary_str)
        ans = input("Enter its decimal value: ").strip()
        post_resp = requests.post(f"{BASE_URL}/solve-level0", json={"answer": ans})
        if post_resp.status_code == 200:
            print(post_resp.json().get("message"))
            print("Level 0 completed.")
            set_registry_value(r"SOFTWARE\CTF_Simulation", "LockAdministrator", '1')
            return solve_level_1()
        else:
            print(post_resp.json().get("message"))
            return solve_level_0()
    else:
        print("Failed to get Level 0 challenge.")
        return solve_level_0()

def solve_level_1():
    print("\nLevel 1: File System Challenge")
    response = requests.get(f"{BASE_URL}/get-level1")
    if response.status_code == 200:
        challenge_info = response.json()
        print("\nChallenge:", challenge_info.get("challenge"))
        print("Registry Key:", challenge_info.get("registry_key"))
        print("Value Name:", challenge_info.get("value_name"))

    key_path = r"SOFTWARE\CTF_Simulation"
    value_name = "LockAdministrator"

    print("\nPress Enter to check current status")
    input()

    current_lock_status = get_registry_value(key_path, value_name)
    print("Current LockAdministrator:", current_lock_status)

    if current_lock_status == '0':
        base_path = os.path.join(os.path.expanduser(r"C:\Program Files"), "CTF_Challenge")
        flag_location = os.path.join(base_path, "Users", "Administrator", "secret_logs", "system_log.txt")
        os.makedirs(os.path.dirname(flag_location), exist_ok=True)
        with open(flag_location, 'w') as f:
            f.write("FileSystemMasterKey2024!")
        ans = input("\nEnter the flag from the system_log.txt: ").strip()
                
        post_resp = requests.post(f"{BASE_URL}/solve-level1", json={"answer": ans})
        if post_resp.status_code == 200:
            print(post_resp.json().get("message"))
            solve_level_2()
        else:
            print(post_resp.json().get("message"))
    else:
        print("Administrator directory is still locked. Change the LockAdministrator registry value to 0.")
        solve_level_1()

# ========== LEVEL 2-3 FUNCTIONS ==========
def solve_level_2():
    print("\n=== LEVEL 2: ACCESS LEVEL CHALLENGE ===")
    with requests.Session() as s:
        while True:
            # Login/Signup menu
            print("\n1. Sign up")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose option: ").strip()

            if choice == '1':
                username = input("Username: ")
                password = input("Password: ")
                resp = s.post(f"{BASE_URL}/signup", json={"username": username, "password": password})
                print(resp.json().get("message"))

            elif choice == '2':
                username = input("Username: ")
                password = input("Password: ")
                resp = s.post(f"{BASE_URL}/login", json={"username": username, "password": password})
                msg = resp.json().get("message")
                print(msg)
                if resp.status_code == 200:
                    handle_logged_in_menu(s)
                    break
            elif choice == '3':
                return False
            else:
                print("Invalid choice")

def handle_logged_in_menu(session):
    while True:
        # Check user status
        status_resp = session.get(f"{BASE_URL}/check-admin-status")
        is_admin = status_resp.json().get("is_admin", False)
        user_status = status_resp.json().get("status", "Regular User")

        print(f"\nLogged in as: {user_status}")
        print("1. Sign out")
        print("2. Check status")
        print("3. Continue")

        choice = input("Choose option: ").strip()

        if choice == '1':
            session.post(f"{BASE_URL}/logout")
            print("Signed out successfully")
            break
        elif choice == '2':
            print(f"Your status: {user_status}")
        elif choice == '3':
            if is_admin:
                verify_resp = session.post(f"{BASE_URL}/verify-level3")
                if verify_resp.json().get("success"):
                    print("\nGREAT! You've completed Level 3!")
                    print("Proceeding to Level 4...")
                    # Placeholder for Level 4
                    return True
                else:
                    print("Admin password not modified. Change Admin password in user_db.json")
            else:
                print("Access denied! Admin privileges required.")
        else:
            print("Invalid choice")

def solve_level_3():
    print("\n=== LEVEL 3: CAESAR CIPHER CHALLENGE ===")
    while True:
        print("\n1. Open File (Encrypt .txt)")
        print("2. Run Command")
        print("3. Exit to Main Menu")
        choice = input("Choose option: ").strip()

        if choice == '1':
            file_path = input("Enter the path to the .txt file: ").strip()
            try:
                with open(file_path, 'r') as f:
                    text = f.read()
                response = requests.post(f"{BASE_URL}/encrypt-file", json={"text": text})
                if response.status_code == 200:
                    encrypted_text = response.json().get("encrypted_text")
                    print("\nEncrypted Content:")
                    print(encrypted_text)
                else:
                    print("Error encrypting file.")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == '2':
            cmd = input("Enter command (For enter the flag use SOLVE): ").strip().upper()
            if cmd == "HELP":
                response = requests.get(f"{BASE_URL}/get-encrypted-flag")
                if response.status_code == 200:
                    encrypted_flag = response.json().get("encrypted_flag")
                    print(f"\nEncrypted Flag: {encrypted_flag}")
                else:
                    print("Failed to retrieve flag.")
            elif cmd == "SOLVE":
                answer = input("Enter decrypted flag: ").strip()
                response = requests.post(f"{BASE_URL}/solve-level3", json={"answer": answer})
                if response.status_code == 200:
                    print(f"\n{response.json().get('message')}")
                    return solve_level_4()
                else:
                    print(f"\n{response.json().get('message')}")
            else:
                print("Invalid command.")

        elif choice == '3':
            return False
        else:
            print("Invalid choice.")

def solve_level_4():
    print("\n=== LEVEL 4: PROCESS SANDBOX ESCAPE CHALLENGE ===")
    
    # Get the challenge information
    response = requests.get(f"{BASE_URL}/get-level4")
    if response.status_code == 200:
        challenge_info = response.json()
        print("\nChallenge:", challenge_info.get("challenge"))
        print("Instructions:", challenge_info.get("instructions"))
        print("Process Name:", challenge_info.get("process_name"))
        print(f"Process ID: {challenge_info.get('process_id')}")
        print("Hint:", challenge_info.get("hint"))
        
        while True:
            print("\n1. Check Process Status")
            print("2. Help - Kill Process Instructions")
            print("3. Proceed to Part 2 (after terminating process)")
            print("4. Exit to Main Menu")
            
            choice = input("Choose option: ").strip()
            
            if choice == '1':
                status_resp = requests.get(f"{BASE_URL}/check-process-status")
                if status_resp.status_code == 200:
                    status_info = status_resp.json()
                    print(f"\nStatus: {status_info.get('status')}")
                    print(f"Message: {status_info.get('message')}")
                    if status_info.get('status') == 'running':
                        print(f"Process ID: {status_info.get('pid')}")
                else:
                    print("Failed to check process status")
            
            elif choice == '2':
                print("\nTo terminate the process, you need to do it manually:")
                print("1. Use Task Manager: Press Ctrl+Shift+Esc, find the Python process with the right PID and End Task")
                print(f"2. Use Command Prompt: Run 'taskkill /F /PID {challenge_info.get('process_id')}'")
                print(f"3. Use PowerShell: Run 'Stop-Process -Id {challenge_info.get('process_id')} -Force'")
                print("\nThis is a manual step you must complete outside this program.")
                print("Once you've terminated the process, check the status again to confirm.")
            
            elif choice == '3':
                status_resp = requests.get(f"{BASE_URL}/check-process-status")
                if status_resp.status_code == 200 and status_resp.json().get('status') == 'terminated':
                    return solve_level_4_part2()
                else:
                    print("\nYou must terminate the challenge process first!")
                    print("Use option 2 for instructions on how to manually terminate the process.")
            
            elif choice == '4':
                return False
            
            else:
                print("Invalid choice.")
    else:
        print("Failed to get Level 4 challenge.")
        return False

# Remove the automatic decode option
def solve_level_4_part2():
    print("\n=== LEVEL 4 PART 2: BASE64 DECODING CHALLENGE ===")
    
    response = requests.get(f"{BASE_URL}/get-level4-part2")
    if response.status_code == 200:
        challenge_info = response.json()
        print("\nChallenge:", challenge_info.get("challenge"))
        encoded_flag = challenge_info.get("encoded_flag")
        print("Encoded Flag:", encoded_flag)
        print("Hint:", challenge_info.get("hint"))
        
        while True:
            print("\n1. Enter Decoded Flag")
            print("2. Exit to Main Menu")
            
            choice = input("Choose option: ").strip()
            
            if choice == '1':
                answer = input("Enter the decoded flag: ").strip()
                resp = requests.post(f"{BASE_URL}/solve-level4", json={"answer": answer})
                if resp.status_code == 200:
                    print(f"\n{resp.json().get('message')}")
                    print("\nCongratulations! You've completed Level 4!")
                    return True
                else:
                    print(f"\n{resp.json().get('message')}")
            
            elif choice == '2':
                return False
            
            else:
                print("Invalid choice.")
    else:
        print("Failed to get Level 4 Part 2 challenge.")
        return False

def solve_level_5():
    pass


def main():
    print("Starting CTF Challenge...")
    set_registry_value(r"SOFTWARE\CTF_Simulation", "LockAdministrator", '1')
    ensure_admin_exists()
    solve_level_4()


if __name__ == "__main__":
    main()
