import os
import requests
import winreg
import logging
import json

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
            return True
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
    # Empty as requested
    pass

def main():
    print("Starting CTF Challenge...")
    set_registry_value(r"SOFTWARE\CTF_Simulation", "LockAdministrator", '1')
    solve_level_0()
    solve_level_1()
    solve_level_2()

if __name__ == "__main__":
    main()
