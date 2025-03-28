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

# Original Level 0-1 Functions (Unchanged)
def solve_level_0():
    print("Level 0: Binary-to-Decimal Challenge")
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
    print("Level 1: File System Challenge")
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

# New Level 2-3 Functions
def solve_level_2():
    print("\n=== LEVEL 2: ACCESS LEVEL CHALLENGE ===")
    with requests.Session() as s:
        while True:
            print("\n1. Sign up")
            print("2. Login")
            print("3. Exit to main menu")
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
                    break
            elif choice == '3':
                return False
            else:
                print("Invalid choice")

        resp = s.get(f"{BASE_URL}/get-level2")
        challenge = resp.json()
        print(f"\n{challenge['challenge']}")
        print(f"Target access level: {challenge['target_access_level']}")
        print(f"JSON file: {challenge['file_path']}")

        input("\nModify your access_level to 15 in the JSON file, then press Enter...")

        resp = s.post(f"{BASE_URL}/solve-level2")
        result = resp.json()
        print(f"\n{result.get('message')}")
        if resp.status_code == 200:
            print(f"FLAG: {result.get('flag')}")
            return True
        return solve_level_2()

def solve_level_3():
    print("\n=== LEVEL 3: ADMIN PASSWORD RESET ===")
    with requests.Session() as s:
        resp = s.get(f"{BASE_URL}/get-level3")
        challenge = resp.json()
        
        print(f"\nChallenge: {challenge['challenge']}")
        print("Requirements:")
        for req in challenge['requirements']:
            print(f"- {req}")
        print(f"\nHint: {challenge['hint']}")
        
        input("\nPress Enter after modifying Admin's password_hash...")
        
        resp = s.post(f"{BASE_URL}/solve-level3")
        result = resp.json()
        
        if resp.status_code == 200:
            print(f"\nSUCCESS: {result['message']}")
            print(f"FLAG: {result['flag']}")
            return True
        else:
            print(f"\nERROR: {result['message']}")
            retry = input("Try again? (y/n): ").lower()
            if retry == 'y':
                return solve_level_3()
            return False

def main():
    print("Starting CTF Challenge...")
    set_registry_value(r"SOFTWARE\CTF_Simulation", "LockAdministrator", '1')
    #solve_level_0()
    #solve_level_1()
    solve_level_2()
    solve_level_3()

if __name__ == "__main__":
    main()
