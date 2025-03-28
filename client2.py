import os
import requests
import winreg
import logging
import json

BASE_URL = "http://127.0.0.1:5000"

FLAG_1 = "FileSystemMasterKey2024!"

def get_registry_value(key_path, value_name):
    """Retrieve a value from the Windows Registry."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        return str(value)
    except FileNotFoundError:
        return '1'  # Default to locked
    except Exception as e:
        logging.error(f"Registry read error: {e}")
        return '1'

def set_registry_value(key_path, value_name, value):
    """Set a value in the Windows Registry."""
    try:
        # Ensure the key exists
        key, _ = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, str(value))
        winreg.CloseKey(key)
        return True
    except Exception as e:
        logging.error(f"Registry write error: {e}")
        return False

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
            
            # Set initial registry value
            key_path = r"SOFTWARE\CTF_Simulation"
            value_name = "LockAdministrator"
            set_registry_value(key_path, value_name, '1')
            
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

    # Registry key for storing LockAdministrator status
    key_path = r"SOFTWARE\CTF_Simulation"
    value_name = "LockAdministrator"

    print("\nPress Enter to check current status")
    input()  # Wait for user to press Enter

    # Dynamically fetch current registry value
    current_lock_status = get_registry_value(key_path, value_name)
    print("Current LockAdministrator:", current_lock_status)

    if current_lock_status == '0':
      base_path = os.path.join(os.path.expanduser(r"C:\Program Files"), "CTF_Challenge")
      flag_location = os.path.join(base_path, "Users", "Administrator", "secret_logs", "system_log.txt")
      os.makedirs(os.path.dirname(flag_location), exist_ok=True)
      with open(flag_location, 'w') as f:
        f.write(FLAG_1)
      ans = input("\nEnter the flag from the system_log.txt: ").strip()
            
            # Attempt to submit the flag
      post_resp = requests.post(f"{BASE_URL}/solve-level1", json={"answer": ans})
      if post_resp.status_code == 200:
       print(post_resp.json().get("message"))
       return True 
      else:
        print(post_resp.json().get("message"))
    else:
        print("Administrator directory is still locked. Change the LockAdministrator registry value to 0.")
        solve_level_1()

def solve_level_2():
    """Solve Stage 2: Access Level Challenge with JSON Document"""
    print("\nLevel 2: Access Level Challenge")
    
    # Get challenge details
    response = requests.get(f"{BASE_URL}/get-level2")
    if response.status_code == 200:
        challenge_info = response.json()
        print("\nChallenge:", challenge_info.get("challenge"))
        print("File Path:", challenge_info.get("file_path"))
        print("Current Access Level:", challenge_info.get("current_access_level"))
        print("Target Access Level:", challenge_info.get("target_access_level"))
        
        # Locate the user database file
        documents_path = os.path.join(os.path.expanduser("~"), "Documents")
        user_db_path = os.path.join(documents_path, "user_db.json")
        
        # Read the current user database
        with open(user_db_path, 'r') as f:
            user_db = json.load(f)
        
        # Print current database for user to see
        print("\nCurrent User Database:")
        print(json.dumps(user_db, indent=2))
        
        # Modify access level
        user_db['users'][0]['access_level'] = 15
        
        # Write back to the file
        with open(user_db_path, 'w') as f:
            json.dump(user_db, f, indent=4)
        
        print("\nAccess level modified successfully!")
        
        # Prompt for flag
        ans = input("Enter the flag for Level 2: ").strip()
        
        # Submit solution
        post_resp = requests.post(f"{BASE_URL}/solve-level2", json={"answer": ans})
        if post_resp.status_code == 200:
            print(post_resp.json().get("message"))
            return True
        else:
            print(post_resp.json().get("message"))
            return solve_level_2()



def main():
    print("Starting CTF Challenge...")
    
    # Set initial registry value
    key_path = r"SOFTWARE\CTF_Simulation"
    value_name = "LockAdministrator"
    set_registry_value(key_path, value_name, '1')
    
    solve_level_2()

if __name__ == "__main__":
    main()
