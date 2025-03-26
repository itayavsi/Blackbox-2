import os
import requests
import subprocess

BASE_URL = "http://127.0.0.1:5000"

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
            os.environ["LockAdministrator"] = "1"  # Update it for the script
            os.system("set LockAdministrator=1")  # Update it for the shell
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

    print("Press Enter after unlocking the Administrator to reveal the flag")
    print("Current LockAdministrator:", get_env_var("LockAdministrator"))

    ans = input("\nEnter the flag from the system_log.txt: ").strip()
    
    # Attempt to submit the flag
    post_resp = requests.post(f"{BASE_URL}/solve-level1", json={"answer": ans})
    if post_resp.status_code == 200:
        print(post_resp.json().get("message"))
        print("Level 1 completed.")
        return True
    else:
        print(post_resp.json().get("message"))
        return solve_level_1()

def get_env_var(var_name):
    """Fetch updated environment variable value."""
    result = subprocess.run(['cmd.exe', '/c', f'echo %{var_name}%'], capture_output=True, text=True)
    return result.stdout.strip()

def main():
    print("Starting CTF Challenge...")
    
    # Set initial environment variable
    os.environ["LockAdministrator"] = "1"  # For the script
    os.system("set LockAdministrator=1")  # For the shell
    
    solve_level_0()

if __name__ == "__main__":
    main()
