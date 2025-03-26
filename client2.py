import os
import requests
from pathlib import Path

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
        
    print("\nPossible steps to solve:")
    print("1. Change the environment variable LockAdministrator to '0'")
    print("2. Use 'import os' and 'os.environ[\"LockAdministrator\"] = \"0\"'")
    print("Press Enter after Unlock the Administrator to Refreash and revel the flag")
                    
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


def main():
    print("Starting CTF Challenge...")
    solve_level_0()
    

if __name__ == "__main__":
    main()
