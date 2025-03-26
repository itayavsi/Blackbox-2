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
        else:
            print(post_resp.json().get("message"))
            solve_level_0()
    else:
        print("Failed to get Level 0 challenge.")
        solve_level_0()
        
def main():
    print("Starting CTF Challenge...")
    solve_level_0()

if __name__ == "__main__":
    main()
