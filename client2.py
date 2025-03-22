import requests
import socket
import webbrowser
import json

BASE_URL = "http://127.0.0.1:5000"

def solve_level_1():
    print("Level 1: Binary-to-Decimal Challenge")
    response = requests.get(f"{BASE_URL}/get-level1")
    if response.status_code == 200:
        binary_str = response.json().get("binary")
        print("Binary number:", binary_str)
        ans = input("Enter its decimal value: ").strip()
        post_resp = requests.post(f"{BASE_URL}/solve-level1", json={"answer": ans})
        if post_resp.status_code == 200:
            print(post_resp.json().get("message"))
            solve_level_2()
        else:
            print(post_resp.json().get("message"))
            solve_level_1()
    else:
        print("Failed to get Level 1 challenge.")
        solve_level_1()

def solve_level_2():
    print("\nLevel 2: Hidden HTML Comment Challenge")
    print("Open the following URL in your browser and view the page source:")
    print(f"{BASE_URL}/level2")
    flag = input("Enter the hidden flag you found: ").strip()
    response = requests.post(f"{BASE_URL}/solve-level2", json={"answer": flag})
    if response.status_code == 200:
        print(response.json().get("message"))
        solve_level_3()
    else:
        print(response.json().get("message"))
        solve_level_2()

def solve_level_3():
    print("\nLevel 3: ROT13 Challenge")
    response = requests.get(f"{BASE_URL}/get-level3")
    if response.status_code == 200:
        encoded = response.json().get("rot13")
        print("ROT13 encoded flag:", encoded)
        ans = input("Enter the decoded flag: ").strip()
        resp = requests.post(f"{BASE_URL}/solve-level3", json={"answer": ans})
        if resp.status_code == 200:
            print(resp.json().get("message"))
            solve_level_4()
        else:
            print(resp.json().get("message"))
            solve_level_3()
    else:
        print("Error retrieving Level 3 challenge.")
        solve_level_3()

def solve_level_4():
    print("\nLevel 4: TCP Reversal Challenge")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("127.0.0.1", 65434))
        data = s.recv(1024).decode().strip()
        print("Received reversed flag:", data)
        ans = input("Enter the corrected flag: ").strip()
        s.sendall(ans.encode())
        resp = s.recv(1024).decode().strip()
        print("TCP Server response:", resp)
    response = requests.post(f"{BASE_URL}/solve-level4", json={"answer": ans})
    if response.status_code == 200:
        print(response.json().get("message"))
        solve_level_5()
    else:
        print(response.json().get("message"))
        solve_level_4()

def solve_level_5():
    print("\nLevel 5: Hidden Pattern Extraction")
    response = requests.get(f"{BASE_URL}/get-level5")
    if response.status_code == 200:
        long_str = response.json().get("string")
        print("Long string:", long_str)
        print("Hint: Every 3rd character (starting at index 0) forms the flag.")
        ans = input("Enter the extracted flag: ").strip()
        resp = requests.post(f"{BASE_URL}/solve-level5", json={"answer": ans})
        if resp.status_code == 200:
            print(resp.json().get("message"))
            solve_level_6()
        else:
            print(resp.json().get("message"))
            solve_level_5()
    else:
        print("Error retrieving Level 5 challenge.")
        solve_level_5()

def solve_level_6():
    print("\nLevel 6: JWT Token Challenge")
    response = requests.get(f"{BASE_URL}/get-token-level6")
    if response.status_code == 200:
        token = response.json().get("token")
        print("JWT token:", token)
        ans = input("Decode the token payload and enter the flag: ").strip()
        resp = requests.post(f"{BASE_URL}/solve-level6", json={"answer": ans})
        if resp.status_code == 200:
            print(resp.json().get("message"))
            solve_level_7()
        else:
            print(resp.json().get("message"))
            solve_level_6()
    else:
        print("Error retrieving JWT token.")
        solve_level_6()

def solve_level_7():
    print("\nLevel 7: Log File Hex Challenge")
    print("A log file 'activity.log' has been created on your Desktop.")
    ans = input("Enter the flag decoded from the hex string in the log file: ").strip()
    response = requests.post(f"{BASE_URL}/solve-level7", json={"answer": ans})
    if response.status_code == 200:
        print(response.json().get("message"))
        solve_level_8()
    else:
        print(response.json().get("message"))
        solve_level_7()

def solve_level_8():
    print("\nLevel 8: Morse Code Challenge")
    response = requests.get(f"{BASE_URL}/get-level8")
    if response.status_code == 200:
        morse = response.json().get("morse")
        print("Morse Code:", morse)
        ans = input("Decode the Morse code and enter the flag: ").strip()
        resp = requests.post(f"{BASE_URL}/solve-level8", json={"answer": ans})
        if resp.status_code == 200:
            print(resp.json().get("message"))
            solve_level_9()
        else:
            print(resp.json().get("message"))
            solve_level_8()
    else:
        print("Error retrieving Morse challenge.")
        solve_level_8()

def solve_level_9():
    print("\nLevel 9: ASCII Art Steganography Challenge")
    response = requests.get(f"{BASE_URL}/get-level9")
    if response.status_code == 200:
        art = response.json().get("ascii_art")
        print("ASCII Art:\n", art)
        ans = input("Extract and enter the hidden flag: ").strip()
        resp = requests.post(f"{BASE_URL}/solve-level9", json={"answer": ans})
        if resp.status_code == 200:
            print(resp.json().get("message"))
            print("CTF completed! Congratulations!")
        else:
            print(resp.json().get("message"))
            solve_level_9()
    else:
        print("Error retrieving ASCII art challenge.")
        solve_level_9()

def main():
    solve_level_1()

if __name__ == "__main__":
    main()
