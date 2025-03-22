import os
import json
import socket
import threading
import base64
import hashlib
import random, string
from flask import Flask, request, jsonify, render_template_string, make_response
from datetime import datetime
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = Flask(__name__)

# ------------------------------
# Define flags for each level
# ------------------------------
FLAG_1 = "42"                # Level 1: Binary conversion challenge
FLAG_2 = "flag{html_hidden}" # Level 2: Hidden HTML comment challenge
FLAG_3 = "flag{rot13_master}"# Level 3: ROT13 challenge
FLAG_4 = "flag{tcp_reversed}"# Level 4: TCP reversal challenge
FLAG_5 = "flag{hidden_text}" # Level 5: Hidden pattern extraction
FLAG_6 = "flag{jwt_unveiled}"# Level 6: JWT token challenge
FLAG_7 = "flag{hex_decoded}" # Level 7: Log file hex challenge
FLAG_8 = "flag{morse_master}"# New Level 8: Morse code challenge
FLAG_9 = "flag{ascii_hidden}"# New Level 9: ASCII art steganography challenge

# ------------------------------
# Levels 1–7 (unchanged)
# ------------------------------
@app.route('/get-level1', methods=["GET"])
def get_level1():
    return jsonify({"binary": "101010"})

@app.route('/solve-level1', methods=["POST"])
def solve_level1():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_1:
        return make_response(jsonify({"message": "Level 1 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect answer. Try again."}), 400)

@app.route('/level2', methods=["GET"])
def level2():
    html = """
    <!DOCTYPE html>
    <html lang="he">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>אתגר רמה 2 - גאמא אסנשאלס</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #f8f9fa;
                margin: 0;
                padding: 0;
                direction: rtl; /* Forces left-to-right layout */
            }}
            header {{
                background-color: #000080;
                color: #ffffff;
                padding: 20px;
                text-align: center;
            }}
            .container {{
                max-width: 800px;
                margin: 40px auto;
                padding: 20px;
                background-color: #ffffff;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            footer {{
                text-align: center;
                padding: 10px;
                font-size: 0.9em;
                color: #6c757d;
            }}
        </style>
    </head>
    <body>
        <header>
            <h1>גאמא אסנשאלס</h1>
            <p>SubHeader</p>
        </header>
        <div class="container">
            <h2>ברוכים הבאים לאתגר רמה 2</h2>
            <p>Text 1 </p>
            <p>Text 2</p>
            <!-- רמז 1: {flag_part1} -->
            <div style="display:none;">
                {flag_part2}
            </div>
            <span hidden>
                {flag_part3}
            </span>
        </div>
        <footer>
            &copy; 2025 גאמא אסנשאלס. כל הזכויות שמורות.
        </footer>
    </body>
    </html>
    """.format(
        flag_part1 = FLAG_2[0:len(FLAG_2)//3],
        flag_part2 = FLAG_2[len(FLAG_2)//3:2*len(FLAG_2)//3],
        flag_part3 = FLAG_2[2*len(FLAG_2)//3:]
    )
    return html

@app.route('/solve-level2', methods=["POST"]) #TODO: Make the level harder
def solve_level2():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_2:
        return make_response(jsonify({"message": "Level 2 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect flag. Try again."}), 400)

def rot13(s):
    result = []
    for char in s:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return "".join(result)

@app.route('/get-level3', methods=["GET"])
def get_level3():
    encoded = rot13(FLAG_3)
    return jsonify({"rot13": encoded})

@app.route('/solve-level3', methods=["POST"]) #TODO: Hide the level enc name
def solve_level3():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_3:
        return make_response(jsonify({"message": "Level 3 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect decryption. Try again."}), 400)

def tcp_level4_server(): #FIXME: TCP server don't working.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 65434))
    server.listen(5)
    print("Level 4 TCP server listening on 127.0.0.1:65434")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_level4_client, args=(conn, addr), daemon=True).start()

def handle_level4_client(conn, addr):
    print(f"Level 4: Connection from {addr}")
    reversed_flag = FLAG_4[::-1]
    conn.sendall(reversed_flag.encode())
    data = conn.recv(1024).decode().strip()
    if data == FLAG_4:
        conn.sendall("Correct!".encode())
    else:
        conn.sendall("Incorrect!".encode())
    conn.close()

@app.route('/solve-level4', methods=["POST"])
def solve_level4():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_4:
        return make_response(jsonify({"message": "Level 4 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect flag from TCP challenge."}), 400)

threading.Thread(target=tcp_level4_server, daemon=True).start()

@app.route('/get-level5', methods=["GET"])
def get_level5():
    parts = list(FLAG_5)
    long_str = ""
    for ch in parts:
        long_str += ch + "".join(random.choices(string.ascii_letters, k=2))
    long_str += "".join(random.choices(string.ascii_letters, k=20))
    return jsonify({"string": long_str})

@app.route('/solve-level5', methods=["POST"])
def solve_level5():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_5:
        return make_response(jsonify({"message": "Level 5 solved!"}), 200)
    return make_response(jsonify({"message": "Extraction failed. Try again."}), 400)

@app.route('/get-token-level6', methods=["GET"])
def get_token_level6():
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"flag": FLAG_6}).encode()).decode().rstrip("=")
    token = header + "." + payload + "."
    return jsonify({"token": token})

@app.route('/solve-level6', methods=["POST"])
def solve_level6():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_6:
        return make_response(jsonify({"message": "Level 6 solved!"}), 200)
    return make_response(jsonify({"message": "JWT payload not decoded correctly."}), 400)

@app.route('/level7', methods=["GET"])
def level7():
    desktop = Path.home() / "Desktop"
    log_file = desktop / "activity.log"
    lines = []
    for i in range(10):
        lines.append(f"{datetime.now()} - INFO - Routine check.")
    hex_flag = FLAG_7.encode().hex()
    insert_index = 3
    lines.insert(insert_index, f"{datetime.now()} - ALERT - {hex_flag}")
    with open(log_file, "w") as f:
        f.write("\n".join(lines))
    return make_response(jsonify({"message": f"Log file created at {log_file}"}), 200)

@app.route('/solve-level7', methods=["POST"])
def solve_level7():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_7:
        return make_response(jsonify({"message": "Level 7 solved!"}), 200)
    return make_response(jsonify({"message": "Hex string did not decode to the correct flag."}), 400)

# ------------------------------
# New Level 8: Morse Code Challenge
# ------------------------------
@app.route('/get-level8', methods=["GET"])
def get_level8():
    flag = FLAG_8.upper()
    morse_dict = {
        'A': '.-',   'B': '-...', 'C': '-.-.', 'D': '-..',  'E': '.',
        'F': '..-.', 'G': '--.',  'H': '....', 'I': '..',   'J': '.---',
        'K': '-.-',  'L': '.-..', 'M': '--',   'N': '-.',   'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.',  'S': '...',  'T': '-',
        'U': '..-',  'V': '...-', 'W': '.--',  'X': '-..-', 'Y': '-.--',
        'Z': '--..',
        '0': '-----','1': '.----','2': '..---','3': '...--','4': '....-',
        '5': '.....','6': '-....','7': '--...','8': '---..','9': '----.',
        '{': '-.--.', '}': '-..-.', '_': '..--.-'
    }
    morse_encoded = []
    for char in flag:
        if char in morse_dict:
            morse_encoded.append(morse_dict[char])
        else:
            morse_encoded.append(char)
    morse_str = " ".join(morse_encoded)
    return jsonify({"morse": morse_str})

@app.route('/solve-level8', methods=["POST"])
def solve_level8():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_8:
        return make_response(jsonify({"message": "Level 8 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect Morse decoding. Try again."}), 400)

# ------------------------------
# New Level 9: ASCII Art Steganography Challenge
# ------------------------------
@app.route('/get-level9', methods=["GET"])
def get_level9():
    flag = FLAG_9
    art_lines = []
    for ch in flag:
        noise1 = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        noise2 = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        line = noise1 + ch + noise2
        art_lines.append(line)
    ascii_art = "\n".join(art_lines)
    return jsonify({"ascii_art": ascii_art})

@app.route('/solve-level9', methods=["POST"])
def solve_level9():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_9:
        return make_response(jsonify({"message": "Level 9 solved! Flag: " + FLAG_9}), 200)
    return make_response(jsonify({"message": "Incorrect flag from ASCII art. Try again."}), 400)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
