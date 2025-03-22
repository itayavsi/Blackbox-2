import os
import json
import socket
import threading
import base64
import hashlib
import random, string
import time
import hmac
from flask import Flask, request, jsonify, render_template_string, make_response, send_file
from datetime import datetime, timedelta
from pathlib import Path
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    crypto_available = True
except ImportError:
    crypto_available = False

app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

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
FLAG_8 = "flag{morse_master}"# Level 8: Morse code challenge
FLAG_9 = "flag{ascii_hidden}"# Level 9: ASCII art steganography challenge

# ------------------------------
# Helper functions
# ------------------------------
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

# Custom JWT implementation to avoid dependency on jwt library
def base64url_encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64url_decode(data):
    padding = b'=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data.encode('utf-8') + padding)

def generate_jwt_token():
    # Create JWT header
    header = {"alg": "HS256", "typ": "JWT"}
    header_encoded = base64url_encode(json.dumps(header))
    
    # Create JWT payload with the flag hidden in base64
    payload = {
        'exp': int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        'iat': int(datetime.utcnow().timestamp()),
        'sub': 'user123',
        'role': 'user',
        'hidden_data': base64.b64encode(FLAG_6.encode()).decode()
    }
    payload_encoded = base64url_encode(json.dumps(payload))
    
    # Create signature
    message = f"{header_encoded}.{payload_encoded}"
    signature = hmac.new(
        app.config['SECRET_KEY'].encode(),
        message.encode(),
        hashlib.sha256
    ).digest()
    signature_encoded = base64url_encode(signature)
    
    # Combine to form JWT
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

def generate_log_file():
    log_entries = []
    flag_hex = ''.join([hex(ord(c))[2:] for c in FLAG_7])
    
    for i in range(20):
        timestamp = (datetime.now() - timedelta(minutes=random.randint(1, 500))).strftime('%Y-%m-%d %H:%M:%S')
        ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
        path = random.choice(['/login', '/dashboard', '/profile', '/settings', '/logout'])
        status = random.choice([200, 201, 400, 401, 403, 404, 500])
        
        # Insert the flag in a random log entry
        if i == 10:
            user_agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) FLAGHEX:{flag_hex} AppleWebKit/537.36"
        else:
            user_agent = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        log_entries.append(f"{timestamp} - IP: {ip} - {method} {path} - Status: {status} - User-Agent: {user_agent}")
    
    log_path = os.path.join(os.path.dirname(__file__), 'access.log')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)  # Ensure directory exists
    with open(log_path, 'w') as f:
        f.write('\n'.join(log_entries))
    
    return log_path

def text_to_morse(text):
    morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 
        'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--', 
        '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', 
        '9': '----.', '0': '-----', ' ': '/'
    }
    
    morse_text = []
    for char in text.upper():
        if char in morse_dict:
            morse_text.append(morse_dict[char])
    
    return ' '.join(morse_text)

def generate_ascii_art():
    # Simple ASCII art with hidden flag
    ascii_art = """
    +----------------------------------+
    |        SECURITY CHALLENGE        |
    |         SYSTEM ACCESS            |
    +----------------------------------+
    |                                  |
    |     /\\       /\\      /\\          |
    |    /  \\     /  \\    /  \\         |
    |   /    \\   /    \\  /    \\        |
    |  /      \\ /      \\/      \\       |
    | /        V        V        \\      |
    |/                            \\     |
    +----------------------------------+
    """
    
    # Hide the flag in specific positions
    art_lines = ascii_art.split('\n')
    
    # Extract first letter of each line to form the flag
    hidden_message = ""
    for i, line in enumerate(art_lines):
        if 3 <= i <= 11:
            if i % 2 == 0 and len(line) > 5:
                hidden_message += line[5]
    
    return ascii_art, hidden_message

# ------------------------------
# Level 1: Binary conversion
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

# ------------------------------
# Level 2: Hidden HTML comment
# ------------------------------
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
                direction: rtl; /* Forces right-to-left layout */
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
            <p>אתגר אבטחה</p>
        </header>
        <div class="container">
            <h2>ברוכים הבאים לאתגר רמה 2</h2>
            <p>כדי להשלים את האתגר, עליך למצוא את כל חלקי הדגל.</p>
            <p>חפש היטב! הדגל עשוי להיות מוסתר בכל מקום.</p>
            <!-- רמז 1: {flag_part1} -->
            <div style="display:none;">
                {flag_part2}
            </div>
            <span hidden>
                {flag_part3}
            </span>
            <!-- עוד רמז? אולי תבדוק עם המפתח 'ctrl+u' -->
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

@app.route('/solve-level2', methods=["POST"])
def solve_level2():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_2:
        return make_response(jsonify({"message": "Level 2 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect flag. Try again."}), 400)

# ------------------------------
# Level 3: ROT13 challenge
# ------------------------------
@app.route('/get-level3', methods=["GET"])
def get_level3():
    encoded = rot13(FLAG_3)
    # Hide the fact that ROT13 is being used
    return jsonify({"encrypted_challenge": encoded})

@app.route('/solve-level3', methods=["POST"])
def solve_level3():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_3:
        return make_response(jsonify({"message": "Level 3 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect decryption. Try again."}), 400)

# ------------------------------
# Level 4: TCP reversal challenge
# ------------------------------
def tcp_level4_server():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 65434))
        server.listen(5)
        print("Level 4 TCP server listening on 0.0.0.0:65434")
        
        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_level4_client, args=(conn, addr), daemon=True).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")
    except Exception as e:
        print(f"TCP server error: {e}")

def handle_level4_client(conn, addr):
    try:
        print(f"Level 4: Connection from {addr}")
        reversed_flag = FLAG_4[::-1]
        conn.sendall(reversed_flag.encode())
        
        # Set a timeout for receiving data
        conn.settimeout(10)
        
        data = conn.recv(1024).decode().strip()
        if data == FLAG_4:
            conn.sendall("Correct! You've solved Level 4.".encode())
        else:
            conn.sendall("Incorrect! Try again.".encode())
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()

@app.route('/level4-info', methods=["GET"])
def level4_info():
    return jsonify({
        "message": "To solve level 4, connect to the TCP server on port 65434 and reverse the received message.",
        "hint": "The server sends data in reverse. You need to correct it and send it back."
    })

@app.route('/solve-level4', methods=["POST"])
def solve_level4():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_4:
        return make_response(jsonify({"message": "Level 4 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect flag from TCP challenge."}), 400)


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
