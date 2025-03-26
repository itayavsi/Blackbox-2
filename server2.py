from flask import Flask
import random
import string
from flask import jsonify, make_response, request


app = Flask(__name__)
app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

FLAG_0 = "42"     

@app.route('/get-level0', methods=["GET"])
def get_level0():
    return jsonify({"binary": "101010"})

@app.route('/solve-level0', methods=["POST"])
def solve_level1():
    data = request.get_json()
    answer = data.get("answer")
    if answer == FLAG_0:
        return make_response(jsonify({"message": "Level 0 solved!"}), 200)
    return make_response(jsonify({"message": "Incorrect answer. Try again."}), 400)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
