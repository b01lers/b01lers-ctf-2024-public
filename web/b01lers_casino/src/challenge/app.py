from flask import render_template, Flask, redirect, request, jsonify, make_response
from token_utils import *
import secrets
from database import *

app = Flask(__name__)
app.static_folder = 'assets'
app.config['SECRET_KEY'] = secrets.token_bytes(69)
app.config['FLAG'] = "bctf{how_can_a_casino_put_that_much_trust_on_client_uhmm_clientside}"
print(app.config['SECRET_KEY'])
init_db()

@app.route("/")
def index():
    jwt_token = request.cookies.get('jwt')
    if (jwt_token):
        print("JWT presented")
        if is_valid_token(jwt_token,  app.config['SECRET_KEY']):
            return render_template("index.html")
    return redirect("/login")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "GET":
        return render_template('login.html')
    if request.method == "POST":
        if request.is_json:
            # Retrieve JSON data
            data = request.json
            print(data)
            # Extract required fields from JSON data
            username = data.get('username')
            password = data.get('password')

            # Check if all required fields are present
            if username and password:
                # Here you can perform further processing like database operations or authentication
                if authenticate(username, password):
                    granted_token = create_token(username, app.config['SECRET_KEY'])
                    return jsonify({'jwt': granted_token}), 200
                else:
                    return jsonify({'error': "Incorrect username or password"}), 403
            else:
                # If any required field is missing, return 400 Bad Request
                return jsonify({'error': 'Missing required fields in JSON data'}), 400
    else:
        # If the request method is not POST, return 400 Bad Request
        return jsonify({'error': 'Unsupported method'}), 400



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "GET":
        return render_template('register.html')
    elif request.method == "POST":
        # Check if request contains JSON data
        if request.is_json:
            # Retrieve JSON data
            data = request.json
            print(data)
            # Extract required fields from JSON data
            fullname = data.get('fullname')
            username = data.get('username')
            password = data.get('password')

            # Check if all required fields are present
            if fullname and username and password:
                if not is_valid_sha256(password):
                    return jsonify({'message': "Man-In-The-Middle Attack Detected!"}), 400

                # Here you can perform further processing like database operations or authentication
                try:
                    register_user(fullname, username, password)
                except Exception as e:
                    return jsonify({'message': str(e)}), 400
                # Returning a success response
                return jsonify({'message': 'Registration successful'}), 200
            else:
                # If any required field is missing, return 400 Bad Request
                return jsonify({'error': 'Missing required fields in JSON data'}), 400
        else:
            # If request does not contain JSON data, return 400 Bad Request
            return jsonify({'error': 'Request data must be in JSON format'}), 400
    else:
        # If the request method is not POST, return 400 Bad Request
        return jsonify({'error': 'Unsupported method'}), 400

@app.route("/checkdb")
def checkdb():
    check_db()
    return redirect("/login")

@app.route("/registration_successful")
def registration_successful():
    return render_template("registration_successful.html")

@app.route("/scoreboard")
def scoreboard():
    return render_template("scoreboard.html", players=fetchScoreboard())

@app.route("/logout")
def logout():
    response = redirect("/login")
    response.delete_cookie("jwt")
    return response

@app.route("/slots", methods = ["GET", "POST"])
def slots():
    jwt_token = request.cookies.get('jwt')
    if jwt_token == None or not is_valid_token(jwt_token, app.config['SECRET_KEY']):
        return redirect("/login")
    
    if request.method == "GET":
        username = decode_token(jwt_token, app.config['SECRET_KEY'])["username"]
        if (checkBalance(username) == 0):
            return render_template("brokie.html")
        return render_template("slots.html")
    elif request.method == "POST":
        # Check if request contains JSON data
        if request.is_json:
            # Retrieve JSON data
            data = request.json
            # Extract required fields from JSON data
            amount = data["change"]
            username = decode_token(jwt_token, app.config['SECRET_KEY'])["username"]
            updateBalance(username, amount)
            return jsonify({"message": "alright"}), 200
        else:
            # If request does not contain JSON data, return 400 Bad Request
            return jsonify({'error': 'Request data must be in JSON format'}), 400

@app.route("/update_password", methods = ["POST",])
def change_password():
    jwt_token = request.cookies.get('jwt')
    if jwt_token == None or not is_valid_token(jwt_token, app.config['SECRET_KEY']):
        return jsonify({'error': 'Unauthorized'}), 403
    if request.is_json:
        data = request.json
        new_password = data["new_password"]
        if not is_valid_sha256(new_password):
            return jsonify({'error': "Sus"}), 400
        else:
            username = decode_token(jwt_token, app.config['SECRET_KEY'])["username"]
            updatePassword(username, new_password)
            return jsonify({"message": "alright"}), 200
    else:
        jsonify({'error': 'Request data must be in JSON format'}), 400

@app.route("/grab_flag", methods = ["GET"])
def grab_flag():
    jwt_token = request.cookies.get('jwt')
    if jwt_token == None or not is_valid_token(jwt_token, app.config['SECRET_KEY']):
        return jsonify({'error': 'Unauthorized'}), 403
    payload = decode_token(jwt_token, app.config["SECRET_KEY"])
    if (payload["username"] != "admin"):
        return jsonify({'error': 'Unauthorized'}), 403
    return jsonify({"flag": app.config["FLAG"]})

@app.route("/blackjack", methods = ["GET"])
def blackjack():
    return jsonify({'message': "Dev has better things to do than implement this"}), 400

@app.route("/baccarat", methods = ["GET"])
def baccarat():
    return jsonify({'message': "Dev has better things to do than implement this"}), 400

@app.route("/poker", methods = ["GET"])
def poker():
    return jsonify({'message': "Dev has better things to do than implement this"}), 400


if __name__ == "__main__":
    app.run(ssl_context='adhoc')
