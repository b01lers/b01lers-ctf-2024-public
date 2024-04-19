from flask import render_template, Flask, request, jsonify
import os
from waf import *
import secrets

app = Flask(__name__)
app.static_folder = 'assets'

@app.route("/", methods= ["GET"])
def index():
    return render_template('writeups.html')

@app.route("/pentest_submitted_flags", methods=["POST"])
def submit():
    if request.is_json:
        # Retrieve JSON data
        data = request.json
        content = data["content"]
        print(content)
        if sus(content):
            return jsonify({"message": "The requested URL was rejected. Please consult with your administrator."}), 200
        else:
            filename = "writeup_" + secrets.token_urlsafe(50)
            os.system(f"bash -c \'echo \"{content}\" > {filename}\'")
            # Like I care about your writeup
            os.system(f"rm -f writeup_{filename}")
            return jsonify({"message": "Writeup submitted successfully"}), 200


    else:
        return jsonify({'error': 'Request data must be in JSON format'}), 400

if __name__ == "__main__":
    app.run(port=1337)