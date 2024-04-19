import jwt
import time

def create_token(username, secret):
    role = "noobs"
    if username == "admin":
        role = "admin"
    expire_time = int(time.time() + 300)
    jwt_token = jwt.encode({"username": username, "role": role, "expire_time": expire_time}, secret, algorithm="HS256")
    print(jwt_token)
    return jwt_token

def decode_token(token, secret):
    return jwt.decode(token, secret, algorithms="HS256")

def is_valid_token(token, secret):
    now = int(time.time())
    try:
        payload = decode_token(token, secret)
        if (payload["expire_time"] > now):
            return True
    except Exception as e:
        return False
    return False

def still_in(token, secret):
    if is_valid_token(token, secret):
        attr = decode_token(token, secret)
        if attr["balance"] > 0:
            return True
    return False
