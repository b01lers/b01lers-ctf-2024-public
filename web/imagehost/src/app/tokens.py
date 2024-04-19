from pathlib import Path

import jwt

def encode(payload, public_key: Path, private_key: Path):
	key = private_key.read_bytes()
	return jwt.encode(payload=payload, key=key, algorithm="RS256", headers={"kid": str(public_key)})

def decode(token):
	headers = jwt.get_unverified_header(token)
	public_key = Path(headers["kid"])
	if public_key.absolute().is_relative_to(Path.cwd()):
		key = public_key.read_bytes()
		return jwt.decode(jwt=token, key=key, algorithms=["RS256"])
	else:
		return {}
