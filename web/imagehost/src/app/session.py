import typing
from pathlib import Path

from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

import tokens

class SessionMiddleware:
	def __init__(
		self,
		app: ASGIApp,
		public_key: Path,
		private_key: Path,
		session_cookie: str = "session",
		max_age: int | None = 14 * 24 * 60 * 60,  # 14 days, in seconds
		path: str = "/",
		same_site: typing.Literal["lax", "strict", "none"] = "lax",
		https_only: bool = False,
		domain: str | None = None,
	) -> None:
		self.app = app
		self.public_key = public_key
		self.private_key = private_key
		self.session_cookie = session_cookie
		self.max_age = max_age
		self.path = path
		self.security_flags = "httponly; samesite=" + same_site
		if https_only:  # Secure flag can be used with HTTPS only
			self.security_flags += "; secure"
		if domain is not None:
			self.security_flags += f"; domain={domain}"
	
	async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
		if scope["type"] not in ("http", "websocket"):  # pragma: no cover
			await self.app(scope, receive, send)
			return
		
		connection = HTTPConnection(scope)
		initial_session_was_empty = True
		
		if self.session_cookie in connection.cookies:
			data = connection.cookies[self.session_cookie].encode("utf-8")
			try:
				scope["session"] = tokens.decode(data)
				initial_session_was_empty = False
			except tokens.jwt.InvalidTokenError:
				scope["session"] = {}
		else:
			scope["session"] = {}
		
		async def send_wrapper(message: Message) -> None:
			if message["type"] == "http.response.start":
				if scope["session"]:
					# We have session data to persist.
					data = tokens.encode(
						payload=scope["session"],
						public_key=self.public_key,
						private_key=self.private_key
					)
					headers = MutableHeaders(scope=message)
					header_value = "{session_cookie}={data}; path={path}; {max_age}{security_flags}".format(  # noqa E501
						session_cookie=self.session_cookie,
						data=data,
						path=self.path,
						max_age=f"Max-Age={self.max_age}; " if self.max_age else "",
						security_flags=self.security_flags,
					)
					headers.append("Set-Cookie", header_value)
				elif not initial_session_was_empty:
					# The session has been cleared.
					headers = MutableHeaders(scope=message)
					header_value = "{session_cookie}={data}; path={path}; {expires}{security_flags}".format(  # noqa E501
						session_cookie=self.session_cookie,
						data="null",
						path=self.path,
						expires="expires=Thu, 01 Jan 1970 00:00:00 GMT; ",
						security_flags=self.security_flags,
					)
					headers.append("Set-Cookie", header_value)
			await send(message)
		
		await self.app(scope, receive, send_wrapper)
