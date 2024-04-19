import uuid
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

UPLOAD_FOLDER = Path("/app/uploads")

async def index(request: Request):
	return FileResponse("static/index.html")

async def create_note(request: Request):
	async with request.form(max_fields=1) as form:
		if 'note' not in form:
			return PlainTextResponse("No note provided", 400)
		
		note = form["note"]
		if not isinstance(note, str):
			return PlainTextResponse("Invalid note", 400)
		
		if len(note) > 5_000:
			return PlainTextResponse("Note is too long", 400)
		
		filename = str(uuid.uuid4())
		flag = request.cookies["flag"] + "<br>" if "flag" in request.cookies else ""
		with UPLOAD_FOLDER.joinpath(filename).open("w") as f:
			f.write(flag + note)
		return RedirectResponse(f"/view/{filename}", 302)

async def view_note(request: Request):
	filename = request.path_params["note"]
	file_path = UPLOAD_FOLDER.joinpath("a").with_name(filename)
	return FileResponse(
		file_path,
		headers={"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';"},
		media_type="text/html"
	)

app = Starlette(
	routes=[
	Route("/", index),
	Route("/", create_note, methods=["POST"]),
	Route("/view/{note}", view_note),
	Mount("/static", StaticFiles(directory="static"))
	]
)
