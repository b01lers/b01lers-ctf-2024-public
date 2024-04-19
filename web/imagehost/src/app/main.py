import mimetypes
import os
import shutil
import uuid
from pathlib import Path

import aiomysql
from PIL import Image
from session import SessionMiddleware
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import (FileResponse, PlainTextResponse, RedirectResponse, Response)
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

UPLOAD_FOLDER = Path("/uploads")
templates = Jinja2Templates(directory='templates')

async def home(request):
	if "user_id" not in request.session:
		return RedirectResponse("/login")
	else:
		context = {}
		
		if "error" in request.query_params:
			context["error"] = request.query_params["error"]
		
		async with request.app.state.pool.acquire() as conn:
			async with conn.cursor() as cursor:
				await cursor.execute(
					"SELECT filename FROM images WHERE user_id = %s",
					(request.session["user_id"], )
				)
				context["images"] = [row[0] for row in await cursor.fetchall()]
				return templates.TemplateResponse(request, "index.html", context)

async def login_get(request):
	context = {}
	if "error" in request.query_params:
		context["error"] = request.query_params["error"]
	return templates.TemplateResponse(request, "login.html", context)

async def login(request):
	async with request.form(max_fields=10) as form:
		if "user" not in form or "password" not in form:
			return RedirectResponse("/login?error=Missing+credentials", status_code=303)
		
		async with request.app.state.pool.acquire() as conn:
			async with conn.cursor() as cursor:
				await cursor.execute(
					"SELECT id, admin FROM users WHERE user = %s AND password = %s",
					(form["user"], form["password"])
				)
				
				row = await cursor.fetchone()
		
		if row is None:
			return RedirectResponse("/login?error=Invalid+credentials", status_code=303)
		
		request.session["user_id"], request.session["admin"] = row
		
		return RedirectResponse("/", status_code=303)

async def register_get(request):
	context = {}
	if "error" in request.query_params:
		context["error"] = request.query_params["error"]
	return templates.TemplateResponse(request, "register.html", context)

async def register(request):
	async with request.form(max_fields=10) as form:
		if "user" not in form or "password" not in form:
			return RedirectResponse("/register?error=Missing+credentials", status_code=303)
		
		async with request.app.state.pool.acquire() as conn:
			async with conn.cursor() as cursor:
				try:
					await cursor.execute(
						"INSERT INTO users(user, password) VALUES(%s, %s) RETURNING ID",
						(form["user"], form["password"])
					)
				except Exception:
					return RedirectResponse("/register?error=Invalid+credentials", status_code=303)
				
				request.session["user_id"] = (await cursor.fetchone())[0]
				request.session["admin"] = False
				
				return RedirectResponse("/", status_code=303)

async def logout(request):
	request.session.pop("user_id", None)
	request.session.pop("admin", None)
	return RedirectResponse("/login")

async def upload(request):
	if "user_id" not in request.session:
		return PlainTextResponse("Not logged in", 401)
	
	async with request.form(max_files=1, max_fields=1) as form:
		if "image" not in form:
			return RedirectResponse("/?error=Missing+image", status_code=303)
		
		image = form["image"]
		
		if image.size > 2**16:
			return RedirectResponse("/?error=File+too+big", 303)
		
		try:
			img = Image.open(image.file)
		except Exception:
			return RedirectResponse("/?error=Invalid+file", 303)
		
		if image.filename is None or not image.filename.endswith(
			tuple(k for k, v in Image.EXTENSION.items() if v == img.format)
		):
			return RedirectResponse("/?error=Invalid+filename", 303)
		
		await image.seek(0)
		filename = Path(image.filename).with_stem(str(uuid.uuid4())).name
		with UPLOAD_FOLDER.joinpath("a").with_name(filename).open("wb") as f:
			shutil.copyfileobj(image.file, f)
		
		async with request.app.state.pool.acquire() as conn:
			async with conn.cursor() as cursor:
				await cursor.execute(
					"INSERT INTO images(filename, user_id) VALUES (%s, %s)",
					(filename, request.session["user_id"])
				)
		
		return RedirectResponse("/", 303)

async def view(request):
	filename = request.path_params["filename"]
	
	path = UPLOAD_FOLDER.joinpath("a").with_name(filename)
	if not path.exists():
		return PlainTextResponse("Image not found", 404)
	
	return FileResponse(UPLOAD_FOLDER.joinpath("a").with_name(filename))

async def on_startup():
	app.state.pool = await aiomysql.create_pool(
		user="ctf", password=os.environ["DB_PASSWORD"], host="localhost", db="ctf", autocommit=True
	)

async def on_shutdown():
	app.state.pool.close()
	await app.state.pool.wait_closed()

app = Starlette(
	routes=[
	Route("/", home),
	Route("/login", login_get),
	Route("/login", login, methods=["POST"]),
	Route("/register", register_get),
	Route("/register", register, methods=["POST"]),
	Route("/logout", logout),
	Route("/", upload, methods=["POST"]),
	Route("/view/{filename}", view),
	Mount(
	'/static',
	app=StaticFiles(directory='static'),
	),
	],
	middleware=[
	Middleware(
	SessionMiddleware,
	public_key=Path("public_key.pem"),
	private_key=Path("private_key.pem"),
	same_site="strict",
	)
	],
	on_startup=[on_startup],
	on_shutdown=[on_shutdown]
)
